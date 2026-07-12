//! The privileged fstrace daemon.
//!
//! It loads the eBPF programs once, then listens on a Unix socket. Each
//! connecting (unprivileged) client registers the pid of its stopped child; the
//! daemon starts tracing that pid, and streams the resulting kernel events —
//! and those of the child's descendants — back to the owning client. All
//! privileged work (loading BPF, owning the ring buffer and the traced-pid map)
//! lives here; clients need no elevation.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::Instant,
};

use anyhow::{Context as _, anyhow};
use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf};
use fstrace_common::{EVENT_EXIT, EVENT_FORK, EbpfProfileStat, Event, SYSCALL_COUNT};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use tracing::{debug, info, trace, warn};

use crate::{loader::load_programs, profile, wire};

/// Bound on per-client outbound event queue. Under sustained overload events
/// are dropped (tracing is best-effort) rather than stalling other clients.
const CLIENT_QUEUE: usize = 65536;

/// The traced-pid map, shared between client handler threads (which register /
/// unregister pids) behind a mutex. The eBPF fork/exit tracepoints mutate it
/// in-kernel; userspace only inserts roots and cleans up on disconnect.
type TracedMap = Arc<Mutex<AyaHashMap<MapData, u32, u8>>>;

/// Per-CPU eBPF profile map, shared with client-handler threads for interval
/// snapshots.
type ProfileMap = Arc<Mutex<PerCpuArray<MapData, EbpfProfileStat>>>;

fn snapshot_ebpf_profile(map: &ProfileMap) -> anyhow::Result<profile::EbpfProfileSnapshot> {
    let map = map.lock().unwrap();
    let mut snapshot = [EbpfProfileStat::default(); SYSCALL_COUNT];
    for (index, total) in snapshot.iter_mut().enumerate() {
        let values = map
            .get(&(index as u32), 0)
            .with_context(|| format!("reading PROFILE_STATS slot {index}"))?;
        for value in values.iter() {
            total.calls += value.calls;
            total.submitted += value.submitted;
            total.ringbuf_drops += value.ringbuf_drops;
            total.path_reads += value.path_reads;
            total.path_bytes += value.path_bytes;
            total.capture_ns += value.capture_ns;
            total.path_read_ns += value.path_read_ns;
        }
    }
    Ok(snapshot)
}

/// A connected client's outbound channel plus the set of pids it owns.
struct Client {
    tx: SyncSender<Vec<u8>>,
    pids: HashSet<u32>,
    profile: Option<Arc<profile::DaemonProfile>>,
}

/// Routes kernel events to the client that owns the originating pid.
#[derive(Default)]
struct Router {
    pid_owner: HashMap<u32, u64>,
    clients: HashMap<u64, Client>,
}

impl Router {
    /// Registers a client and its root pid. Events for that pid (and, via
    /// [`Router::add_fork`], its descendants) route to `tx`.
    fn register(
        &mut self,
        id: u64,
        root_pid: u32,
        tx: SyncSender<Vec<u8>>,
        profile: Option<Arc<profile::DaemonProfile>>,
    ) {
        let mut pids = HashSet::new();
        pids.insert(root_pid);
        self.pid_owner.insert(root_pid, id);
        self.clients.insert(id, Client { tx, pids, profile });
    }

    /// Associates a newly forked `child` with the same client that owns
    /// `parent`, so the child's events are routed to it too.
    fn add_fork(&mut self, parent: u32, child: u32) {
        if let Some(&id) = self.pid_owner.get(&parent) {
            self.pid_owner.insert(child, id);
            if let Some(client) = self.clients.get_mut(&id) {
                client.pids.insert(child);
            }
            trace!(client = id, parent, child, "routing fork to client");
        }
    }

    /// Forgets a pid that has exited (its slot may later be reused).
    fn drop_pid(&mut self, pid: u32) {
        if let Some(id) = self.pid_owner.remove(&pid)
            && let Some(client) = self.clients.get_mut(&id)
        {
            client.pids.remove(&pid);
            trace!(client = id, pid, "pid exited; dropped from routing");
        }
    }

    /// Encodes and forwards `ev` to the owning client. Returns the client id if
    /// the client has disconnected and should be torn down.
    fn route(&mut self, ev: &Event, dispatch_start: Option<Instant>) -> Option<u64> {
        let id = *self.pid_owner.get(&ev.pid)?;
        let client = self.clients.get(&id)?;
        let route_start = client.profile.as_ref().map(|_| Instant::now());
        let encode_start = client.profile.as_ref().map(|_| Instant::now());
        let bytes = wire::encode_event(ev);
        if let (Some(stats), Some(start)) = (&client.profile, encode_start) {
            stats
                .encode_ns
                .fetch_add(profile::duration_ns(start.elapsed()), Ordering::Relaxed);
            stats
                .wire_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        let result = client.tx.try_send(bytes);
        if let (Some(stats), Some(start)) = (&client.profile, route_start) {
            stats
                .route_ns
                .fetch_add(profile::duration_ns(start.elapsed()), Ordering::Relaxed);
        }
        if let (Some(stats), Some(start)) = (&client.profile, dispatch_start) {
            stats
                .dispatch_ns
                .fetch_add(profile::duration_ns(start.elapsed()), Ordering::Relaxed);
        }
        match result {
            Ok(()) => {
                if let Some(stats) = &client.profile {
                    stats.routed.fetch_add(1, Ordering::Relaxed);
                }
                trace!(
                    client = id,
                    pid = ev.pid,
                    syscall = ev.syscall,
                    "routed event"
                );
                None
            }
            Err(TrySendError::Full(_)) => {
                if let Some(stats) = &client.profile {
                    stats.queue_drops.fetch_add(1, Ordering::Relaxed);
                }
                trace!(client = id, pid = ev.pid, "queue full; dropping event");
                None // best-effort: drop under overload
            }
            Err(TrySendError::Disconnected(_)) => Some(id),
        }
    }

    /// Removes a client, returning every pid it owned so the caller can drop
    /// them from the kernel traced-pid map.
    fn remove_client(&mut self, id: u64) -> Vec<u32> {
        let Some(client) = self.clients.remove(&id) else {
            return Vec::new();
        };
        for pid in &client.pids {
            self.pid_owner.remove(pid);
        }
        client.pids.into_iter().collect()
    }
}

/// Removes a client and drops all of its pids from the kernel traced-pid map.
fn teardown_client(id: u64, router: &Mutex<Router>, traced: &TracedMap) {
    let pids = router.lock().unwrap().remove_client(id);
    if pids.is_empty() {
        return;
    }
    let mut map = traced.lock().unwrap();
    for pid in pids {
        let _ = map.remove(&pid);
    }
}

/// Per-connection handler: performs the registration handshake, spawns a writer
/// thread for outbound events, then blocks until the client disconnects and
/// tears the client down.
fn handle_client(
    stream: UnixStream,
    id: u64,
    router: Arc<Mutex<Router>>,
    traced: TracedMap,
    profile_map: Option<ProfileMap>,
) {
    let mut ctrl = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            warn!("client {id}: clone failed: {err}");
            return;
        }
    };

    let root_pid = match wire::read_hello(&mut ctrl) {
        Ok(pid) => pid,
        Err(err) => {
            debug!("client {id}: no hello: {err}");
            return;
        }
    };

    // Start capturing the child before acknowledging, so the client only
    // resumes it once tracing is active (no early syscalls are missed).
    if let Err(err) = traced.lock().unwrap().insert(root_pid, 1, 0) {
        warn!("client {id}: registering pid {root_pid} failed: {err}");
        return;
    }

    let daemon_profile = profile_map
        .as_ref()
        .map(|_| Arc::new(profile::DaemonProfile::default()));
    let process_cpu_start = daemon_profile.as_ref().map(|_| profile::process_cpu_ns());
    let ebpf_before = profile_map
        .as_ref()
        .and_then(|map| match snapshot_ebpf_profile(map) {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                warn!("client {id}: taking initial eBPF profile snapshot failed: {err:#}");
                None
            }
        });

    let (tx, rx) = sync_channel::<Vec<u8>>(CLIENT_QUEUE);
    router
        .lock()
        .unwrap()
        .register(id, root_pid, tx, daemon_profile.clone());

    // Acknowledge on the socket *before* the writer thread can emit any event,
    // guaranteeing the ACK byte is the first thing the client reads.
    let mut ack_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            warn!("client {id}: clone failed: {err}");
            teardown_client(id, &router, &traced);
            return;
        }
    };
    if let Err(err) = wire::write_ack(&mut ack_stream) {
        debug!("client {id}: ack failed: {err}");
        teardown_client(id, &router, &traced);
        return;
    }

    // Writer thread: drains the outbound queue to the socket.
    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            warn!("client {id}: clone failed: {err}");
            teardown_client(id, &router, &traced);
            return;
        }
    };
    let writer_profile = daemon_profile.clone();
    let writer_handle = thread::spawn(move || {
        use std::io::Write;
        for bytes in rx {
            let started = writer_profile.as_ref().map(|_| Instant::now());
            let result = writer.write_all(&bytes);
            if let (Some(stats), Some(started)) = (&writer_profile, started) {
                stats.socket_writes.fetch_add(1, Ordering::Relaxed);
                stats
                    .socket_write_ns
                    .fetch_add(profile::duration_ns(started.elapsed()), Ordering::Relaxed);
            }
            if result.is_err() {
                break;
            }
        }
    });

    debug!("client {id}: registered root pid {root_pid}");

    // Block until the client disconnects (we expect no further input).
    let mut buf = [0u8; 256];
    loop {
        match ctrl.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }

    teardown_client(id, &router, &traced);
    let _ = writer_handle.join();
    if let Some(daemon_profile) = daemon_profile {
        daemon_profile.log(
            id,
            profile::process_cpu_ns().saturating_sub(process_cpu_start.unwrap_or_default()),
        );
    }
    if let (Some(map), Some(before)) = (&profile_map, ebpf_before) {
        match snapshot_ebpf_profile(map) {
            Ok(after) => {
                let delta = profile::subtract_ebpf_profiles(&before, &after);
                profile::log_ebpf_profile(id, &delta);
            }
            Err(err) => warn!("client {id}: taking final eBPF profile snapshot failed: {err:#}"),
        }
    }
    debug!("client {id}: disconnected");
}

/// Prepares the Unix listener: ensures the parent directory exists, clears any
/// stale socket, binds, and makes the socket world-connectable.
fn bind_listener() -> anyhow::Result<UnixListener> {
    let path = wire::socket_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Remove a stale socket left by a previous daemon instance.
    let _ = fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    // Allow unprivileged clients to connect.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("chmod {}", path.display()))?;
    info!("listening on {}", path.display());
    Ok(listener)
}

/// First file descriptor systemd passes for socket activation (see
/// `sd_listen_fds(3)`).
const SD_LISTEN_FDS_START: RawFd = 3;

/// If the daemon was launched via systemd socket activation, adopt the
/// listening socket systemd already bound and passed to us; otherwise `None`.
///
/// Implements the `sd_listen_fds(3)` handshake without pulling in libsystemd:
/// `LISTEN_PID` must be our pid and `LISTEN_FDS` the count of inherited
/// sockets, which start at [`SD_LISTEN_FDS_START`].
fn systemd_listener() -> anyhow::Result<Option<UnixListener>> {
    let (Some(pid), Some(fds)) = (
        std::env::var("LISTEN_PID").ok(),
        std::env::var("LISTEN_FDS").ok(),
    ) else {
        return Ok(None);
    };
    // These variables target exactly the process systemd spawned; ignore any
    // that leaked into an unrelated invocation.
    if pid.parse::<u32>().context("parsing LISTEN_PID")? != std::process::id() {
        return Ok(None);
    }
    let count: i32 = fds.parse().context("parsing LISTEN_FDS")?;
    if count < 1 {
        return Ok(None);
    }
    if count > 1 {
        warn!("systemd passed {count} sockets; using only the first");
    }
    // SAFETY: under socket activation systemd guarantees fd
    // `SD_LISTEN_FDS_START` is an open, bound, listening socket handed to us; we
    // take exclusive ownership of it.
    let listener = unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };
    info!("using systemd socket-activated listener (fd {SD_LISTEN_FDS_START})");
    Ok(Some(listener))
}

/// Acquires the listening socket: prefer a systemd socket-activation fd, and
/// fall back to binding the socket ourselves for standalone use.
fn acquire_listener() -> anyhow::Result<UnixListener> {
    match systemd_listener()? {
        Some(listener) => Ok(listener),
        None => bind_listener(),
    }
}

/// Runs the daemon: load eBPF, accept clients, and route ring-buffer events
/// until interrupted.
pub fn run() -> anyhow::Result<()> {
    let profiling = profile::enabled();
    let mut ebpf = load_programs(profiling).context("loading eBPF programs")?;

    let traced_map: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
        ebpf.take_map("TRACED")
            .ok_or_else(|| anyhow!("TRACED map missing"))?,
    )?;
    let traced: TracedMap = Arc::new(Mutex::new(traced_map));

    let mut ring: RingBuf<_> = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("EVENTS map missing"))?,
    )?;
    let profile_map = if profiling {
        let map = ebpf
            .take_map("PROFILE_STATS")
            .ok_or_else(|| anyhow!("PROFILE_STATS map missing"))?;
        Some(Arc::new(Mutex::new(
            PerCpuArray::try_from(map).context("PROFILE_STATS is not a per-CPU array")?,
        )))
    } else {
        None
    };

    let router = Arc::new(Mutex::new(Router::default()));
    let listener = acquire_listener()?;

    // Accept loop runs on its own thread; each client gets a handler thread.
    {
        let router = Arc::clone(&router);
        let traced = Arc::clone(&traced);
        let profile_map = profile_map.clone();
        let ids = AtomicU64::new(1);
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let id = ids.fetch_add(1, Ordering::Relaxed);
                        let router = Arc::clone(&router);
                        let traced = Arc::clone(&traced);
                        let profile_map = profile_map.clone();
                        thread::spawn(move || {
                            handle_client(stream, id, router, traced, profile_map)
                        });
                    }
                    Err(err) => warn!("accept failed: {err}"),
                }
            }
        });
    }

    // Main thread: drain the ring buffer and route events to owning clients.
    let ring_fd = ring.as_raw_fd();
    // SAFETY: `ring_fd` is owned by `ring` and outlives the borrow.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(ring_fd) };
    loop {
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        let _ = poll(&mut fds, PollTimeout::from(500u16));

        loop {
            let dispatch_start = profiling.then(Instant::now);
            let Some(item) = ring.next() else {
                break;
            };
            if item.len() < core::mem::size_of::<Event>() {
                continue;
            }
            // SAFETY: the kernel reserved exactly `size_of::<Event>()` bytes,
            // 8-byte aligned, populated with a valid `Event`.
            let ev = unsafe { &*(item.as_ptr() as *const Event) };
            match ev.syscall {
                EVENT_FORK => router.lock().unwrap().add_fork(ev.pid, ev.ret as u32),
                EVENT_EXIT => router.lock().unwrap().drop_pid(ev.pid),
                _ => {
                    let dead = router.lock().unwrap().route(ev, dispatch_start);
                    if let Some(id) = dead {
                        teardown_client(id, &router, &traced);
                    }
                }
            }
        }
    }
}

/// Entry point for the `fstrace-daemon` binary. Never returns on success (runs
/// until killed); exits non-zero on a fatal startup error.
pub fn main() -> ! {
    let mut socket_override: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("fstrace-daemon {VERSION}");
                std::process::exit(0);
            }
            "--socket" => {
                socket_override = Some(args.next().unwrap_or_else(|| {
                    eprintln!("fstrace-daemon: --socket requires a PATH argument");
                    std::process::exit(2);
                }));
            }
            other if other.starts_with("--socket=") => {
                socket_override = Some(other["--socket=".len()..].to_string());
            }
            other => {
                eprintln!(
                    "fstrace-daemon: unexpected argument '{other}'\n\
                     Try 'fstrace-daemon --help' for more information."
                );
                std::process::exit(2);
            }
        }
    }

    if let Some(socket) = socket_override {
        // SAFETY: set before any threads are spawned; wire::socket_path() reads
        // FSTRACE_SOCKET when binding.
        unsafe {
            std::env::set_var(wire::SOCKET_ENV, &socket);
        }
    }

    crate::runtime::init_tracing("fstrace-daemon");
    match run() {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            eprintln!("fstrace-daemon: {err:#}");
            std::process::exit(1);
        }
    }
}

/// Version string reported by `--version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prints the `fstrace-daemon --help` text.
fn print_help() {
    print!(
        "\
fstrace-daemon {VERSION}
Privileged fstrace eBPF daemon.

Loads the eBPF programs once, then serves unprivileged fstrace clients over a
Unix socket: each client registers the pid of its stopped child and the daemon
streams that process tree's kernel events back. This is the only component that
needs root (CAP_BPF/CAP_SYS_ADMIN); the fstrace client runs without privileges.

USAGE:
    fstrace-daemon [OPTIONS]

OPTIONS:
    --socket <PATH>    Unix socket to listen on (overrides FSTRACE_SOCKET;
                       default /run/fstrace/fstrace.sock).
    -h, --help         Print this help and exit.
    -V, --version      Print version and exit.

SOCKET ACTIVATION:
    If launched via systemd socket activation (LISTEN_FDS/LISTEN_PID), the daemon
    adopts the passed listening socket; otherwise it binds the socket itself.

ENVIRONMENT:
    FSTRACE_SOCKET                      Socket path to bind (default /run/fstrace/fstrace.sock);
                                        --socket takes precedence.
    FSTRACE_PROFILE=1                   Emit aggregate daemon and eBPF performance timings.
    FSTRACE_LOG_FILE / FSTRACE_LOG_DIR  Write logs to an explicit file / a per-process directory.
    RUST_LOG                            Log verbosity (e.g. fstrace=trace); FSTRACE_DEBUG=1 means fstrace=debug.

Documentation: https://github.com/bmiddha/fstrace
"
    );
}
