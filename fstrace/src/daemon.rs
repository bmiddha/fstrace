//! Privileged daemon: load eBPF, authenticate clients, and route their events.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use aya::maps::{
    HashMap as AyaHashMap, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues, RingBuf,
};
use fstrace_common::{
    EVENT_EXIT, EVENT_FORK, EbpfProfileStat, Event, Registration, SYSCALL_COUNT, TaskKey,
};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use tracing::{debug, info, trace, warn};

use crate::{loader::load_programs, profile, wire};

/// A full queue fails the trace instead of stalling other clients.
const CLIENT_QUEUE: usize = 1024;
const MAX_CLIENTS: usize = 64;

struct ConnectionPermit(Arc<AtomicUsize>);

fn finish_stream(writer: &mut UnixStream, finished: bool, loss: u64) -> std::io::Result<()> {
    if finished {
        let mut done = Event::zeroed();
        done.syscall = wire::EVENT_DONE;
        done.ret = i64::from(loss != 0);
        writer.write_all(&wire::encode_event(&done))?;
    }
    writer.shutdown(std::net::Shutdown::Both)
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shared kernel maps. BPF also updates membership during fork and exit.
type TracedMap = Arc<Mutex<KernelState>>;

struct KernelState {
    traced: AyaHashMap<MapData, TaskKey, u64>,
    registrations: AyaHashMap<MapData, [u64; 2], Registration>,
    parents: AyaHashMap<MapData, u64, [u64; 2]>,
    sessions: AyaHashMap<MapData, u64, u8>,
    inflight: PerCpuHashMap<MapData, u64, u64>,
    losses: PerCpuArray<MapData, u64>,
}

impl KernelState {
    fn loss_generation(&self) -> anyhow::Result<u64> {
        Ok(self.losses.get(&0, 0)?.iter().copied().sum())
    }
}

struct RegistrationGuard {
    kernel: TracedMap,
    token: [u64; 2],
    id: u64,
    committed: bool,
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        let mut kernel = self.kernel.lock().unwrap();
        if let Ok(pending) = kernel.registrations.get(&self.token, 0) {
            let key = TaskKey::new(pending.child, pending.child_start);
            if kernel.parents.get(&pending.parent_task, 0).ok() == Some(self.token) {
                let _ = kernel.parents.remove(&pending.parent_task);
            }
            if !self.committed && kernel.traced.get(&key, 0).ok() == Some(self.id) {
                let _ = kernel.traced.remove(&key);
            }
        }
        let _ = kernel.registrations.remove(&self.token);
        if !self.committed {
            let _ = kernel.sessions.remove(&self.id);
            let _ = kernel.inflight.remove(&self.id);
        }
    }
}

/// Per-CPU profile stats shared with client handlers.
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

struct Client {
    _permit: Option<Arc<ConnectionPermit>>,
    tx: SyncSender<Vec<u8>>,
    pids: HashSet<TaskKey>,
    profile: Option<Arc<profile::DaemonProfile>>,
    loss: Arc<AtomicU64>,
    finished: Arc<AtomicBool>,
    generation: u64,
    cancelled: bool,
}

struct Finishing {
    started: Instant,
    position: Option<u64>,
    complete: bool,
}

/// Route events by task lifetime and session.
#[derive(Default)]
struct Router {
    pid_owner: HashMap<TaskKey, u64>,
    clients: HashMap<u64, Client>,
}

impl Router {
    fn register(
        &mut self,
        id: u64,
        root_pid: TaskKey,
        tx: SyncSender<Vec<u8>>,
        profile: Option<Arc<profile::DaemonProfile>>,
        generation: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.pid_owner.contains_key(&root_pid),
            "task already registered"
        );
        let mut pids = HashSet::new();
        pids.insert(root_pid);
        self.pid_owner.insert(root_pid, id);
        self.clients.insert(
            id,
            Client {
                _permit: None,
                tx,
                pids,
                profile,
                loss: Arc::new(AtomicU64::new(0)),
                finished: Arc::new(AtomicBool::new(false)),
                generation,
                cancelled: false,
            },
        );
        Ok(())
    }

    /// Give the child its parent's owner.
    fn add_fork(&mut self, parent: TaskKey, child: TaskKey) {
        if let Some(&id) = self.pid_owner.get(&parent) {
            if self.pid_owner.get(&child).is_some_and(|owner| *owner != id) {
                if let Some(client) = self.clients.get(&id) {
                    client.loss.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            self.pid_owner.insert(child, id);
            if let Some(client) = self.clients.get_mut(&id) {
                client.pids.insert(child);
            }
            trace!(client = id, ?parent, ?child, "routing fork to client");
        }
    }

    fn drop_pid(&mut self, pid: TaskKey) {
        if let Some(id) = self.pid_owner.remove(&pid)
            && let Some(client) = self.clients.get_mut(&id)
        {
            client.pids.remove(&pid);
            trace!(client = id, ?pid, "pid exited; dropped from routing");
        }
    }

    /// Forward an event; return the client ID if it needs cancellation.
    fn route(&mut self, ev: &Event, dispatch_start: Option<Instant>) -> Option<u64> {
        let id = *self.pid_owner.get(&TaskKey::new(ev.tid, ev.birth))?;
        if ev.session != id {
            return None;
        }
        let client = self.clients.get_mut(&id)?;
        if client.cancelled {
            return None;
        }
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
                client.loss.fetch_add(1, Ordering::Relaxed);
                if let Some(stats) = &client.profile {
                    stats.queue_drops.fetch_add(1, Ordering::Relaxed);
                }
                warn!(
                    client = id,
                    pid = ev.pid,
                    "outbound queue full; failing trace"
                );
                client.cancelled = true;
                Some(id)
            }
            Err(TrySendError::Disconnected(_)) => {
                client.cancelled = true;
                Some(id)
            }
        }
    }

    /// Return owned tasks for kernel-map cleanup.
    fn remove_client(&mut self, id: u64) -> Vec<TaskKey> {
        let Some(client) = self.clients.remove(&id) else {
            return Vec::new();
        };
        client
            .pids
            .into_iter()
            .filter(|pid| {
                if self.pid_owner.get(pid) == Some(&id) {
                    self.pid_owner.remove(pid);
                    true
                } else {
                    false
                }
            })
            .collect()
    }
}

fn begin_finish(
    id: u64,
    complete: bool,
    finishing: &mut HashMap<u64, Finishing>,
    router: &Mutex<Router>,
    traced: &TracedMap,
) -> anyhow::Result<()> {
    let mut routing = router.lock().unwrap();
    let Some(client) = routing.clients.get_mut(&id) else {
        return Ok(());
    };
    if !complete {
        client.cancelled = true;
    }
    if let Some(state) = finishing.get_mut(&id) {
        state.complete &= complete;
        return Ok(());
    }
    traced
        .lock()
        .unwrap()
        .sessions
        .remove(&id)
        .context("revoking completed session")?;
    finishing.insert(
        id,
        Finishing {
            started: Instant::now(),
            position: None,
            complete,
        },
    );
    Ok(())
}

fn teardown_client(id: u64, router: &Mutex<Router>, traced: &TracedMap) {
    let mut routing = router.lock().unwrap();
    let pids = routing.remove_client(id);
    let mut map = traced.lock().unwrap();
    let _ = map.sessions.remove(&id);
    let _ = map.inflight.remove(&id);
    for pid in pids {
        if map.traced.get(&pid, 0).ok() == Some(id) {
            let _ = map.traced.remove(&pid);
        }
    }
}

/// Authenticate a client, stream its events, and request ordered cleanup.
fn handle_client(
    stream: UnixStream,
    id: u64,
    router: Arc<Mutex<Router>>,
    traced: TracedMap,
    profile_map: Option<ProfileMap>,
    finish_tx: SyncSender<(u64, bool)>,
    permit: Arc<ConnectionPermit>,
) {
    if let Err(err) = stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(30))))
    {
        warn!("client {id}: setting socket deadlines: {err}");
        return;
    }
    let mut ctrl = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            warn!("client {id}: clone failed: {err}");
            return;
        }
    };

    let mut token_bytes = [0; 16];
    if let Err(err) = std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut token_bytes))
    {
        warn!("client {id}: generating registration capability: {err}");
        return;
    }
    let token = [
        u64::from_ne_bytes(token_bytes[..8].try_into().unwrap()),
        u64::from_ne_bytes(token_bytes[8..].try_into().unwrap()),
    ];
    let generation = {
        let mut kernel = traced.lock().unwrap();
        let result = (|| -> anyhow::Result<u64> {
            let generation = kernel.loss_generation()?;
            kernel.inflight.insert(
                &id,
                PerCpuValues::try_from(vec![
                    0u64;
                    aya::util::nr_cpus()
                        .map_err(|(path, error)| anyhow!(
                            "counting kernel CPUs from {path}: {error}"
                        ))?
                        .get() as usize
                ])?,
                1,
            )?;
            kernel.sessions.insert(&id, &1, 1)?;
            kernel.registrations.insert(
                &token,
                &Registration {
                    session: id,
                    ..Default::default()
                },
                1,
            )?;
            Ok(generation)
        })();
        match result {
            Ok(generation) => generation,
            Err(err) => {
                let _ = kernel.sessions.remove(&id);
                let _ = kernel.inflight.remove(&id);
                warn!("client {id}: preparing registration: {err:#}");
                return;
            }
        }
    };
    let mut registration = RegistrationGuard {
        kernel: traced.clone(),
        token,
        id,
        committed: false,
    };
    if let Err(err) = wire::write_challenge(&mut ctrl, token) {
        debug!("client {id}: challenge failed: {err}");
        return;
    }
    match wire::read_hello(&mut ctrl) {
        Ok(0) => {}
        Ok(_) => {
            let _ = ctrl.write_all(&[wire::REJECT]);
            return;
        }
        Err(err) => {
            debug!("client {id}: no hello: {err}");
            return;
        }
    }
    let root_pid = {
        let kernel = traced.lock().unwrap();
        match kernel.registrations.get(&token, 0) {
            Ok(pending)
                if pending.child != 0
                    && kernel
                        .traced
                        .get(&TaskKey::new(pending.child, pending.child_start), 0)
                        .ok()
                        == Some(id) =>
            {
                TaskKey::new(pending.child, pending.child_start)
            }
            _ => {
                let _ = ctrl.write_all(&[wire::REJECT]);
                warn!("client {id}: no live kernel-authenticated fork");
                return;
            }
        }
    };

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
    let (loss, finished) = {
        let mut routing = router.lock().unwrap();
        if let Err(err) = routing.register(id, root_pid, tx, daemon_profile.clone(), generation) {
            let _ = ctrl.write_all(&[wire::REJECT]);
            warn!("client {id}: {err:#}");
            return;
        }
        let client = routing.clients.get_mut(&id).unwrap();
        client._permit = Some(permit.clone());
        let activation = traced.lock().unwrap().sessions.insert(&id, &2, 2);
        if let Err(error) = activation {
            routing.remove_client(id);
            let _ = ctrl.write_all(&[wire::REJECT]);
            warn!("client {id}: activating authenticated session: {error}");
            return;
        }
        let client = routing.clients.get(&id).unwrap();
        (client.loss.clone(), client.finished.clone())
    };
    registration.committed = true;
    drop(registration);

    // ACK must precede all event frames.
    let mut ack_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            warn!("client {id}: clone failed: {err}");
            if finish_tx.try_send((id, false)).is_err() {
                teardown_client(id, &router, &traced);
            }
            return;
        }
    };
    if let Err(err) = wire::write_ack(&mut ack_stream, root_pid.tid) {
        debug!("client {id}: ack failed: {err}");
        if finish_tx.try_send((id, false)).is_err() {
            teardown_client(id, &router, &traced);
        }
        return;
    }

    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            warn!("client {id}: clone failed: {err}");
            if finish_tx.try_send((id, false)).is_err() {
                teardown_client(id, &router, &traced);
            }
            return;
        }
    };
    let writer_profile = daemon_profile.clone();
    let writer_handle = thread::spawn(move || -> std::io::Result<()> {
        let result = (|| -> std::io::Result<()> {
            for bytes in rx {
                let started = writer_profile.as_ref().map(|_| Instant::now());
                writer.write_all(&bytes)?;
                if let (Some(stats), Some(started)) = (&writer_profile, started) {
                    stats.socket_writes.fetch_add(1, Ordering::Relaxed);
                    stats
                        .socket_write_ns
                        .fetch_add(profile::duration_ns(started.elapsed()), Ordering::Relaxed);
                }
            }
            finish_stream(
                &mut writer,
                finished.load(Ordering::Acquire),
                loss.load(Ordering::Relaxed),
            )?;
            Ok(())
        })();
        if result.is_err() {
            let _ = writer.shutdown(std::net::Shutdown::Both);
        }
        result
    });

    debug!("client {id}: registered root task {root_pid:?}");

    if let Err(err) = ctrl.set_read_timeout(None) {
        warn!("client {id}: resetting control timeout: {err}");
    }
    let mut command = [0];
    let complete = ctrl.read_exact(&mut command).is_ok() && command[0] == wire::FINISH;
    if finish_tx.try_send((id, complete)).is_err() {
        warn!("client {id}: completion command queue full; cancelling");
        teardown_client(id, &router, &traced);
    }
    match writer_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => warn!("client {id}: event writer failed: {err}"),
        Err(_) => warn!("client {id}: event writer panicked"),
    }
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

/// Bind a socket that unprivileged clients can use.
fn bind_listener() -> anyhow::Result<UnixListener> {
    let path = wire::socket_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("chmod {}", path.display()))?;
    info!("listening on {}", path.display());
    Ok(listener)
}

/// First inherited socket in sd_listen_fds(3).
const SD_LISTEN_FDS_START: RawFd = 3;

/// Adopt systemd's first socket when LISTEN_PID matches this process.
fn systemd_listener() -> anyhow::Result<Option<UnixListener>> {
    let (Some(pid), Some(fds)) = (
        std::env::var("LISTEN_PID").ok(),
        std::env::var("LISTEN_FDS").ok(),
    ) else {
        return Ok(None);
    };
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

/// Use systemd's socket if supplied; otherwise bind our own.
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

    let traced_map: AyaHashMap<_, TaskKey, u64> = AyaHashMap::try_from(
        ebpf.take_map("TRACED")
            .ok_or_else(|| anyhow!("TRACED map missing"))?,
    )?;
    let traced: TracedMap = Arc::new(Mutex::new(KernelState {
        traced: traced_map,
        registrations: AyaHashMap::try_from(
            ebpf.take_map("REGISTRATIONS")
                .context("REGISTRATIONS missing")?,
        )?,
        parents: AyaHashMap::try_from(
            ebpf.take_map("REGISTERING_TASKS")
                .context("REGISTERING_TASKS missing")?,
        )?,
        sessions: AyaHashMap::try_from(ebpf.take_map("SESSIONS").context("SESSIONS missing")?)?,
        inflight: PerCpuHashMap::try_from(ebpf.take_map("INFLIGHT").context("INFLIGHT missing")?)?,
        losses: PerCpuArray::try_from(ebpf.take_map("LOSSES").context("LOSSES missing")?)?,
    }));

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
    let (finish_tx, finish_rx) = sync_channel::<(u64, bool)>(2 * MAX_CLIENTS);

    // Accept loop runs on its own thread; each client gets a handler thread.
    {
        let router = Arc::clone(&router);
        let traced = Arc::clone(&traced);
        let profile_map = profile_map.clone();
        let finish_tx = finish_tx.clone();
        let ids = AtomicU64::new(1);
        let connections = Arc::new(AtomicUsize::new(0));
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if connections
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                                (count < MAX_CLIENTS).then_some(count + 1)
                            })
                            .is_err()
                        {
                            warn!("connection limit ({MAX_CLIENTS}) reached; rejecting client");
                            continue;
                        }
                        let permit = Arc::new(ConnectionPermit(connections.clone()));
                        let id = ids.fetch_add(1, Ordering::Relaxed);
                        let router = Arc::clone(&router);
                        let traced = Arc::clone(&traced);
                        let profile_map = profile_map.clone();
                        let finish_tx = finish_tx.clone();
                        thread::spawn(move || {
                            handle_client(
                                stream,
                                id,
                                router,
                                traced,
                                profile_map,
                                finish_tx,
                                permit,
                            )
                        });
                    }
                    Err(err) => warn!("accept failed: {err}"),
                }
            }
        });
    }

    // Main thread: drain the ring buffer and route events to owning clients.
    let ring_fd = ring.as_raw_fd();
    let fence =
        crate::ring_fence::RingFence::new(ring_fd).context("mapping ring completion positions")?;
    // SAFETY: `ring_fd` is owned by `ring` and outlives the borrow.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(ring_fd) };
    let mut finishing: HashMap<u64, Finishing> = HashMap::new();
    loop {
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        poll(&mut fds, PollTimeout::from(10u16)).context("polling BPF ring")?;
        for (id, complete) in finish_rx.try_iter() {
            begin_finish(id, complete, &mut finishing, &router, &traced)?;
        }
        let generation = traced.lock().unwrap().loss_generation()?;
        let failed: Vec<_> = router
            .lock()
            .unwrap()
            .clients
            .iter()
            .filter_map(|(id, client)| {
                if !client.cancelled
                    && (generation != client.generation || client.loss.load(Ordering::Relaxed) != 0)
                {
                    client.loss.fetch_add(1, Ordering::Relaxed);
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        for id in failed {
            warn!("client {id}: kernel event loss; failing trace");
            begin_finish(id, false, &mut finishing, &router, &traced)?;
        }
        {
            let routing = router.lock().unwrap();
            let kernel = traced.lock().unwrap();
            finishing.retain(|id, _| routing.clients.contains_key(id));
            for (id, state) in &mut finishing {
                if state.position.is_none()
                    && kernel.inflight.get(id, 0)?.iter().all(|count| *count == 0)
                {
                    state.position = Some(fence.snapshot());
                }
            }
        }

        // A busy unrelated trace must not starve FINISH or socket cancellation.
        for _ in 0..4096 {
            let dispatch_start = profiling.then(Instant::now);
            let Some(item) = ring.next() else {
                break;
            };
            if item.len() != core::mem::size_of::<Event>() {
                anyhow::bail!("invalid BPF ring record length: {}", item.len());
            }
            // SAFETY: the kernel reserved exactly `size_of::<Event>()` bytes,
            // 8-byte aligned, populated with a valid `Event`.
            let ev = unsafe { &*(item.as_ptr() as *const Event) };
            match ev.syscall {
                EVENT_FORK | EVENT_EXIT => {
                    let mut routing = router.lock().unwrap();
                    let key = TaskKey::new(ev.tid, ev.birth);
                    if routing.pid_owner.get(&key) == Some(&ev.session) {
                        let dead = routing.route(ev, dispatch_start);
                        if ev.syscall == EVENT_FORK {
                            routing.add_fork(key, TaskKey::new(ev.ret as u32, ev.child_birth));
                        } else {
                            routing.drop_pid(key);
                        }
                        drop(routing);
                        if let Some(id) = dead {
                            begin_finish(id, false, &mut finishing, &router, &traced)?;
                        }
                    }
                }
                _ => {
                    let dead = router.lock().unwrap().route(ev, dispatch_start);
                    if let Some(id) = dead {
                        begin_finish(id, false, &mut finishing, &router, &traced)?;
                    }
                }
            }
        }
        let completed: Vec<_> = finishing
            .iter()
            .filter_map(|(id, state)| {
                let timed_out = state.started.elapsed() >= Duration::from_secs(30);
                (state
                    .position
                    .is_some_and(|position| fence.drained(position))
                    || timed_out)
                    .then_some((*id, timed_out, state.complete))
            })
            .collect();
        for (id, timed_out, complete) in completed {
            finishing.remove(&id);
            {
                let routing = router.lock().unwrap();
                if let Some(client) = routing.clients.get(&id) {
                    if timed_out {
                        client.loss.fetch_add(1, Ordering::Relaxed);
                    }
                    match traced.lock().unwrap().loss_generation() {
                        Ok(generation) if generation == client.generation => {}
                        _ => {
                            client.loss.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    client.finished.store(
                        complete || client.loss.load(Ordering::Relaxed) != 0,
                        Ordering::Release,
                    );
                }
            }
            teardown_client(id, &router, &traced);
            let _ = traced.lock().unwrap().inflight.remove(&id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_unblocks_control_without_peer_finish_and_retains_admission() {
        let connections = Arc::new(AtomicUsize::new(1));
        let permit = Arc::new(ConnectionPermit(connections.clone()));
        let mut router = Router::default();
        let (tx, _rx) = sync_channel(1);
        router.register(1, key(2000), tx, None, 0).unwrap();
        router.clients.get_mut(&1).unwrap()._permit = Some(permit.clone());
        router.remove_client(1);
        assert_eq!(connections.load(Ordering::Relaxed), 1);

        let (mut peer, mut control) = UnixStream::pair().unwrap();
        let mut writer = control.try_clone().unwrap();
        let (exited, exit) = sync_channel(1);
        let handler = thread::spawn(move || {
            let mut command = [0];
            assert!(control.read_exact(&mut command).is_err());
            drop(permit);
            exited.send(()).unwrap();
        });
        finish_stream(&mut writer, true, 1).unwrap();
        let done = wire::read_event(&mut peer).unwrap();
        assert_eq!(done.syscall, wire::EVENT_DONE);
        assert_eq!(done.ret, 1);
        exit.recv_timeout(Duration::from_secs(2)).unwrap();
        handler.join().unwrap();
        assert_eq!(connections.load(Ordering::Relaxed), 0);
    }

    fn key(tid: u32) -> TaskKey {
        TaskKey::new(tid, 0)
    }

    fn event(session: u64, tid: u32) -> Event {
        let mut event = Event::zeroed();
        event.session = session;
        event.pid = tid;
        event.tid = tid;
        event
    }

    #[test]
    fn duplicate_registration_cannot_redirect_the_original_owner() {
        let mut router = Router::default();
        let (first, original) = sync_channel(2);
        let (second, replacement) = sync_channel(2);
        router.register(1, key(2000), first, None, 0).unwrap();
        assert!(router.register(2, key(2000), second, None, 0).is_err());
        router.route(&event(1, 2000), None);
        assert!(original.try_recv().is_ok());
        assert!(replacement.try_recv().is_err());
    }

    #[test]
    fn stale_events_and_old_teardown_cannot_touch_a_reused_task() {
        let mut router = Router::default();
        let (first, _old) = sync_channel(2);
        router.register(1, key(2000), first, None, 0).unwrap();
        router.add_fork(key(2000), key(2001));
        router.drop_pid(key(2001));
        let (second, current) = sync_channel(2);
        router.register(2, key(2001), second, None, 0).unwrap();
        assert_eq!(router.remove_client(1), vec![key(2000)]);
        router.route(&event(1, 2001), None);
        assert!(current.try_recv().is_err());
        router.route(&event(2, 2001), None);
        assert!(current.try_recv().is_ok());
        assert_eq!(router.pid_owner.get(&key(2001)), Some(&2));
    }

    #[test]
    fn queue_pressure_is_recorded_without_profiling() {
        let mut router = Router::default();
        let (tx, rx) = sync_channel(1);
        router.register(1, key(2000), tx, None, 0).unwrap();
        router.route(&event(1, 2000), None);
        router.route(&event(1, 2000), None);
        assert_eq!(router.clients[&1].loss.load(Ordering::Relaxed), 1);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn thread_churn_retires_routes_instead_of_growing_membership() {
        let mut router = Router::default();
        let (tx, _rx) = sync_channel(1);
        router.register(1, key(2000), tx, None, 0).unwrap();
        for tid in 2001..10000 {
            router.add_fork(key(2000), key(tid));
            router.drop_pid(key(tid));
        }
        assert_eq!(router.clients[&1].pids.len(), 1);
        assert_eq!(router.pid_owner.len(), 1);
    }

    #[test]
    fn old_cleanup_cannot_delete_a_new_birth_at_the_same_tid() {
        let old = TaskKey::new(2000, 123);
        let new = TaskKey::new(2000, 456);
        let mut membership = HashMap::from([(old, 1_u64), (new, 2)]);
        let mut router = Router::default();
        let (first, _old_events) = sync_channel(2);
        let (second, current) = sync_channel(2);
        router.register(1, old, first, None, 0).unwrap();
        router.register(2, new, second, None, 0).unwrap();

        for stale in router.remove_client(1) {
            membership.remove(&stale);
        }
        router.drop_pid(old);
        assert_eq!(membership.get(&new), Some(&2));
        assert_eq!(router.pid_owner.get(&new), Some(&2));

        let mut stale = event(2, new.tid);
        stale.birth = old.birth;
        router.route(&stale, None);
        assert!(current.try_recv().is_err());
        let mut live = stale;
        live.birth = new.birth;
        router.route(&live, None);
        assert!(current.try_recv().is_ok());
    }
}
