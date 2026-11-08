//! Unprivileged client: launch a command, receive daemon events, and write reports.

use std::{
    ffi::{CString, OsStr, OsString},
    fs::File,
    os::{
        fd::{FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt, net::UnixStream},
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use nix::sys::{
    prctl,
    signal::{self, SigHandler, Signal},
    wait::{WaitPidFlag, WaitStatus},
};
use tracing::trace;
use tracing_subscriber::{EnvFilter, fmt::writer::BoxMakeWriter};

use crate::{
    Tracer,
    child::{self, Child, Fork},
    debounce::Debounce,
    filter::Filter,
    options::Options,
    proc::CapturedSystem,
    profile, wire,
};

const REPORT_FD: RawFd = 3;

/// Report path override; useful when sudo closes fd 3.
const REPORT_FILE_ENV: &str = "FSTRACE_REPORT_FILE";

/// Set by the `SIGUSR1` handler; drains to a debounce flush in the event loop.
static FLUSH_REQUESTED: AtomicBool = AtomicBool::new(false);

struct QueuedEvent {
    event: fstrace_common::Event,
    received_at: Option<Instant>,
}

enum ReaderMessage {
    Event(Box<QueuedEvent>),
    Failed(std::io::Error),
}

const CLIENT_EVENT_QUEUE: usize = 1024;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);

struct SessionGuard {
    child: Child,
    socket: UnixStream,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

fn receive_events(
    mut reader: UnixStream,
    tx: mpsc::SyncSender<ReaderMessage>,
    profiling: bool,
    stats: Arc<profile::ClientRuntimeProfile>,
) {
    loop {
        match wire::read_event(&mut reader) {
            Ok(event) => {
                let done = event.syscall == wire::EVENT_DONE;
                if profiling {
                    stats.record_wire_event(wire::encoded_len(&event) as u64);
                }
                if tx
                    .send(ReaderMessage::Event(Box::new(QueuedEvent {
                        event,
                        received_at: profiling.then(Instant::now),
                    })))
                    .is_err()
                    || done
                {
                    break;
                }
            }
            Err(error) => {
                let _ = tx.send(ReaderMessage::Failed(error));
                break;
            }
        }
    }
}

fn stream_message(message: ReaderMessage) -> anyhow::Result<Box<QueuedEvent>> {
    match message {
        ReaderMessage::Event(queued) => Ok(queued),
        ReaderMessage::Failed(error) => {
            Err(error).context("daemon stream failed before trace completion")
        }
    }
}

fn completed(event: &fstrace_common::Event) -> anyhow::Result<bool> {
    if event.syscall != wire::EVENT_DONE {
        return Ok(false);
    }
    anyhow::ensure!(
        event.ret == 0
            && event.path_len == 0
            && event.path2_len == 0
            && event.pid == 0
            && event.tid == 0
            && event.session == 0
            && event.birth == 0
            && event.child_birth == 0
            && event.dirfd == 0
            && event.dirfd2 == 0
            && event.flags == 0,
        "trace incomplete: daemon reported event loss or invalid completion status"
    );
    Ok(true)
}

extern "C" fn handle_sigusr1(_sig: i32) {
    FLUSH_REQUESTED.store(true, Ordering::SeqCst);
}

/// Use FSTRACE_REPORT_FILE when set, otherwise inherited fd 3.
fn open_report_sink() -> anyhow::Result<crate::report_sink::ReportSink> {
    if let Some(path) = std::env::var_os(REPORT_FILE_ENV) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .with_context(|| format!("opening {REPORT_FILE_ENV}={}", path.to_string_lossy()))?;
        return crate::report_sink::ReportSink::new(file).context("configuring report destination");
    }
    if unsafe { libc::fcntl(REPORT_FD, libc::F_GETFD) } == -1 {
        anyhow::bail!(
            "no report destination: fd 3 is closed. Use `fstrace ... 3>&1`, \
             `3>reports.txt`, or {REPORT_FILE_ENV}=/path/to/report. \
             sudo closes fd 3; run the client without sudo or redirect \
             inside the elevated shell."
        );
    }
    let mode = unsafe { libc::fcntl(REPORT_FD, libc::F_GETFL) };
    if mode == -1 {
        return Err(std::io::Error::last_os_error()).context("reading report descriptor flags");
    }
    anyhow::ensure!(
        mode & libc::O_ACCMODE != libc::O_RDONLY,
        "report file descriptor 3 is read-only"
    );
    // SAFETY: fd 3 is open (checked above); we take ownership for the sink.
    crate::report_sink::ReportSink::new(unsafe { File::from_raw_fd(REPORT_FD) })
        .context("configuring report descriptor")
}

fn connect_daemon() -> anyhow::Result<UnixStream> {
    let path = wire::socket_path();
    UnixStream::connect(&path).map_err(|err| {
        anyhow!(
            "cannot connect to daemon at {} ({err}); \
             start `sudo fstrace-daemon` or set {} to its socket path.",
            path.display(),
            wire::SOCKET_ENV
        )
    })
}

/// Fork a stopped child; exec starts after the daemon acknowledges registration.
fn spawn_child_os(program: &OsStr, args: &[OsString], token: [u64; 2]) -> anyhow::Result<Child> {
    let c_program = CString::new(program.as_bytes()).context("program contains NUL")?;
    let c_args: Vec<CString> = std::iter::once(program)
        .chain(args.iter().map(OsString::as_os_str))
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .context("argument contains NUL")?;
    let argv: Vec<_> = c_args
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let parent = unsafe { libc::getpid() };
    // SAFETY: the child path only calls async-signal-safe operations before exec.
    match unsafe { child::fork() }.context("fork with lifetime handle")? {
        Fork::Parent(child) => Ok(child),
        Fork::Child => {
            // Die with the client so the tracee never outlives fstrace.
            if prctl::set_pdeathsig(Signal::SIGKILL).is_err()
                || unsafe { libc::getppid() } != parent
                || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
            {
                unsafe {
                    libc::_exit(125);
                }
            }
            unsafe {
                libc::prctl(
                    fstrace_common::REGISTER_PRCTL as libc::c_int,
                    token[0],
                    token[1],
                    0u64,
                    0u64,
                );
            }
            // Raw clone does not reset libc's cached thread ID used by raise.
            unsafe {
                if libc::syscall(
                    libc::SYS_kill,
                    libc::syscall(libc::SYS_getpid),
                    libc::SIGSTOP,
                ) != 0
                {
                    libc::_exit(125);
                }
            }

            unsafe {
                if libc::signal(libc::SIGPIPE, libc::SIG_DFL) == libc::SIG_ERR {
                    libc::_exit(125);
                }
                libc::execvp(c_program.as_ptr(), argv.as_ptr());
            }
            unsafe {
                libc::write(
                    libc::STDERR_FILENO,
                    c"fstrace: failed to exec target\n".as_ptr().cast(),
                    31,
                );
                libc::_exit(127);
            }
        }
    }
}

/// Trace the command and return its exit code.
pub fn run(program: &str, args: &[String], filter: Filter, debounce: bool) -> anyhow::Result<i32> {
    run_os(OsStr::new(program), &os_args(args), filter, debounce)
}

fn os_args(args: &[String]) -> Vec<OsString> {
    args.iter()
        .map(|arg| OsString::from(arg.as_str()))
        .collect()
}

fn run_os(
    program: &OsStr,
    args: &[OsString],
    filter: Filter,
    debounce: bool,
) -> anyhow::Result<i32> {
    let sink = open_report_sink()?;
    let stream = connect_daemon()?;
    run_connected_os(program, args, filter, debounce, sink, stream)
}

fn run_connected_os<W: std::io::Write>(
    program: &OsStr,
    args: &[OsString],
    filter: Filter,
    debounce: bool,
    sink: W,
    mut stream: UnixStream,
) -> anyhow::Result<i32> {
    let total_start = Instant::now();
    let profiling = profile::enabled();
    let process_cpu_start = profiling.then(profile::process_cpu_ns);
    let runtime_profile = Arc::new(profile::ClientRuntimeProfile::default());

    // SAFETY: installing an async-signal-safe handler for SIGUSR1.
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1))
            .context("installing SIGUSR1 handler")?;
    }

    let handshake_start = Instant::now();
    stream
        .set_read_timeout(Some(COMPLETION_TIMEOUT))
        .context("setting handshake timeout")?;
    stream
        .set_write_timeout(Some(COMPLETION_TIMEOUT))
        .context("setting control timeout")?;
    let token = wire::read_challenge(&mut stream).context("reading registration challenge")?;
    let guard_socket = stream.try_clone().context("cloning cleanup socket")?;
    // Bind the token to this task's next fork, not a supplied PID.
    unsafe {
        libc::prctl(
            fstrace_common::REGISTER_PRCTL as libc::c_int,
            token[0],
            token[1],
            0u64,
            0u64,
        );
    }
    trace!(socket = %wire::socket_path().display(), "connected to daemon");

    let target = spawn_child_os(program, args, token)?;
    let child = target.pid();
    let session = SessionGuard {
        child: target,
        socket: guard_socket,
    };
    trace!(pid = child.as_raw(), program = ?program, "forked child (stopped)");
    match session
        .child
        .wait(WaitPidFlag::WUNTRACED)
        .context("waiting for initial stop")?
    {
        WaitStatus::Stopped(_, _) => {}
        other @ (WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)) => {
            return Err(anyhow!("child exited before registration: {other:?}"));
        }
        other => return Err(anyhow!("unexpected initial child status: {other:?}")),
    }
    wire::write_hello(&mut stream, 0).context("registering with daemon")?;
    let root_pid = wire::read_ack(&mut stream).context("daemon handshake")?;
    stream
        .set_read_timeout(None)
        .context("resetting event timeout")?;
    let handshake_duration = handshake_start.elapsed();
    trace!(pid = child.as_raw(), "daemon acknowledged; tracing active");

    let mut tracer = Tracer::new(CapturedSystem, filter, Debounce::new(debounce), sink);
    // Seed inherited cwd before allowing the child to exec.
    let cwd = std::env::current_dir().context("recording child's inherited working directory")?;
    tracer.seed_cwd(root_pid, cwd.to_string_lossy().into_owned());

    // Keep blocking reads off the thread that owns the non-Send tracer.
    let reader = stream.try_clone().context("cloning daemon socket")?;
    let (tx, rx) = mpsc::sync_channel::<ReaderMessage>(CLIENT_EVENT_QUEUE);
    let reader_profile = Arc::clone(&runtime_profile);
    let reader_handle = thread::Builder::new()
        .spawn(move || receive_events(reader, tx, profiling, reader_profile))
        .context("starting daemon event reader")?;

    let result = (|| -> anyhow::Result<i32> {
        session
            .child
            .signal(Signal::SIGCONT)
            .context("resuming child")?;
        trace!(pid = child.as_raw(), "resumed child");
        let child_start = Instant::now();

        let exit_code = loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(message) => {
                    let queued = stream_message(message)?;
                    anyhow::ensure!(!completed(&queued.event)?, "premature daemon completion");
                    if let Some(received_at) = queued.received_at {
                        runtime_profile
                            .record_queue_latency(profile::duration_ns(received_at.elapsed()));
                    }
                    tracer
                        .handle_event(&queued.event)
                        .context("writing access reports")?;
                    for message in rx.try_iter().take(63) {
                        let queued = stream_message(message)?;
                        anyhow::ensure!(!completed(&queued.event)?, "premature daemon completion");
                        if let Some(received_at) = queued.received_at {
                            runtime_profile
                                .record_queue_latency(profile::duration_ns(received_at.elapsed()));
                        }
                        tracer
                            .handle_event(&queued.event)
                            .context("writing access reports")?;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("daemon event stream ended before trace completion");
                }
            }

            if FLUSH_REQUESTED.swap(false, Ordering::SeqCst) {
                tracer.flush_debounce();
            }

            match session.child.wait(WaitPidFlag::WNOHANG) {
                Ok(WaitStatus::Exited(_, code)) => {
                    break code;
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    break 128 + sig as i32;
                }
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => {}
                Err(nix::errno::Errno::ECHILD) => {
                    anyhow::bail!("tracee was reaped externally");
                }
                Err(err) => return Err(err).context("waiting for tracee"),
            }
        };
        let child_duration = child_start.elapsed();

        let drain_start = Instant::now();
        wire::write_finish(&mut stream).context("requesting trace completion")?;
        let deadline = Instant::now() + COMPLETION_TIMEOUT;
        loop {
            let message = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .context("trace completion was not acknowledged")?;
            let queued = stream_message(message)?;
            if completed(&queued.event)? {
                break;
            }
            if let Some(received_at) = queued.received_at {
                runtime_profile.record_queue_latency(profile::duration_ns(received_at.elapsed()));
            }
            tracer
                .handle_event(&queued.event)
                .context("writing access reports")?;
        }
        tracer.flush().context("flushing access reports")?;

        let drain_duration = drain_start.elapsed();

        tracer.log_profile();
        if profiling {
            runtime_profile.log(
                total_start.elapsed(),
                handshake_duration,
                child_duration,
                drain_duration,
                profile::process_cpu_ns().saturating_sub(process_cpu_start.unwrap_or_default()),
            );
        }

        Ok(exit_code)
    })();
    // A bounded sender must lose its receiver before join, including failures.
    drop(rx);
    drop(session);
    reader_handle
        .join()
        .map_err(|_| anyhow!("event reader panicked"))?;
    result
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    print!(
        "\
fstrace {VERSION}
Trace filesystem accesses of a command using eBPF.

USAGE:
    fstrace [--] <COMMAND> [ARGS]...

ARGS:
    <COMMAND> [ARGS]...    Command to trace. All arguments after COMMAND,
                          including flags such as --help, pass through unchanged.

OPTIONS (must appear before COMMAND):
    -h, --help       Print this help and exit.
    -V, --version    Print version and exit.
    --               End fstrace's options; treat the rest as the command.

REPORTS:
    File-access reports are written to file descriptor 3. Redirect it, e.g.
    `fstrace ls 3>&1` (to stdout) or `fstrace ls 3>reports.txt`. Set
    FSTRACE_REPORT_FILE=<path> to write reports there instead (useful under sudo,
    which closes fd 3). Each line is `<access><type> <path>`; see fstrace(1).

ENVIRONMENT:
    FSTRACE_FILTER_PREFIX               Only report paths under these ':'-separated prefixes (default '/').
    FSTRACE_FILTER_SUBSTRING            Only report paths containing these ':'-separated substrings.
    FSTRACE_NEGATIVE_FILTER_PREFIX      Ignore paths under these ':'-separated prefixes.
    FSTRACE_NEGATIVE_FILTER_SUBSTRING   Ignore paths containing these ':'-separated substrings.
    FSTRACE_DEBOUNCE                    Set to 1 to debounce duplicate reports (SIGUSR1 flushes the cache).
    FSTRACE_REPORT_FILE                 Write reports to this path instead of file descriptor 3.
    FSTRACE_SOCKET                      Daemon socket path (default /run/fstrace/fstrace.sock).
    FSTRACE_PROFILE=1                   Emit aggregate client performance timings.
    FSTRACE_LOG_FILE / FSTRACE_LOG_DIR  Write logs to an explicit file / a per-process directory.
    RUST_LOG                            Log verbosity (e.g. fstrace=trace); FSTRACE_DEBUG=1 means fstrace=debug.

Requires a running fstrace-daemon (see `fstrace-daemon --help`).
Documentation: https://github.com/bmiddha/fstrace
"
    );
}

pub(crate) const LOG_FILE_ENV: &str = "FSTRACE_LOG_FILE";
/// Each process writes `<dir>/<component>.log`.
pub(crate) const LOG_DIR_ENV: &str = "FSTRACE_LOG_DIR";
/// Legacy alias for [`LOG_FILE_ENV`], kept for backwards compatibility.
pub(crate) const LEGACY_LOG_FILE_ENV: &str = "FSTRACE_DEBUG_FILE";

/// Append to the log file, or use stderr if it cannot be opened.
fn file_writer(path: std::path::PathBuf) -> BoxMakeWriter {
    BoxMakeWriter::new(move || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map(|f| Box::new(f) as Box<dyn std::io::Write>)
            .unwrap_or_else(|_| Box::new(std::io::stderr()))
    })
}

/// Prefer LOG_FILE, LOG_DIR, legacy DEBUG_FILE, then stderr.
/// The bool marks file output, which should not use ANSI colors.
fn resolve_log_writer(component: &str) -> (BoxMakeWriter, bool) {
    if let Some(path) = std::env::var_os(LOG_FILE_ENV) {
        return (file_writer(path.into()), true);
    }
    if let Some(dir) = std::env::var_os(LOG_DIR_ENV) {
        let _ = std::fs::create_dir_all(&dir);
        return (
            file_writer(std::path::Path::new(&dir).join(format!("{component}.log"))),
            true,
        );
    }
    if let Some(path) = std::env::var_os(LEGACY_LOG_FILE_ENV) {
        return (file_writer(path.into()), true);
    }
    (BoxMakeWriter::new(std::io::stderr), false)
}

/// Configure logging. RUST_LOG overrides the default level.
pub(crate) fn init_tracing(component: &str) {
    let default_directive = if profile::enabled() {
        "warn,fstrace::profile=info"
    } else if std::env::var_os("FSTRACE_DEBUG").is_some() {
        "fstrace=debug"
    } else {
        "warn"
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    let (writer, to_file) = resolve_log_writer(component);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(!to_file)
        .with_target(true)
        .without_time()
        .try_init();
}

/// Entry point for the `fstrace` binary.
pub fn entrypoint() -> ! {
    let mut raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    match raw.first().and_then(|arg| arg.to_str()) {
        Some("-h") | Some("--help") => {
            print_help();
            std::process::exit(0);
        }
        Some("-V") | Some("--version") => {
            println!("fstrace {VERSION}");
            std::process::exit(0);
        }
        Some("--") => {
            raw.remove(0);
        }
        _ => {}
    }
    if raw.is_empty() {
        eprintln!(
            "Usage: fstrace [--] <command> [args...]\n\
             Try 'fstrace --help' for more information."
        );
        std::process::exit(1);
    }
    let options = Options::from_env();
    let component = format!("fstrace-{}", std::process::id());
    init_tracing(&component);
    match run_os(&raw[0], &raw[1..], options.filter, options.debounce) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("fstrace: {err:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
fn spawn_child(program: &str, args: &[String], token: [u64; 2]) -> anyhow::Result<Child> {
    spawn_child_os(OsStr::new(program), &os_args(args), token)
}

#[cfg(test)]
fn run_connected<W: std::io::Write>(
    program: &str,
    args: &[String],
    filter: Filter,
    debounce: bool,
    sink: W,
    stream: UnixStream,
) -> anyhow::Result<i32> {
    run_connected_os(
        OsStr::new(program),
        &os_args(args),
        filter,
        debounce,
        sink,
        stream,
    )
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use fstrace_common::{Event, Syscall};
    use nix::sys::wait::waitpid;

    use super::*;

    fn fake_daemon(
        action: impl FnOnce(UnixStream) + Send + 'static,
    ) -> (UnixStream, thread::JoinHandle<()>) {
        let (client, mut server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let handle = thread::spawn(move || {
            wire::write_challenge(&mut server, [0; 2]).unwrap();
            assert_eq!(wire::read_hello(&mut server).unwrap(), 0);
            wire::write_ack(&mut server, 1).unwrap();
            action(server);
        });
        (client, handle)
    }

    fn finish(server: &mut UnixStream) {
        let mut command = [0];
        server.read_exact(&mut command).unwrap();
        assert_eq!(command[0], wire::FINISH);
    }

    fn report() -> Event {
        let mut event = Event::zeroed();
        event.pid = 1;
        event.tid = 1;
        event.syscall = Syscall::Openat as u32;
        event.ret = 4;
        event.path[..6].copy_from_slice(b"/input");
        event.path_len = 6;
        event
    }

    fn done() -> Event {
        let mut event = Event::zeroed();
        event.syscall = wire::EVENT_DONE;
        event
    }

    #[test]
    fn child_restores_sigpipe_without_changing_parent_policy() {
        fn disposition() -> libc::sighandler_t {
            let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) },
                0
            );
            unsafe { action.assume_init().sa_sigaction }
        }
        let parent_policy = disposition();
        let (stream, server) = fake_daemon(|mut socket| {
            finish(&mut socket);
            socket.write_all(&wire::encode_event(&done())).unwrap();
        });
        assert_eq!(
            run_connected(
                "/bin/sh",
                &["-c".into(), "kill -PIPE $$; exit 77".into()],
                Filter::default(),
                false,
                Vec::new(),
                stream,
            )
            .unwrap(),
            141
        );
        server.join().unwrap();
        assert_eq!(disposition(), parent_policy);
    }

    #[test]
    fn os_arguments_reach_exec_without_utf8_conversion() {
        use std::os::unix::ffi::OsStringExt;
        let (stream, server) = fake_daemon(|mut socket| {
            finish(&mut socket);
            socket.write_all(&wire::encode_event(&done())).unwrap();
        });
        assert_eq!(
            run_connected_os(
                OsStr::new("/usr/bin/test"),
                &[
                    OsString::from_vec(vec![0xff]),
                    "!=".into(),
                    "\u{fffd}".into(),
                ],
                Filter::default(),
                false,
                Vec::new(),
                stream,
            )
            .unwrap(),
            0
        );
        server.join().unwrap();
    }

    #[test]
    fn unresolved_event_cancels_runtime_instead_of_reporting_success() {
        let (stream, server) = fake_daemon(|mut socket| {
            let mut event = report();
            event.path[..5].copy_from_slice(b"hosts");
            event.path_len = 5;
            event.dirfd = 7;
            socket.write_all(&wire::encode_event(&event)).unwrap();
            let mut command = [0];
            assert_eq!(socket.read(&mut command).unwrap(), 0);
        });
        let error = run_connected(
            "/bin/sleep",
            &["5".into()],
            Filter::default(),
            false,
            Vec::new(),
            stream,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("trace incomplete"));
        server.join().unwrap();
    }

    #[test]
    fn delayed_reports_are_drained_before_done() {
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (stream, server) = fake_daemon(|mut socket| {
            finish(&mut socket);
            thread::sleep(Duration::from_millis(250));
            socket.write_all(&wire::encode_event(&report())).unwrap();
            socket.write_all(&wire::encode_event(&done())).unwrap();
        });
        assert_eq!(
            run_connected(
                "/bin/true",
                &[],
                Filter::default(),
                false,
                Sink(output.clone()),
                stream
            )
            .unwrap(),
            0
        );
        server.join().unwrap();
        assert_eq!(&*output.lock().unwrap(), b"RF /input\n");
    }

    #[test]
    fn stream_eof_truncation_and_invalid_lengths_fail_promptly() {
        for mode in 0..3 {
            let (stream, server) = fake_daemon(move |mut socket| {
                if mode == 1 {
                    socket.write_all(&[0; 5]).unwrap();
                }
                if mode == 2 {
                    let mut bytes = wire::encode_event(&report());
                    bytes[36..40]
                        .copy_from_slice(&(fstrace_common::PATH_MAX as u32 + 1).to_le_bytes());
                    socket.write_all(&bytes).unwrap();
                }
            });
            let start = Instant::now();
            let result = run_connected(
                "/bin/sleep",
                &["10".into()],
                Filter::default(),
                false,
                Vec::new(),
                stream,
            );
            assert!(result.is_err());
            assert!(start.elapsed() < Duration::from_secs(3));
            server.join().unwrap();
        }
    }

    #[test]
    fn missing_or_lossy_done_is_not_success() {
        for loss in [false, true] {
            let (stream, server) = fake_daemon(move |mut socket| {
                finish(&mut socket);
                if loss {
                    let mut event = done();
                    event.ret = 1;
                    socket.write_all(&wire::encode_event(&event)).unwrap();
                }
            });
            assert!(
                run_connected(
                    "/bin/true",
                    &[],
                    Filter::default(),
                    false,
                    Vec::new(),
                    stream
                )
                .is_err()
            );
            server.join().unwrap();
        }
    }

    struct FailingSink {
        flush_only: bool,
    }
    impl Write for FailingSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.flush_only {
                Ok(bytes.len())
            } else {
                Err(io::Error::other("report storage full"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("report flush failed"))
        }
    }

    #[test]
    fn report_write_and_flush_errors_reach_runtime_caller() {
        for flush_only in [false, true] {
            let (stream, server) = fake_daemon(|mut socket| {
                finish(&mut socket);
                socket.write_all(&wire::encode_event(&report())).unwrap();
                socket.write_all(&wire::encode_event(&done())).unwrap();
            });
            let error = run_connected(
                "/bin/true",
                &[],
                Filter::default(),
                false,
                FailingSink { flush_only },
                stream,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains(if flush_only {
                "flushing access reports"
            } else {
                "writing access reports"
            }));
            server.join().unwrap();
        }
    }

    #[test]
    fn bounded_reader_can_be_cancelled_while_queue_is_full() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let shutdown = reader.try_clone().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || receive_events(reader, tx, false, Arc::default()));
        let event = wire::encode_event(&Event::zeroed());
        writer.write_all(&event).unwrap();
        writer.write_all(&event).unwrap();
        writer.write_all(&event).unwrap();
        thread::sleep(Duration::from_millis(20));
        drop(rx);
        shutdown.shutdown(std::net::Shutdown::Both).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn cleanup_guard_kills_and_reaps_stopped_direct_child() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let child = spawn_child("/bin/sleep", &["10".into()], [0; 2]).unwrap();
        let pid = child.pid();
        assert!(matches!(
            waitpid(pid, Some(WaitPidFlag::WUNTRACED)).unwrap(),
            WaitStatus::Stopped(_, _)
        ));
        drop(SessionGuard { child, socket });
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
    }
}
