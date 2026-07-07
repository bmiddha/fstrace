//! Unprivileged fstrace client.
//!
//! The client itself needs no elevation: it connects to the privileged
//! `fstrace-daemon` over a Unix socket, forks the target as the invoking user,
//! asks the daemon to trace it, and then turns the raw kernel events streamed
//! back over the socket into resolved, classified, filtered reports. All eBPF
//! loading lives in the daemon; this process only does path resolution against
//! its own `/proc` (which it may read for its own descendants) and reporting.

use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{FromRawFd, RawFd},
        unix::net::UnixStream,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use nix::{
    sys::{
        prctl,
        signal::{self, SigHandler, Signal},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, execvp, fork},
};
use tracing::{trace, warn};
use tracing_subscriber::{EnvFilter, fmt::writer::BoxMakeWriter};

use crate::{Tracer, debounce::Debounce, filter::Filter, options::Options, proc::RealSystem, wire};

/// File descriptor reports are written to, matching the original tool.
const REPORT_FD: RawFd = 3;

/// Optional path override for the report stream. Useful under `sudo`, which
/// closes inherited file descriptors >= 3 and thus breaks a `3>&1` redirection.
const REPORT_FILE_ENV: &str = "FSTRACE_REPORT_FILE";

/// Set by the `SIGUSR1` handler; drains to a debounce flush in the event loop.
static FLUSH_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigusr1(_sig: i32) {
    FLUSH_REQUESTED.store(true, Ordering::SeqCst);
}

/// Opens the destination for the report stream. If `FSTRACE_REPORT_FILE` is set
/// the reports are written to that path; otherwise the inherited descriptor 3
/// is used. When neither is available (typically a missing `3>&1` redirection,
/// or `sudo` having closed fd 3), a clear error explains how to fix the
/// invocation.
fn open_report_sink() -> anyhow::Result<File> {
    if let Some(path) = std::env::var_os(REPORT_FILE_ENV) {
        return File::create(&path)
            .with_context(|| format!("opening {REPORT_FILE_ENV}={}", path.to_string_lossy()));
    }
    // Validate that fd 3 is actually open before taking ownership of it.
    if unsafe { libc::fcntl(REPORT_FD, libc::F_GETFD) } == -1 {
        anyhow::bail!(
            "no report destination: reports are written to file descriptor 3, \
             but it is not open. Add a redirection, e.g. `fstrace ... 3>&1` \
             (reports to stdout) or `fstrace ... 3>reports.txt`, or set \
             {REPORT_FILE_ENV}=/path/to/report. Note: the client does not need \
             `sudo` (only `fstrace-daemon` does); running it under `sudo` closes \
             fd 3, so drop the `sudo` or put the redirection inside the elevated \
             shell, e.g. `sudo sh -c 'fstrace ... 3>&1'`."
        );
    }
    // SAFETY: fd 3 is open (checked above); we take ownership for the sink.
    Ok(unsafe { File::from_raw_fd(REPORT_FD) })
}

/// Connects to the daemon, returning a friendly error when it isn't running.
fn connect_daemon() -> anyhow::Result<UnixStream> {
    let path = wire::socket_path();
    UnixStream::connect(&path).map_err(|err| {
        anyhow!(
            "cannot connect to the fstrace daemon at {} ({err}). \
             Start it first with: `sudo fstrace-daemon` \
             (or set {} to its socket path).",
            path.display(),
            wire::SOCKET_ENV
        )
    })
}

/// Forks and execs the target, pausing the child until the daemon has begun
/// tracing it. Returns the child's pid (parent) or never returns (child).
fn spawn_child(program: &str, args: &[String]) -> anyhow::Result<Pid> {
    // SAFETY: the child path only calls async-signal-safe operations before exec.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Parent { child } => Ok(child),
        ForkResult::Child => {
            // Die with the client so the tracee never outlives fstrace.
            let _ = prctl::set_pdeathsig(Signal::SIGKILL);
            // Stop so the daemon can register us before any syscalls run.
            let _ = signal::raise(Signal::SIGSTOP);

            let c_program = CString::new(program).unwrap();
            let c_args: Vec<CString> = std::iter::once(program)
                .chain(args.iter().map(String::as_str))
                .map(|a| CString::new(a).unwrap())
                .collect();
            let _ = execvp(&c_program, &c_args);
            // execvp only returns on failure.
            eprintln!("fstrace: failed to exec {program}");
            std::process::exit(127);
        }
    }
}

/// Runs the tracer against `program`/`args`, returning the process exit code to
/// propagate.
pub fn run(program: &str, args: &[String], filter: Filter, debounce: bool) -> anyhow::Result<i32> {
    // Acquire the report sink before anything else so a closed fd 3 is detected
    // deterministically (see `open_report_sink`).
    let sink = open_report_sink()?;

    // SAFETY: installing an async-signal-safe handler for SIGUSR1.
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1))
            .context("installing SIGUSR1 handler")?;
    }

    let mut stream = connect_daemon()?;
    trace!(socket = %wire::socket_path().display(), "connected to daemon");

    // Fork the (stopped) child, register it with the daemon, and only resume it
    // once the daemon has acknowledged — so no early syscalls are missed.
    let child = spawn_child(program, args)?;
    trace!(pid = child.as_raw(), program, "forked child (stopped)");
    match waitpid(child, Some(WaitPidFlag::WUNTRACED)).context("waitpid (initial stop)")? {
        WaitStatus::Stopped(_, _) => {}
        other => return Err(anyhow!("unexpected initial child status: {other:?}")),
    }
    wire::write_hello(&mut stream, child.as_raw() as u32).context("registering with daemon")?;
    wire::read_ack(&mut stream).context("daemon handshake")?;
    trace!(pid = child.as_raw(), "daemon acknowledged; tracing active");

    let mut tracer = Tracer::new(RealSystem, filter, Debounce::new(debounce), sink);
    // The child inherits our working directory; seed it so cwd-relative paths
    // resolve even if the child exits before we can read `/proc/<pid>/cwd`.
    if let Ok(cwd) = std::env::current_dir() {
        tracer.seed_cwd(child.as_raw() as u32, cwd.to_string_lossy().into_owned());
    }

    // Reader thread: blocking-reads whole events off the socket and forwards
    // them to the main loop, which owns the (non-Send) tracer.
    let mut reader = stream.try_clone().context("cloning daemon socket")?;
    let (tx, rx) = mpsc::channel::<fstrace_common::Event>();
    let reader_handle = thread::spawn(move || {
        while let Ok(ev) = wire::read_event(&mut reader) {
            if tx.send(ev).is_err() {
                break;
            }
        }
    });

    // Resume the child now that tracing is active.
    signal::kill(child, Signal::SIGCONT).context("resuming child")?;
    trace!(pid = child.as_raw(), "resumed child");

    let exit_code = loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(ev) => {
                let _ = tracer.handle_event(&ev);
                while let Ok(ev) = rx.try_recv() {
                    let _ = tracer.handle_event(&ev);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Daemon closed the stream; keep looping only to reap the child.
            }
        }

        if FLUSH_REQUESTED.swap(false, Ordering::SeqCst) {
            tracer.flush_debounce();
        }

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => break code,
            Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
            Ok(_) => {}
            Err(nix::errno::Errno::ECHILD) => break 0,
            Err(err) => {
                warn!("waitpid failed: {err}");
                break 1;
            }
        }
    };

    // Drain any events emitted right before the child exited.
    while let Ok(ev) = rx.recv_timeout(Duration::from_millis(50)) {
        let _ = tracer.handle_event(&ev);
    }
    let _ = tracer.flush();

    // Tear down the connection so the daemon cleans up our pids.
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = reader_handle.join();

    Ok(exit_code)
}

/// Version string reported by `--version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prints the `fstrace --help` text.
fn print_help() {
    print!(
        "\
fstrace {VERSION}
Trace filesystem accesses of a command using eBPF.

USAGE:
    fstrace [--] <COMMAND> [ARGS]...

ARGS:
    <COMMAND> [ARGS]...    The program to run and trace, followed by its own
                          arguments. Everything after the command — including
                          flags such as --help — is passed through to it
                          unchanged, so `fstrace ls --help` shows ls's help.

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
    FSTRACE_LOG_FILE / FSTRACE_LOG_DIR  Write logs to an explicit file / a per-process directory.
    RUST_LOG                            Log verbosity (e.g. fstrace=trace); FSTRACE_DEBUG=1 means fstrace=debug.

Requires a running fstrace-daemon (see `fstrace-daemon --help`).
Documentation: https://github.com/bmiddha/fstrace
"
    );
}

/// Environment variable naming an explicit log-file path (all binaries).
pub(crate) const LOG_FILE_ENV: &str = "FSTRACE_LOG_FILE";
/// Environment variable naming a directory into which each process writes its
/// own log file (`<dir>/<component>.log`), so the daemon and concurrent clients
/// never interleave.
pub(crate) const LOG_DIR_ENV: &str = "FSTRACE_LOG_DIR";
/// Legacy alias for [`LOG_FILE_ENV`], kept for backwards compatibility.
pub(crate) const LEGACY_LOG_FILE_ENV: &str = "FSTRACE_DEBUG_FILE";

/// Builds a make-writer that appends to `path`, falling back to stderr if the
/// file cannot be opened.
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

/// Resolves where log output goes for the process identified by `component`
/// (e.g. `fstrace-daemon` or `fstrace-<pid>`), honouring, in order of
/// precedence: `FSTRACE_LOG_FILE` (explicit path), `FSTRACE_LOG_DIR`
/// (per-process file `<dir>/<component>.log`), the legacy `FSTRACE_DEBUG_FILE`,
/// and finally stderr. The returned bool is `true` when output is a file (so
/// ANSI colouring should be disabled).
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

/// Initializes `tracing` for the process named `component`, routing output to a
/// file when `FSTRACE_LOG_FILE`/`FSTRACE_LOG_DIR` (or legacy `FSTRACE_DEBUG_FILE`)
/// is set (see [`resolve_log_writer`]) and to stderr otherwise.
///
/// Verbosity is controlled by the standard `RUST_LOG` environment variable
/// (e.g. `RUST_LOG=fstrace=trace`, `RUST_LOG=debug`, `RUST_LOG=fstrace::engine=trace`).
/// When `RUST_LOG` is unset the default level is `debug` if `FSTRACE_DEBUG` is
/// set (a shorthand for `RUST_LOG=fstrace=debug`) and `warn` otherwise.
pub(crate) fn init_tracing(component: &str) {
    // `RUST_LOG` fully overrides the default when present; `FSTRACE_DEBUG` is a
    // convenience shorthand for bumping fstrace's own modules to debug.
    let default_directive = if std::env::var_os("FSTRACE_DEBUG").is_some() {
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
        // Plain text in files; colour only when writing to the terminal.
        .with_ansi(!to_file)
        .with_target(true)
        .without_time()
        .try_init();
}

/// Entry point for the `fstrace` binary.
///
/// Handles `--help`/`--version` when they appear before the command, then runs
/// the tracer and exits with the child's propagated exit code. Everything from
/// the command word onward (including flags like `--help`) is passed through to
/// the traced program unchanged. Never returns.
pub fn entrypoint() -> ! {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    match raw.first().map(String::as_str) {
        Some("-h") | Some("--help") => {
            print_help();
            std::process::exit(0);
        }
        Some("-V") | Some("--version") => {
            println!("fstrace {VERSION}");
            std::process::exit(0);
        }
        // `--` explicitly ends fstrace's own options; the rest is the command.
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
    // Per-process component name so FSTRACE_LOG_DIR yields a distinct file per
    // client (e.g. fstrace-1234.log).
    let component = format!("fstrace-{}", std::process::id());
    init_tracing(&component);

    let program = &raw[0];
    let args = &raw[1..];

    match run(program, args, options.filter, options.debounce) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("fstrace: {err:#}");
            std::process::exit(1);
        }
    }
}
