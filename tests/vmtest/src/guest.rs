//! The privileged in-guest bootstrap, run once as root.
//!
//! Creates an unprivileged `fstuser`, publishes the client binaries where that
//! user can reach them, starts the `fstrace-daemon`, then runs the client suite
//! as `fstuser` so all tracing happens sudo-less. Finally it exercises systemd
//! socket activation. Gates success on both the client suite and that test.

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

const CLIENT_USER: &str = "fstuser";
const DEFAULT_SOCKET: &str = "/run/fstrace/fstrace.sock";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

/// Copies `src` to `dst` with mode 0755.
fn install(src: &Path, dst: &str) -> Result<()> {
    std::fs::copy(src, dst).with_context(|| format!("installing {} -> {dst}", src.display()))?;
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o755);
    std::fs::set_permissions(dst, perms)?;
    Ok(())
}

/// Kernel probe loading under TCG can exceed ten seconds on large mainline BTF.
fn wait_for_socket(path: &str, process: &mut Child) -> Result<bool> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            println!(
                "socket ready at {path} after {:.1}s",
                start.elapsed().as_secs_f64()
            );
            return Ok(true);
        }
        if let Some(status) = process.try_wait().context("checking daemon startup")? {
            println!("socket process exited before readiness: {status}");
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("socket startup timed out at {path} after 60s");
    Ok(false)
}

/// Builds `su <CLIENT_USER> -c "<script>"`.
fn su(script: &str) -> Command {
    let mut cmd = Command::new("su");
    cmd.arg(CLIENT_USER).arg("-c").arg(script);
    cmd
}

/// Creates an unprivileged login user with a home directory, working across
/// both shadow-utils (`useradd`, Debian/Ubuntu) and BusyBox (`adduser`, Alpine).
fn create_user(user: &str) -> Result<()> {
    if which("useradd").is_ok() {
        let ok = Command::new("useradd")
            .args(["-m", user])
            .status()
            .context("useradd")?
            .success();
        if ok {
            return Ok(());
        }
    }
    // BusyBox `adduser`: `-D` disables the password (non-interactive), `-h` sets
    // the home directory, `-s` the shell.
    if which("adduser").is_ok() {
        let ok = Command::new("adduser")
            .args(["-D", "-h", &format!("/home/{user}"), "-s", "/bin/sh", user])
            .status()
            .context("adduser")?
            .success();
        if ok {
            return Ok(());
        }
    }
    bail!("could not create user {user}: neither useradd nor adduser worked");
}

/// Name of a POSIX shell that reliably exists: `bash` on Debian/Ubuntu, or the
/// BusyBox `sh` (ash) on Alpine. Used for the fork-following test.
fn portable_shell() -> &'static str {
    if which("bash").is_ok() { "bash" } else { "sh" }
}

fn find_socket_activate() -> Option<String> {
    if let Ok(p) = which("systemd-socket-activate") {
        return Some(p);
    }
    for c in [
        "/usr/lib/systemd/systemd-socket-activate",
        "/lib/systemd/systemd-socket-activate",
    ] {
        if Path::new(c).is_file() {
            return Some(c.to_string());
        }
    }
    None
}

fn which(bin: &str) -> Result<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()?;
    if out.status.success() {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !p.is_empty() {
            return Ok(p);
        }
    }
    bail!("{bin} not found")
}

/// Runs the systemd socket-activation test. Returns `Ok(true)` on pass,
/// `Ok(false)` on failure, and prints a SKIP + `Ok(true)` when the tool is
/// absent (matching the original harness).
fn socket_activation_test(daemon: &str) -> Result<bool> {
    println!("=== systemd socket-activation test ===");
    let Some(sa_bin) = find_socket_activate() else {
        println!("SKIP  socket-activation (systemd-socket-activate not found)");
        return Ok(true);
    };

    let sa_sock = "/run/fstrace/fstrace-sa.sock";
    let sa_testdir = "/tmp/fstrace-sa-dir";
    let _ = std::fs::remove_file(sa_sock);
    let _ = std::fs::remove_dir_all(sa_testdir);
    std::fs::create_dir_all(sa_testdir)?;
    std::fs::File::create(format!("{sa_testdir}/file0"))?;
    Command::new("chown")
        .args(["-R", CLIENT_USER, sa_testdir])
        .status()?;

    let sa_log = std::fs::File::create("/tmp/fstrace-sa.log")?;
    let mut activator = Command::new(sa_bin)
        .args(["-l", sa_sock, daemon])
        .stdout(sa_log.try_clone()?)
        .stderr(sa_log)
        .spawn()
        .context("spawning systemd-socket-activate")?;

    let mut result = false;
    if wait_for_socket(sa_sock, &mut activator)? {
        let _ = Command::new("chmod").args(["0666", sa_sock]).status();
        let script = format!(
            "FSTRACE_SOCKET='{sa_sock}' FSTRACE_FILTER_PREFIX='{sa_testdir}' \
             /usr/local/bin/fstrace cat '{sa_testdir}/file0' 3>&1 1>/dev/null"
        );
        let out = su(&script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        let reports = String::from_utf8_lossy(&out.stdout);
        if reports.contains(&format!("RF {sa_testdir}/file0")) {
            println!("PASS  socket-activation (systemd sd_listen_fds)");
            result = true;
        } else {
            println!("FAIL  socket-activation — no events via activated socket");
            println!("-- client out --\n{reports}");
            println!(
                "-- client error --\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            print_file("/tmp/fstrace-sa.log");
        }
    } else {
        println!("FAIL  socket-activation — socket never appeared");
        print_file("/tmp/fstrace-sa.log");
    }

    let _ = activator.kill();
    let _ = activator.wait();
    let _ = std::fs::remove_file(sa_sock);
    let _ = std::fs::remove_dir_all(sa_testdir);
    Ok(result)
}

fn print_file(path: &str) {
    if let Ok(s) = std::fs::read_to_string(path) {
        print!("{s}");
    }
}

/// Traces `argv` (a shell-quoted command) as the unprivileged `fstuser` against
/// the daemon at `sock`, scoping reports to `prefix`, and returns the captured
/// fd-3 report stream.
fn trace_as_user(sock: &str, prefix: &str, argv: &str) -> Result<String> {
    let script = format!(
        "FSTRACE_SOCKET='{sock}' FSTRACE_FILTER_PREFIX='{prefix}' \
         /usr/local/bin/fstrace {argv} 3>&1 1>/dev/null"
    );
    let out = su(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        eprintln!(
            "trace failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Runs the container-style namespace-isolation test.
///
/// The privileged daemon deliberately never reads `/proc` for path or pid
/// resolution — it only loads eBPF and routes kernel events by their
/// root-namespace pid — so it stays correct even when it runs in a *different*
/// pid and mount namespace than its clients (exactly the case when it is
/// containerized with the socket bind-mounted to the host). This reproduces
/// that split with `unshare`: the daemon runs in fresh pid + mount + uts + ipc
/// namespaces (with its own `/proc`), while the client runs in the host
/// namespace, and we assert traces — including fork-following across the
/// boundary — are still correct.
///
/// Returns `Ok(true)` on pass, `Ok(false)` on failure, and a SKIP + `Ok(true)`
/// when `unshare` is unavailable.
fn namespace_isolation_test(daemon: &str) -> Result<bool> {
    println!("=== namespace-isolation test (containerized daemon) ===");
    if which("unshare").is_err() {
        println!("SKIP  namespace-isolation (unshare not found)");
        return Ok(true);
    }

    let ns_sock = "/run/fstrace/fstrace-ns.sock";
    let ns_dir = "/tmp/fstrace-ns-dir";
    let _ = std::fs::remove_file(ns_sock);
    let _ = std::fs::remove_dir_all(ns_dir);
    std::fs::create_dir_all(ns_dir)?;
    std::fs::write(format!("{ns_dir}/file0"), b"hello\n")?;
    Command::new("chown")
        .args(["-R", CLIENT_USER, ns_dir])
        .status()?;

    // Launch the daemon in fresh pid + mount + uts + ipc namespaces. `-f -p
    // --mount-proc` makes the daemon pid 1 in a namespace with its own `/proc`,
    // so it cannot see the client's pids there — proving routing relies solely
    // on the eBPF-reported (root-namespace) pids, not `/proc`. Short flags are
    // used so this works on both util-linux and BusyBox `unshare` (Alpine).
    let ns_log = std::fs::File::create("/tmp/fstrace-ns.log")?;
    let mut daemon_proc = Command::new("unshare")
        .args(["-f", "-p", "--mount-proc", "-u", "-i", daemon])
        .env("FSTRACE_SOCKET", ns_sock)
        .stdout(ns_log.try_clone()?)
        .stderr(ns_log)
        .spawn()
        .context("spawning unshare'd daemon")?;

    let mut result = false;
    if wait_for_socket(ns_sock, &mut daemon_proc)? {
        let _ = Command::new("chmod").args(["0666", ns_sock]).status();

        // (1) Direct read: proves eBPF loads in the namespaced daemon and events
        // route back to a host-namespace client with a correctly resolved path.
        let read = trace_as_user(ns_sock, ns_dir, &format!("cat '{ns_dir}/file0'"))?;
        let read_ok = read.contains(&format!("RF {ns_dir}/file0"));

        // (2) Fork-following across the pid-namespace boundary: the shell forks
        // a child `cat` (the trailing `:` keeps the shell from exec-optimizing
        // it away); the child's events must still route to the client.
        let sh = portable_shell();
        let fork = trace_as_user(
            ns_sock,
            ns_dir,
            &format!("{sh} -c \"cat '{ns_dir}/file0'; :\""),
        )?;
        let fork_ok = fork.contains(&format!("RF {ns_dir}/file0"));
        let auth_ok = super::client::registration_rejections(ns_sock)?;
        let nested = Command::new("unshare")
            .args(["-f", "-p", "--mount-proc", "su", CLIENT_USER, "-c"])
            .arg(format!("FSTRACE_SOCKET='{ns_sock}' FSTRACE_FILTER_PREFIX='{ns_dir}' /usr/local/bin/fstrace cat '{ns_dir}/file0' 3>&1 1>/dev/null"))
            .output()?;
        let nested_reports = String::from_utf8_lossy(&nested.stdout);
        let nested_ok =
            nested.status.success() && nested_reports.trim() == format!("RF {ns_dir}/file0");
        let inherited = Command::new("unshare")
            .args(["-f", "-p", "--mount-proc", "su", CLIENT_USER, "-c"])
            .arg(format!("exec 7<'{ns_dir}'; FSTRACE_SOCKET='{ns_sock}' FSTRACE_FILTER_PREFIX='{ns_dir}' /usr/local/bin/fstrace /usr/local/bin/fstrace-scenario inherited-dirfd 3>&1 1>/dev/null"))
            .output()?;
        let inherited_ok = !inherited.status.success()
            && String::from_utf8_lossy(&inherited.stderr).contains("trace incomplete")
            && !String::from_utf8_lossy(&inherited.stdout).contains(&format!("RF {ns_dir}/file0"));

        if read_ok && fork_ok && auth_ok && nested_ok && inherited_ok {
            println!(
                "PASS  namespace-isolation (private daemon, nested client, authenticated forks)"
            );
            result = true;
        } else {
            println!(
                "FAIL  namespace-isolation (read_ok={read_ok}, fork_follow_ok={fork_ok}, auth_ok={auth_ok}, nested_ok={nested_ok}, inherited_ok={inherited_ok})"
            );
            println!(
                "-- nested client --\n{nested_reports}\n{}",
                String::from_utf8_lossy(&nested.stderr)
            );
            println!("-- read reports --\n{read}");
            println!("-- fork reports --\n{fork}");
            print_file("/tmp/fstrace-ns.log");
        }
    } else {
        println!("FAIL  namespace-isolation — daemon socket never appeared");
        print_file("/tmp/fstrace-ns.log");
    }

    let _ = daemon_proc.kill();
    let _ = daemon_proc.wait();
    let _ = std::fs::remove_file(ns_sock);
    let _ = std::fs::remove_dir_all(ns_dir);
    Ok(result)
}

/// Runs the full privileged bootstrap. Returns `Ok(())` iff the client suite
/// and the socket-activation test both pass.
pub fn run() -> Result<()> {
    let fstrace = PathBuf::from(env_or("FSTRACE", "/root/fstrace/fstrace"));
    let daemon = env_or("FSTRACE_DAEMON", "/root/fstrace/fstrace-daemon");
    let scenario = PathBuf::from(env_or("FSTRACE_SCENARIO", "/root/fstrace/fstrace-scenario"));
    let socket = env_or("FSTRACE_SOCKET", DEFAULT_SOCKET);
    let self_bin = std::env::current_exe().context("resolving current exe")?;
    required_hook_failure(&daemon)?;

    // Create the unprivileged user (idempotent). Prefer shadow's `useradd`
    // (Debian/Ubuntu) but fall back to BusyBox `adduser` (Alpine), whose flags
    // differ: `-D` disables the password, `-h` sets the home directory.
    if !Command::new("id")
        .arg(CLIENT_USER)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        create_user(CLIENT_USER)?;
    }

    fn required_hook_failure(daemon: &str) -> Result<()> {
        let path = "/tmp/fstrace-missing-hook";
        let socket = "/tmp/fstrace-missing-hook.sock";
        let mut bytes = std::fs::read(daemon)?;
        let original = b"sys_openat\0";
        let mut replaced = 0;
        for pos in 0..bytes.len().saturating_sub(original.len()) {
            if &bytes[pos..pos + original.len()] == original {
                bytes[pos..pos + original.len()].copy_from_slice(b"sys_xpenat\0");
                replaced += 1;
            }
        }
        anyhow::ensure!(replaced > 0, "cannot locate embedded openat program");
        std::fs::write(path, bytes)?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        let log = std::fs::File::create("/tmp/fstrace-missing-hook.log")?;
        let mut child = Command::new(path)
            .args(["--socket", socket])
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(60) {
                child.kill()?;
                child.wait()?;
                bail!("missing-hook startup did not exit");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let error = std::fs::read_to_string("/tmp/fstrace-missing-hook.log")?;
        std::fs::remove_file(path)?;
        anyhow::ensure!(
            !status.success()
                && !Path::new(socket).exists()
                && error.contains("required sys_xpenat"),
            "missing hook allowed startup: {error}"
        );
        println!("PASS: missing openat hook fails before socket publication");
        Ok(())
    }
    install(&fstrace, "/usr/local/bin/fstrace")?;
    install(&scenario, "/usr/local/bin/fstrace-scenario")?;
    install(&scenario, "/usr/local/bin/fstrace-scenario-setuid")?;
    std::fs::set_permissions(
        "/usr/local/bin/fstrace-scenario-setuid",
        std::os::unix::fs::PermissionsExt::from_mode(0o4755),
    )?;
    install(&self_bin, "/usr/local/bin/fstrace-vmtest")?;

    println!("=== starting fstrace-daemon (root) ===");
    let daemon_log = std::fs::File::create("/tmp/fstrace-daemon.log")?;
    let mut daemon_proc = Command::new(&daemon)
        .stdout(daemon_log.try_clone()?)
        .stderr(daemon_log)
        .spawn()
        .with_context(|| format!("spawning daemon {daemon}"))?;

    if !wait_for_socket(&socket, &mut daemon_proc)? {
        let _ = daemon_proc.kill();
        let _ = daemon_proc.wait();
        print_file("/tmp/fstrace-daemon.log");
        bail!("daemon socket never appeared at {socket}");
    }
    println!("daemon up on {socket}; running client suite as '{CLIENT_USER}'");
    if let Err(error) = super::client::retained_peer_cancellation(&socket, daemon_proc.id()) {
        let _ = daemon_proc.kill();
        let _ = daemon_proc.wait();
        return Err(error);
    }

    let script = format!(
        "FSTRACE=/usr/local/bin/fstrace FSTRACE_SCENARIO=/usr/local/bin/fstrace-scenario \
         FSTRACE_SOCKET='{socket}' /usr/local/bin/fstrace-vmtest client"
    );
    let client_ok = su(&script).status()?.success();
    if !client_ok {
        println!("-- /tmp/fstrace-daemon.log --");
        print_file("/tmp/fstrace-daemon.log");
    }

    println!("=== stopping daemon ===");
    let _ = daemon_proc.kill();
    let _ = daemon_proc.wait();

    let sa_ok = socket_activation_test(&daemon)?;
    let ns_ok = namespace_isolation_test(&daemon)?;
    std::fs::remove_file("/usr/local/bin/fstrace-scenario-setuid")?;

    if client_ok && sa_ok && ns_ok {
        Ok(())
    } else {
        bail!(
            "guest tests failed (client_ok={client_ok}, socket_activation_ok={sa_ok}, \
             namespace_isolation_ok={ns_ok})"
        );
    }
}
