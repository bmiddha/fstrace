//! The unprivileged client test suite, run as `fstuser` inside the guest.
//!
//! Mirrors the original `guest-tests.sh` client body: for each scenario it
//! rebuilds the test directory *untraced*, runs the scenario under `fstrace`
//! with reports captured from fd 3, and compares against the expected stream.
//! Also covers passthrough (exit code / signal / env), concurrent clients, and
//! per-process log files.

use std::{
    io,
    os::unix::{
        fs::symlink,
        io::{AsRawFd, RawFd},
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result};

const TESTDIR: &str = "/tmp/fstrace-test-dir";

fn fstrace_bin() -> String {
    std::env::var("FSTRACE").unwrap_or_else(|_| "/usr/local/bin/fstrace".into())
}

/// Path to the thin `fstrace-scenario` binary that `fstrace` traces.
fn scenario_bin() -> String {
    std::env::var("FSTRACE_SCENARIO").unwrap_or_else(|_| "/usr/local/bin/fstrace-scenario".into())
}

/// A POSIX shell that reliably exists: `bash` on Debian/Ubuntu, or BusyBox `sh`
/// (ash) on Alpine. Keeps the passthrough tests portable across userspaces.
fn shell() -> &'static str {
    static SH: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    SH.get_or_init(|| {
        let found = Command::new("sh")
            .args(["-c", "command -v bash"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if found { "bash" } else { "sh" }
    })
}

fn unique_tmp(prefix: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// Runs `fstrace <program> <args...>` with fd 3 redirected to a temp file,
/// returning `(fd3_reports, exit_status)`. `stdout_to` controls the child's
/// Runs `fstrace <program> <args...>` with fd 3 redirected to a temp file.
/// Returns the captured fd-3 reports, the exit status, stdout, and stderr.
fn run_traced(
    program: &[String],
    extra_env: &[(&str, &str)],
) -> Result<(String, std::process::ExitStatus, Vec<u8>, String)> {
    let (prog, args) = program.split_first().expect("program is non-empty");
    let fd3_path = unique_tmp("fstrace-fd3");
    let fd3_file = std::fs::File::create(&fd3_path)?;
    let raw = fd3_file.as_raw_fd();

    let mut cmd = Command::new(fstrace_bin());
    cmd.arg(prog).args(args);
    cmd.stdin(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    // Redirect the child's report descriptor (fd 3) onto our capture file.
    unsafe {
        cmd.pre_exec(move || redirect_fd3(raw));
    }
    // `output()` captures stdout+stderr; fd 3 still flows to our temp file.
    let out = cmd
        .output()
        .with_context(|| format!("spawning fstrace {prog}"))?;
    drop(fd3_file);
    let reports = std::fs::read_to_string(&fd3_path).unwrap_or_default();
    let _ = std::fs::remove_file(&fd3_path);
    Ok((
        trim_trailing_newlines(&reports),
        out.status,
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Points fd 3 (the report descriptor) at `raw` and clears its close-on-exec
/// flag so it survives the exec into `fstrace`. Async-signal-safe: only raw
/// libc calls. Must handle `raw == 3`, where `dup2` is a no-op that would
/// otherwise leave `O_CLOEXEC` set and close fd 3 at exec.
fn redirect_fd3(raw: RawFd) -> io::Result<()> {
    unsafe {
        if raw != 3 && libc::dup2(raw, 3) < 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = libc::fcntl(3, libc::F_GETFD);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn trim_trailing_newlines(s: &str) -> String {
    s.trim_end_matches('\n').to_string()
}

fn rm_rf(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
    let _ = std::fs::remove_file(path);
}

fn setup_testdir() -> Result<()> {
    let base = Path::new(TESTDIR);
    rm_rf(base);
    std::fs::create_dir_all(base)?;
    for i in 0..15 {
        std::fs::create_dir_all(base.join(format!("dir{i}")))?;
        std::fs::File::create(base.join(format!("file{i}")))?;
        symlink(
            base.join(format!("file{i}")),
            base.join(format!("file{i}.link")),
        )?;
        symlink(
            base.join(format!("dir{i}")),
            base.join(format!("dir{i}.link")),
        )?;
    }
    Ok(())
}

/// Tracks pass/fail counts and prints per-check verdicts.
struct Tally {
    pass: u32,
    fail: u32,
}

impl Tally {
    fn new() -> Self {
        Self { pass: 0, fail: 0 }
    }

    fn pass(&mut self, name: &str) {
        println!("PASS  {name}");
        self.pass += 1;
    }

    fn fail(&mut self, name: &str) {
        println!("FAIL  {name}");
        self.fail += 1;
    }

    /// Runs a scenario and asserts its fd-3 output matches `expected` exactly.
    fn check(&mut self, name: &str, expected: &str) -> Result<()> {
        setup_testdir()?;
        let mut program = vec![scenario_bin()];
        program.push(name.to_string());
        let (actual, status, _, stderr) = run_traced(&program, &[])?;
        if status.success() && actual == expected {
            self.pass(name);
        } else {
            self.fail(name);
            println!("----- expected -----\n{expected}");
            println!("----- actual -------\n{actual}");
            println!("----- stderr -------\n{stderr}");
            println!("--------------------");
        }
        Ok(())
    }

    /// Runs a scenario and asserts each `line` appears exactly once (order
    /// independent) — used for multi-process scenarios.
    fn check_counts(&mut self, name: &str, lines: &[&str]) -> Result<()> {
        setup_testdir()?;
        let mut program = vec![scenario_bin()];
        program.push(name.to_string());
        let (actual, status, _, stderr) = run_traced(&program, &[])?;
        let mut ok = status.success();
        for line in lines {
            let n = actual.lines().filter(|l| l == line).count();
            if n != 1 {
                ok = false;
                println!("  missing/dup ({n}): {line}");
            }
        }
        if ok {
            self.pass(name);
        } else {
            self.fail(name);
            println!(
                "----- actual -------\n{actual}\n----- stderr -------\n{stderr}\n--------------------"
            );
        }
        Ok(())
    }
}

fn smoke(t: &mut Tally) -> Result<()> {
    setup_testdir()?;
    let program = vec!["cat".to_string(), format!("{TESTDIR}/file0")];
    let (actual, _, _, stderr) = run_traced(&program, &[])?;
    if actual.contains(&format!("RF {TESTDIR}/file0")) {
        t.pass("smoke (loader attaches and emits events)");
    } else {
        t.fail("smoke — tracer produced no events; eBPF likely failed to load");
        println!("----- actual -------\n{actual}\n----- stderr -------\n{stderr}");
    }
    Ok(())
}

fn exec_path_test(t: &mut Tally, name: &str, via: Option<&str>) -> Result<()> {
    setup_testdir()?;
    let target = Path::new(TESTDIR).join("exec-target");
    std::fs::copy(scenario_bin(), &target)?;
    let target = target.to_string_lossy().into_owned();
    let program = if let Some(scenario) = via {
        vec![scenario_bin(), scenario.into(), target.clone()]
    } else {
        vec![target.clone(), "stat".into()]
    };
    let (actual, status, _, stderr) = run_traced(&program, &[])?;
    let expected = format!("RF {target}");
    let exact = actual.lines().filter(|line| *line == expected).count();
    let cwd_substitution = format!("RF {TESTDIR}/");
    if status.success() && exact == 1 && !actual.lines().any(|line| line == cwd_substitution) {
        t.pass(name);
    } else {
        t.fail(name);
        println!(
            "  expected exactly once: {expected}\n----- actual -------\n{actual}\n----- stderr -------\n{stderr}\n--------------------"
        );
    }
    Ok(())
}

fn pathmax_test(t: &mut Tally) -> Result<()> {
    let base = Path::new(TESTDIR);
    rm_rf(base);
    std::fs::create_dir_all(base)?;
    let comp = "a".repeat(250); // 250-char component (< NAME_MAX 255)
    let mut longdir = base.to_path_buf();
    for _ in 0..16 {
        // 21 + 16*251 = 4037-byte directory
        longdir.push(&comp);
        std::fs::create_dir(&longdir)?;
    }
    let longabs = longdir.join("A".repeat(55)); // ~4093-byte file (near PATH_MAX)
    std::fs::File::create(longdir.join("B"))?; // sibling read from the deep cwd
    let longabs = longabs.to_string_lossy().into_owned();
    let longdir = longdir.to_string_lossy().into_owned();
    println!(
        "  (deep dir length: {}, file length: {})",
        longdir.len(),
        longabs.len()
    );

    let expected = format!("WF {longabs}\nRF {longabs}\nRF {longdir}/B");
    let mut program = vec![scenario_bin()];
    program.extend([
        "pathmax".into(),
        longabs.clone(),
        longdir.clone(),
        "B".into(),
    ]);
    let (actual, _, _, stderr) = run_traced(&program, &[])?;
    if actual == expected {
        t.pass("pathmax (near-PATH_MAX pathnames)");
    } else {
        t.fail("pathmax");
        println!("----- expected -----\n{expected}");
        println!("----- actual -------\n{actual}");
        println!("----- stderr -------\n{stderr}");
        println!("--------------------");
    }
    Ok(())
}

fn passthrough_tests(t: &mut Tally) -> Result<()> {
    println!("=== passthrough tests ===");

    // exit-code passthrough
    let program = vec![shell().into(), "-c".into(), "exit 100".into()];
    let (_, status, _, stderr) = run_traced(&program, &[])?;
    if status.code() == Some(100) {
        t.pass("exit-code passthrough");
    } else {
        t.fail(&format!(
            "exit-code passthrough (got {:?}); stderr: {stderr}",
            status.code()
        ));
    }

    // signal passthrough: SIGTERM -> 143, SIGKILL -> 137
    for (sig, expect) in [(libc::SIGTERM, 143), (libc::SIGKILL, 137)] {
        signal_test(t, sig, expect)?;
    }

    // env passthrough: the child must see an unmodified environment.
    let program = vec![shell().into(), "-c".into(), "env".into()];
    let (_, _, traced_stdout, _) = run_traced(&program, &[])?;
    let plain = Command::new(shell()).args(["-c", "env"]).output()?.stdout;
    let mut a: Vec<&[u8]> = traced_stdout.split(|&b| b == b'\n').collect();
    let mut b: Vec<&[u8]> = plain.split(|&b| b == b'\n').collect();
    a.sort();
    b.sort();
    if a == b {
        t.pass("env passthrough");
    } else {
        t.fail("env passthrough");
    }
    Ok(())
}

fn signal_test(t: &mut Tally, sig: i32, expect: i32) -> Result<()> {
    let name = format!("signal passthrough ({sig})");
    let mut cmd = Command::new(fstrace_bin());
    cmd.args([shell(), "-c", "sleep 10"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // fd 3 -> /dev/null so the report sink opens cleanly.
    let devnull = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    let raw = devnull.as_raw_fd();
    unsafe {
        cmd.pre_exec(move || redirect_fd3(raw));
    }
    let mut child = cmd.spawn()?;
    drop(devnull);
    std::thread::sleep(std::time::Duration::from_secs(1));
    unsafe {
        libc::kill(child.id() as i32, sig);
    }
    let status = child.wait()?;
    let code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(-1);
    if code == expect {
        t.pass(&name);
    } else {
        t.fail(&format!("{name}: expected {expect} got {code}"));
    }
    Ok(())
}

fn concurrency_test(t: &mut Tally) -> Result<()> {
    println!("=== concurrency test ===");
    setup_testdir()?;

    // Two clients tracing distinct files at once; verify no cross-talk.
    fn spawn(file: &str) -> Result<(Child, PathBuf, std::fs::File)> {
        let fd3_path = unique_tmp("fstrace-conc");
        let fd3_file = std::fs::File::create(&fd3_path)?;
        let raw = fd3_file.as_raw_fd();
        let mut cmd = Command::new(fstrace_bin());
        cmd.args(["cat", file]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(move || redirect_fd3(raw));
        }
        let child = cmd.spawn()?;
        Ok((child, fd3_path, fd3_file))
    }

    let (mut c1, p1, f1) = spawn(&format!("{TESTDIR}/file0"))?;
    let (mut c2, p2, f2) = spawn(&format!("{TESTDIR}/file1"))?;
    c1.wait()?;
    c2.wait()?;
    drop(f1);
    drop(f2);
    let a = std::fs::read_to_string(&p1).unwrap_or_default();
    let b = std::fs::read_to_string(&p2).unwrap_or_default();
    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);

    let mut ok = true;
    if !a.contains(&format!("RF {TESTDIR}/file0")) {
        ok = false;
        println!("  client1 missing its own file0");
    }
    if !b.contains(&format!("RF {TESTDIR}/file1")) {
        ok = false;
        println!("  client2 missing its own file1");
    }
    if a.contains("file1") {
        ok = false;
        println!("  client1 leaked client2's file1");
    }
    if b.contains("file0") {
        ok = false;
        println!("  client2 leaked client1's file0");
    }
    if ok {
        t.pass("multi-client isolation");
    } else {
        t.fail("multi-client isolation");
        println!("-- client1 --\n{a}\n-- client2 --\n{b}");
    }
    Ok(())
}

fn logging_test(t: &mut Tally) -> Result<()> {
    println!("=== logging test ===");
    setup_testdir()?;
    let logdir = unique_tmp("fstrace-logs");
    std::fs::create_dir_all(&logdir)?;
    let program = vec!["cat".into(), format!("{TESTDIR}/file0")];
    let logdir_str = logdir.to_string_lossy().into_owned();
    run_traced(
        &program,
        &[
            ("RUST_LOG", "fstrace=trace"),
            ("FSTRACE_LOG_DIR", &logdir_str),
        ],
    )?;

    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(&logdir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("fstrace-") && name.ends_with(".log") {
                let content = std::fs::read_to_string(e.path()).unwrap_or_default();
                if content.contains("TRACE fstrace") {
                    found = true;
                    break;
                }
            }
        }
    }
    if found {
        t.pass("logging (FSTRACE_LOG_DIR per-process file)");
    } else {
        t.fail("logging — no per-process trace log produced");
    }
    rm_rf(&logdir);
    Ok(())
}

/// Runs the full unprivileged client suite; returns `Ok(())` iff all pass.
pub fn registration_rejections(socket: &str) -> Result<bool> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    let mut ok = true;
    for pid in [0, std::process::id(), u32::MAX] {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        let mut challenge = [0; 24];
        stream.read_exact(&mut challenge)?;
        anyhow::ensure!(
            &challenge[..8] == b"FSTRACE2",
            "unexpected authentication protocol"
        );
        stream.write_all(&pid.to_le_bytes())?;
        let mut reply = [0];
        stream.read_exact(&mut reply)?;
        ok &= reply[0] == 0x15;
    }
    Ok(ok)
}

fn lifecycle_and_report_failures(t: &mut Tally) -> Result<()> {
    for (name, expected) in [
        (
            "inherited-paths",
            format!("RD {TESTDIR}/dir0\nRF {TESTDIR}/file0\nRF {TESTDIR}/file1"),
        ),
        ("leader-exit", format!("WF {TESTDIR}/leader-worker")),
        (
            "failed-thread-exec",
            format!("WF {TESTDIR}/after-thread-churn"),
        ),
    ] {
        t.check(name, &expected)?;
    }
    let socket =
        std::env::var("FSTRACE_SOCKET").unwrap_or_else(|_| "/run/fstrace/fstrace.sock".into());
    if registration_rejections(&socket)? {
        t.pass("unauthorized registration rejects arbitrary or unproven PIDs");
    } else {
        t.fail("unauthorized registration rejects arbitrary or unproven PIDs");
    }
    let setuid = "/usr/local/bin/fstrace-scenario-setuid";
    let baseline = Command::new(setuid).arg("privileges").output()?;
    let baseline = String::from_utf8_lossy(&baseline.stdout);
    let (_, status, stdout, stderr) = run_traced(&[setuid.into(), "privileges".into()], &[])?;
    let actual = String::from_utf8_lossy(&stdout);
    let fields: Vec<_> = actual.split_whitespace().collect();
    if baseline.split_whitespace().nth(1) == Some("0")
        && status.success()
        && fields.len() == 3
        && fields[0] == fields[1]
        && fields[0] != "0"
        && fields[2] == "1"
    {
        t.pass("setuid cannot elevate a traced command");
    } else {
        t.fail("setuid cannot elevate a traced command");
        println!("untraced={baseline:?}; traced={actual:?}; {stderr}");
    }
    for mode in [
        "valid-kernel-registration",
        "wrong-token",
        "missing-nnp",
        "exec-before-registration",
    ] {
        if registration_attack(&socket, mode)? {
            t.pass(mode);
        } else {
            t.fail(mode);
        }
    }

    let (_, status, _, stderr) = run_traced(
        &[scenario_bin(), "open".into()],
        &[("FSTRACE_REPORT_FILE", "/dev/full")],
    )?;
    if !status.success() && stderr.contains("writing access reports") {
        t.pass("report ENOSPC fails the trace");
    } else {
        t.fail("report ENOSPC fails the trace");
        println!("{stderr}");
    }
    let read_only = std::fs::File::open("/dev/null")?;
    let fd = read_only.as_raw_fd();
    let mut command = Command::new(fstrace_bin());
    command.arg("/bin/true").env_remove("FSTRACE_REPORT_FILE");
    unsafe {
        command.pre_exec(move || redirect_fd3(fd));
    }
    let output = command.output()?;
    if !output.status.success() && String::from_utf8_lossy(&output.stderr).contains("read-only") {
        t.pass("read-only report FD rejected before launch");
    } else {
        t.fail("read-only report FD rejected before launch");
    }
    Ok(())
}

fn registration_attack(socket: &str, mode: &str) -> Result<bool> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut challenge = [0; 24];
    stream.read_exact(&mut challenge)?;
    let token = [
        u64::from_le_bytes(challenge[8..16].try_into()?),
        u64::from_le_bytes(challenge[16..24].try_into()?),
    ];
    unsafe {
        libc::prctl(0x46535452, token[0], token[1], 0u64, 0u64);
    }
    let mut spawned = None;
    let child = if mode == "exec-before-registration" {
        // This exec really elevates via the fixture; even its later no-new-privs
        // acknowledgement must not authorize the now-different credentials.
        let process = Command::new("/usr/local/bin/fstrace-scenario-setuid")
            .args([
                "register-after-exec",
                &token[0].to_string(),
                &token[1].to_string(),
            ])
            .spawn()?;
        let pid = process.id() as i32;
        spawned = Some(process);
        pid
    } else {
        let child = unsafe { libc::fork() };
        anyhow::ensure!(child >= 0, "authentication fixture fork failed");
        if child == 0 {
            unsafe {
                if mode != "missing-nnp" {
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                }
                libc::prctl(
                    0x46535452,
                    token[0] ^ u64::from(mode == "wrong-token"),
                    token[1],
                    0u64,
                    0u64,
                );
                libc::raise(libc::SIGSTOP);
                libc::_exit(0);
            }
        }
        child
    };
    let mut status = 0;
    let waited = unsafe { libc::waitpid(child, &mut status, libc::WUNTRACED) };
    let result = (|| -> Result<bool> {
        anyhow::ensure!(
            waited == child && libc::WIFSTOPPED(status),
            "authentication child did not stop"
        );
        stream.write_all(&0u32.to_le_bytes())?;
        let mut reply = [0];
        stream.read_exact(&mut reply)?;
        if mode == "valid-kernel-registration" {
            let mut root = [0; 4];
            stream.read_exact(&mut root)?;
            Ok(reply[0] == 0x06 && u32::from_le_bytes(root) == child as u32)
        } else {
            Ok(reply[0] == 0x15)
        }
    })();
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, &mut status, 0);
    }
    drop(spawned);
    result
}

pub fn retained_peer_cancellation(socket: &str, daemon: u32) -> Result<()> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };
    let resources = || -> Result<(usize, usize)> {
        Ok((
            std::fs::read_dir(format!("/proc/{daemon}/task"))?.count(),
            std::fs::read_dir(format!("/proc/{daemon}/fd"))?.count(),
        ))
    };
    std::thread::sleep(Duration::from_millis(250));
    let baseline = resources()?;
    let mut peers = Vec::new();
    let mut path = format!("{TESTDIR}/missing/{}", "aaaaaaaaa/".repeat(450));
    path.truncate(4090);
    let path = std::ffi::CString::new(path)?;
    for _ in 0..4 {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(35)))?;
        let mut challenge = [0; 24];
        stream.read_exact(&mut challenge)?;
        let token = [
            u64::from_le_bytes(challenge[8..16].try_into()?),
            u64::from_le_bytes(challenge[16..24].try_into()?),
        ];
        unsafe {
            libc::prctl(0x46535452, token[0], token[1], 0u64, 0u64);
        }
        let child = unsafe { libc::fork() };
        anyhow::ensure!(child >= 0, "cancellation fork");
        if child == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                libc::prctl(0x46535452, token[0], token[1], 0u64, 0u64);
                libc::raise(libc::SIGSTOP);
                for _ in 0..20000 {
                    let fd = libc::syscall(
                        libc::SYS_openat,
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        libc::O_RDONLY,
                    );
                    if fd >= 0 {
                        libc::close(fd as i32);
                    }
                }
                libc::raise(libc::SIGSTOP);
                libc::_exit(0);
            }
        }
        let result = (|| -> Result<()> {
            let mut status = 0;
            anyhow::ensure!(
                unsafe { libc::waitpid(child, &mut status, libc::WUNTRACED) } == child
                    && libc::WIFSTOPPED(status),
                "cancellation child initial stop"
            );
            stream.write_all(&0u32.to_le_bytes())?;
            let mut ack = [0; 5];
            stream.read_exact(&mut ack)?;
            anyhow::ensure!(ack[0] == 6, "cancellation child unauthorized");
            unsafe {
                libc::kill(child, libc::SIGCONT);
            }
            // Leave the writer blocked long enough to fill the bounded router queue.
            std::thread::sleep(Duration::from_secs(2));
            loop {
                let mut header = [0; 76];
                stream.read_exact(&mut header)?;
                let len = u32::from_le_bytes(header[36..40].try_into()?) as usize
                    + u32::from_le_bytes(header[40..44].try_into()?) as usize;
                anyhow::ensure!(len <= 8192, "bad cancellation frame");
                stream.read_exact(&mut vec![0; len])?;
                if u32::from_le_bytes(header[32..36].try_into()?) == 0xffff0004 {
                    anyhow::ensure!(
                        i64::from_le_bytes(header[44..52].try_into()?) != 0,
                        "pressure produced successful completion"
                    );
                    break;
                }
            }
            // No FINISH and no close from the peer.
            let start = Instant::now();
            while resources()? != baseline && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(25));
            }
            anyhow::ensure!(
                resources()? == baseline,
                "cancelled handler retained resources"
            );
            Ok(())
        })();
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        result?;
        peers.push(stream);
    }
    println!("PASS: retained peers after pressure cancellation release handler threads and FDs");
    Ok(())
}

fn pressure_test(t: &mut Tally) -> Result<()> {
    use std::{
        io::Read,
        os::fd::FromRawFd,
        time::{Duration, Instant},
    };
    let mut pipe = [-1; 2];
    anyhow::ensure!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
        "creating blocked report pipe"
    );
    let _reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
    let writer = unsafe { std::fs::File::from_raw_fd(pipe[1]) };
    let raw = writer.as_raw_fd();
    let mut command = Command::new(fstrace_bin());
    command
        .args([scenario_bin(), "pressure".into()])
        .env("FSTRACE_DEBOUNCE", "0")
        .env_remove("FSTRACE_REPORT_FILE")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || redirect_fd3(raw));
    }
    let mut child = command.spawn()?;
    let start = Instant::now();
    let mut peak_kib = 0u64;
    let status = loop {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", child.id()))
            && let Some(value) = status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| line.split_whitespace().nth(1))
        {
            peak_kib = peak_kib.max(value.parse()?);
        }
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() > Duration::from_secs(40) {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .context("capturing pressure-test stderr")?
        .read_to_string(&mut stderr)?;
    if status.is_some_and(|status| !status.success())
        && peak_kib > 0
        && peak_kib < 64 * 1024
        && stderr.contains("report destination remained blocked")
    {
        t.pass("blocked reports fail within deadline with client RSS below 64 MiB");
        println!(
            "  peak client RSS: {peak_kib} KiB; elapsed: {:.1}s",
            start.elapsed().as_secs_f64()
        );
    } else {
        t.fail("blocked reports fail within deadline with client RSS below 64 MiB");
        println!("  status={status:?}, peak={peak_kib} KiB; {stderr}");
    }
    setup_testdir()?;
    let (report, status, _, error) = run_traced(&[scenario_bin(), "leader-exit".into()], &[])?;
    if status.success() && report == format!("WF {TESTDIR}/leader-worker") {
        t.pass("daemon remains usable after queue-pressure cancellation");
    } else {
        t.fail("daemon remains usable after queue-pressure cancellation");
        println!("{report}\n{error}");
    }
    Ok(())
}

pub fn run() -> Result<()> {
    // Scope reports to the test directory so loader/libc noise is excluded.
    unsafe {
        std::env::set_var("FSTRACE_FILTER_PREFIX", TESTDIR);
    }

    let mut t = Tally::new();
    println!("=== fstrace eBPF end-to-end tests ===");
    if let Ok(v) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        print!("{v}");
    }

    smoke(&mut t)?;
    lifecycle_and_report_failures(&mut t)?;
    review_regressions(&mut t)?;
    exec_path_test(&mut t, "execve path survives successful exec", None)?;
    exec_path_test(
        &mut t,
        "execveat path survives successful exec",
        Some("execveat"),
    )?;
    exec_path_test(
        &mut t,
        "execveat preserves relative directory fd across exec",
        Some("execveat-relative"),
    )?;
    exec_path_test(
        &mut t,
        "thread exec path survives de_thread",
        Some("thread-exec"),
    )?;

    t.check("creat", &fmt(&["WF {D}/newfile0", "WF {D}/newfile1"]))?;
    t.check(
        "open",
        &fmt(&[
            "WF {D}/newfile2",
            "WF {D}/newfile3",
            "RF {D}/file0",
            "RF {D}/file2",
            "WF {D}/file1",
        ]),
    )?;
    t.check(
        "openat",
        &fmt(&[
            "RD {D}",
            "RF {D}/file0",
            "WF {D}/file0",
            "WX {D}/does-not-exist",
            "WX {D}/does-not-exist",
            "RX {D}/does-not-exist",
            "WX {D}/does-not-exist",
            "RD {D}/dir0/",
            "WD {D}/dir0/",
            "RD {D}/dir0/",
            "WD {D}/dir0",
            "WD {D}/dir0",
        ]),
    )?;
    t.check(
        "openat2",
        &fmt(&[
            "RD {D}",
            "RF {D}/file0",
            "WF {D}/file0",
            "WX {D}/does-not-exist",
            "RX {D}/does-not-exist",
            "WX {D}/does-not-exist",
            "RD {D}/dir0/",
            "WD {D}/dir0/",
            "RD {D}/dir0/",
            "WD {D}/dir0",
            "RD {D}/dir0",
        ]),
    )?;
    // Metadata-only syscall families are intentionally not attached. Keep
    // scenarios for them so the suite guards against accidentally re-enabling
    // their high-volume reports.
    t.check("stat", "")?;
    t.check("getdents", &fmt(&["RD {D}", "RF {D}/file0"]))?;
    t.check("readlink", "")?;
    t.check(
        "unlink",
        &fmt(&[
            "RD {D}",
            "DX {D}/file0",
            "DX {D}/file1",
            "DX {D}/file2",
            "DX {D}/file3",
            "DX {D}/file4",
            "DX {D}/file5",
        ]),
    )?;
    t.check(
        "rmdir",
        &fmt(&["DX {D}/dir0/", "DX {D}/dir1", "DX {D}/dir2/", "DX {D}/dir3"]),
    )?;
    t.check(
        "rename",
        &fmt(&[
            "RD {D}",
            "DX {D}/file0",
            "W? {D}/newfile0",
            "DX {D}/file1",
            "W? {D}/newfile1",
            "DX {D}/file2",
            "W? {D}/newfile2",
            "DX {D}/file3",
            "W? {D}/newfile3",
            "DX {D}/file4",
            "W? {D}/newfile4",
            "DX {D}/file5",
            "W? {D}/newfile5",
        ]),
    )?;
    t.check(
        "mkdir",
        &fmt(&[
            "RD {D}",
            "WD {D}/newdir0",
            "WD {D}/newdir1/",
            "WD {D}/newdir2",
            "WD {D}/newdir3",
            "WD {D}/newdir4/",
            "WD {D}/newdir5",
            "WD {D}/newdir6",
            "WD {D}/newdir7/",
            "WD {D}/newdir8",
        ]),
    )?;
    t.check(
        "symlink",
        &fmt(&[
            "RD {D}",
            "WL {D}/newlink0",
            "WL {D}/newlink1",
            "WL {D}/newlink2",
            "WL {D}/newlink3",
            "WL {D}/newlink4",
            "WL {D}/newlink5",
            "WL {D}/newlink6",
        ]),
    )?;
    t.check(
        "link",
        &fmt(&[
            "RD {D}",
            "WF {D}/newfile0",
            "WF {D}/newfile1",
            "WF {D}/newfile2",
            "WF {D}/newfile3",
            "WF {D}/newfile4",
            "WF {D}/newfile5",
            "WF {D}/newfile6",
            "WF {D}/newfile7",
        ]),
    )?;
    t.check("truncate", &fmt(&["WF {D}/file0", "WF {D}/file1"]))?;

    t.check_counts(
        "fork",
        &[
            &format!("WF {TESTDIR}/file0"),
            &format!("WF {TESTDIR}/file1"),
            &format!("WF {TESTDIR}/file2"),
        ],
    )?;

    pathmax_test(&mut t)?;
    passthrough_tests(&mut t)?;
    concurrency_test(&mut t)?;
    logging_test(&mut t)?;
    pressure_test(&mut t)?;

    println!("=== results: {} passed, {} failed ===", t.pass, t.fail);
    if t.fail == 0 {
        Ok(())
    } else {
        anyhow::bail!("{} client test(s) failed", t.fail)
    }
}

fn review_regressions(t: &mut Tally) -> Result<()> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    t.check(
        "empty-shared-files",
        &fmt(&["RD {D}/dir0", "RD {D}/dir1", "WF {D}/dir1/shared-file"]),
    )?;
    for mode in ["exec", "failed", "fork"] {
        setup_testdir()?;
        let (reports, status, _, error) =
            run_traced(&[scenario_bin(), "clone-fs".into(), mode.into()], &[])?;
        let expected = if mode == "fork" {
            format!("WF {TESTDIR}/cwd-file")
        } else {
            format!("WF {TESTDIR}/dir0/cwd-file")
        };
        if status.success() && reports == expected {
            t.pass(&format!("CLONE_FS cwd across {mode}"));
        } else {
            t.fail(&format!("CLONE_FS cwd across {mode}"));
            println!("{reports}\n{error}");
        }
    }
    setup_testdir()?;
    for profile in ["0", "1"] {
        let (reports, status, _, error) = run_traced(
            &[scenario_bin(), "dup-dirfd".into()],
            &[("FSTRACE_PROFILE", profile)],
        )?;
        if !status.success() && error.contains("trace incomplete") && !reports.contains("/file0") {
            t.pass(&format!(
                "uncaptured duplicated dirfd fails (profile={profile})"
            ));
        } else {
            t.fail("uncaptured duplicated dirfd fails");
            println!("{reports}\n{error}");
        }
    }
    let (_, status, _, error) = run_traced(
        &[shell().into(), "-c".into(), "kill -PIPE $$; exit 77".into()],
        &[],
    )?;
    if status.code() == Some(141) {
        t.pass("target receives default SIGPIPE");
    } else {
        t.fail("target receives default SIGPIPE");
        println!("{status}\n{error}");
    }

    let executable = unique_tmp("raw-executable")
        .with_file_name(OsString::from_vec(b"fstrace-executable-\xff".to_vec()));
    symlink(scenario_bin(), &executable)?;
    let capture = unique_tmp("raw-argv-report");
    let file = std::fs::File::create(&capture)?;
    let raw = file.as_raw_fd();
    let mut command = Command::new(fstrace_bin());
    command
        .arg(&executable)
        .arg("raw-argv")
        .arg(OsString::from_vec(vec![0xff]));
    unsafe {
        command.pre_exec(move || redirect_fd3(raw));
    }
    let output = command.output()?;
    if output.status.success() && output.stdout == [0xff] {
        t.pass("non-UTF8 executable name and argv survive CLI exec");
    } else {
        t.fail("non-UTF8 executable name and argv survive CLI exec");
        println!("{}", String::from_utf8_lossy(&output.stderr));
    }
    std::fs::remove_file(executable)?;
    std::fs::remove_file(capture)?;
    let capture = unique_tmp("early-consumer");
    let file = std::fs::File::create(&capture)?;
    let fd = file.as_raw_fd();
    let mut command = Command::new(fstrace_bin());
    command
        .arg("yes")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || redirect_fd3(fd));
    }
    let mut writer = command.spawn()?;
    drop(writer.stdout.take());
    let output = writer.wait_with_output()?;
    if output.status.code() == Some(141) {
        t.pass("early stdout consumer close gives target SIGPIPE");
    } else {
        t.fail("early stdout consumer close gives target SIGPIPE");
        println!("{}", String::from_utf8_lossy(&output.stderr));
    }
    std::fs::remove_file(capture)?;
    Ok(())
}

/// Expands `{D}` to the test directory in each line and joins with newlines.
fn fmt(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|l| l.replace("{D}", TESTDIR))
        .collect::<Vec<_>>()
        .join("\n")
}
