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
        let (actual, _, _, stderr) = run_traced(&program, &[])?;
        if actual == expected {
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
        let (actual, _, _, stderr) = run_traced(&program, &[])?;
        let mut ok = true;
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

    let expected = format!("WF {longabs}\nRF {longabs}\nR? {longabs}\nRF {longdir}/B");
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
    t.check("stat", &fmt(&["R? {D}/file0", "RX {D}/does-not-exist"]))?;
    t.check(
        "getdents",
        &fmt(&["RD {D}", "ED {D}", "RF {D}/file0", "EX {D}/file0"]),
    )?;
    t.check(
        "readlink",
        &fmt(&[
            "RL {D}/file0.link",
            "RX {D}/does-not-exist.link",
            "RL {D}/dir0.link",
        ]),
    )?;
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

    println!("=== results: {} passed, {} failed ===", t.pass, t.fail);
    if t.fail == 0 {
        Ok(())
    } else {
        anyhow::bail!("{} client test(s) failed", t.fail)
    }
}

/// Expands `{D}` to the test directory in each line and joins with newlines.
fn fmt(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|l| l.replace("{D}", TESTDIR))
        .collect::<Vec<_>>()
        .join("\n")
}
