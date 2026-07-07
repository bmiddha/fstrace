//! QEMU direct-kernel-boot end-to-end harness for fstrace.
//!
//! Rather than booting a distro cloud image (whose kernel we cannot choose),
//! this harness pins the **kernel** and the **userspace** independently:
//!
//! - the **kernel** is a *prebuilt* upstream `bzImage` fetched by the
//!   [`crate::kernel`] module from the Ubuntu mainline archive (which publishes
//!   a BTF-enabled image for every upstream tag — LTS, stable, and mainline
//!   release candidates alike);
//! - the **userspace** is an initramfs built by the [`crate::initramfs`] module
//!   from a Docker image rootfs plus the host-built static-musl fstrace
//!   binaries and an `/init` that runs the privileged guest suite.
//!
//! QEMU then direct-kernel-boots the pair (`-kernel` + `-initrd`), and the host
//! scrapes the serial console for the `FSTRACE_VM_RESULT:<code>` sentinel. The
//! host never loads the eBPF programs, so a buggy program cannot affect it.
//!
//! Requirements on the host: `qemu-system-x86_64`, `docker`, `cpio`, `curl`,
//! `sudo`, and (optionally) `/dev/kvm` for acceleration.

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

use crate::{initramfs, kernel};

/// A pinned upstream kernel to boot and run the privileged suite against. Each
/// entry maps to a prebuilt image in the Ubuntu mainline archive.
pub struct Release {
    /// Short selector passed to `--release` (usually the `MAJOR.MINOR` series).
    pub name: &'static str,
    /// Exact upstream tag to download, e.g. `6.12.95` or `7.2-rc2`.
    pub version: &'static str,
    /// Support tier for the chart: `LTS`, `stable`, or `mainline`.
    pub moniker: &'static str,
}

/// The kernel matrix: every active upstream **longterm** series, plus the
/// current **stable** and **mainline** lines released since the newest LTS.
/// Keep in sync with `docs/kernel-support.md` and `.github/workflows/ci.yml`.
pub const RELEASES: &[Release] = &[
    Release {
        name: "5.10",
        version: "5.10.260",
        moniker: "LTS",
    },
    Release {
        name: "5.15",
        version: "5.15.211",
        moniker: "LTS",
    },
    Release {
        name: "6.1",
        version: "6.1.177",
        moniker: "LTS",
    },
    Release {
        name: "6.6",
        version: "6.6.144",
        moniker: "LTS",
    },
    Release {
        name: "6.12",
        version: "6.12.95",
        moniker: "LTS",
    },
    Release {
        name: "6.18",
        version: "6.18.38",
        moniker: "LTS",
    },
    Release {
        name: "7.1",
        version: "7.1.3",
        moniker: "stable",
    },
    Release {
        name: "7.2-rc",
        version: "7.2-rc2",
        moniker: "mainline",
    },
];

/// The Docker image supplying the guest userspace. Universal across kernels
/// (only the kernel is the variable under test); override with `FSTRACE_VM_IMAGE`.
const DEFAULT_IMAGE: &str = "docker.io/library/ubuntu:latest";

/// In-guest binaries are built static against musl so they run on any rootfs.
const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";

/// How long to wait for the guest to reach the result sentinel under KVM.
const BOOT_TIMEOUT: Duration = Duration::from_secs(240);

/// TCG emulation is far slower than KVM, so allow the software-emulated boot a
/// much larger budget before declaring a timeout.
const TCG_BOOT_TIMEOUT: Duration = Duration::from_secs(900);

/// Looks up a release by its `--release` selector (matches `name` or `version`).
pub fn find_release(name: &str) -> Result<&'static Release> {
    RELEASES
        .iter()
        .find(|r| r.name == name || r.version == name)
        .with_context(|| {
            let names: Vec<&str> = RELEASES.iter().map(|r| r.name).collect();
            format!("unknown release {name:?}; known: {}", names.join(", "))
        })
}

fn log(msg: &str) {
    println!("\x1b[1;34m[vm]\x1b[0m {msg}");
}

/// Cleans up the QEMU process on drop so the VM is always torn down.
struct Harness {
    qemu: Option<Child>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut child) = self.qemu.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn require_tool(bin: &str, hint: &str) -> Result<()> {
    let ok = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        bail!("{bin} not found{hint}")
    }
}

fn run(mut cmd: Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command {cmd:?} failed with {status}");
    }
    Ok(())
}

/// Runs the full VM suite against `release`.
pub fn run_vm_test(root: &Path, release: &Release, _extra_args: &[String]) -> Result<()> {
    require_tool("qemu-system-x86_64", "")?;
    require_tool("docker", "")?;
    require_tool("cpio", "")?;
    log(&format!(
        "release '{}' — kernel {} [{}]",
        release.name, release.version, release.moniker
    ));

    // Build the in-guest binaries as fully static musl so they run on any
    // guest rootfs regardless of its libc. This keeps the *kernel* as the only
    // variable across the support matrix.
    log("building static (musl) binaries + guest driver...");
    let mut add = Command::new("rustup");
    add.args(["target", "add", MUSL_TARGET]);
    let _ = add.status();
    let mut build = Command::new(env!("CARGO"));
    build.current_dir(root).args([
        "build",
        "--release",
        "--target",
        MUSL_TARGET,
        "-p",
        "fstrace",
        "-p",
        "fstrace-vmtest",
    ]);
    run(build)?;

    let release_dir = root.join("target").join(MUSL_TARGET).join("release");
    for bin in [
        "fstrace",
        "fstrace-daemon",
        "fstrace-vmtest",
        "fstrace-scenario",
    ] {
        let p = release_dir.join(bin);
        if !p.is_file() {
            bail!("missing {} — build failed", p.display());
        }
    }

    let cache = root.join("tests/vm/.cache");
    std::fs::create_dir_all(&cache)?;

    // 1. Download the prebuilt kernel image (cached across runs).
    log(&format!("fetching prebuilt kernel {}...", release.version));
    let bzimage = kernel::download_kernel(&cache, release.version, "amd64")?;
    if !bzimage.is_file() {
        bail!("kernel image not found at {}", bzimage.display());
    }

    // 2. Build the initramfs from a Docker image rootfs + our static binaries.
    let image = std::env::var("FSTRACE_VM_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    let initramfs_path = cache.join(format!("initramfs-{}.cpio.gz", release.name));
    log(&format!("building initramfs from {image}..."));
    initramfs::build_initramfs(&image, &initramfs_path, &release_dir)?;

    // 3. Direct-kernel-boot the pair and scrape the console for the sentinel.
    boot_and_check(&bzimage, &initramfs_path)
}

/// Boots QEMU with the kernel + initramfs, streams the serial console, and
/// returns `Ok(())` iff the guest prints `FSTRACE_VM_RESULT:0`.
///
/// Acceleration is negotiated at runtime: `/dev/kvm` merely being present is not
/// a reliable signal (GitHub-hosted runners expose the node but KVM does not
/// actually work), so a KVM boot that dies without emitting a single console
/// line is treated as an acceleration failure and transparently retried under
/// TCG emulation.
fn boot_and_check(bzimage: &Path, initramfs: &Path) -> Result<()> {
    let kvm = Path::new("/dev/kvm")
        .metadata()
        .map(|m| !m.permissions().readonly())
        .unwrap_or(false);

    if kvm {
        log("attempting KVM-accelerated boot...");
        let outcome = run_qemu(bzimage, initramfs, true)?;
        if outcome.result.is_some() {
            return interpret(outcome.result);
        }
        if outcome.produced_console {
            // The VM booted far enough to talk to us but never reported a
            // sentinel — a real guest failure/timeout, not an accel problem.
            return interpret(outcome.result);
        }
        log("KVM boot produced no console output — falling back to TCG emulation");
        if !outcome.stderr.trim().is_empty() {
            log(&format!("  (qemu: {})", outcome.stderr.trim()));
        }
    } else {
        log("KVM unavailable — using slow TCG emulation");
    }

    let outcome = run_qemu(bzimage, initramfs, false)?;
    if outcome.result.is_none() && !outcome.stderr.trim().is_empty() {
        log(&format!("  (qemu: {})", outcome.stderr.trim()));
    }
    interpret(outcome.result)
}

/// Turns a parsed guest exit code into a `Result`.
fn interpret(result: Option<i32>) -> Result<()> {
    match result {
        Some(0) => {
            log("ALL GUEST TESTS PASSED");
            Ok(())
        }
        Some(code) => {
            log(&format!("GUEST TESTS FAILED (exit {code})"));
            bail!("guest test suite failed with exit {code}");
        }
        None => {
            log("no result sentinel — VM timed out or crashed");
            bail!("VM did not report a result before the boot timeout elapsed")
        }
    }
}

/// Outcome of a single QEMU invocation.
struct QemuOutcome {
    /// Parsed `FSTRACE_VM_RESULT:<code>`, if the guest reported one.
    result: Option<i32>,
    /// Whether the guest emitted any serial-console output at all (used to tell
    /// an acceleration failure apart from a genuine in-guest failure).
    produced_console: bool,
    /// Tail of QEMU's own stderr, for diagnostics.
    stderr: String,
}

/// Runs QEMU once with the given acceleration mode and scrapes the console.
fn run_qemu(bzimage: &Path, initramfs: &Path, use_kvm: bool) -> Result<QemuOutcome> {
    let mut qemu = Command::new("qemu-system-x86_64");
    if use_kvm {
        qemu.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        qemu.args(["-cpu", "max"]);
    }
    qemu.args([
        "-m",
        "2048",
        "-smp",
        "2",
        "-no-reboot",
        "-nographic",
        "-display",
        "none",
    ])
    .args(["-monitor", "none"])
    .arg("-kernel")
    .arg(bzimage)
    .arg("-initrd")
    .arg(initramfs)
    .args(["-append", "console=ttyS0 panic=-1 loglevel=4"])
    .args(["-serial", "stdio"])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    log("booting VM (direct kernel boot)...");
    let mut child = qemu.spawn().context("spawning qemu")?;
    let stdout = child.stdout.take().context("capturing qemu stdout")?;
    let qemu_stderr = child.stderr.take().context("capturing qemu stderr")?;
    let mut harness = Harness { qemu: Some(child) };

    // Drain QEMU's own stderr on a worker thread so accel/setup errors surface.
    let stderr_reader = std::thread::spawn(move || {
        let mut r = BufReader::new(qemu_stderr);
        let mut collected = String::new();
        let mut line = String::new();
        while r.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
            collected.push_str(&line);
            line.clear();
        }
        // Keep only the last few lines to avoid noise.
        collected
            .lines()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ")
    });

    // Read the console on a worker thread so we can enforce a wall-clock timeout.
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).trim_end().to_string();
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now()
        + if use_kvm {
            BOOT_TIMEOUT
        } else {
            TCG_BOOT_TIMEOUT
        };
    let mut result: Option<i32> = None;
    let mut produced_console = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining.min(Duration::from_secs(5))) {
            Ok(line) => {
                produced_console = true;
                if line.starts_with("[vm]")
                    || line.starts_with("===")
                    || line.starts_with("PASS")
                    || line.starts_with("FAIL")
                    || line.starts_with("SKIP")
                    || line.contains("FSTRACE_VM_RESULT")
                    || line.contains("panic")
                    || line.contains("Kernel panic")
                {
                    println!("  {line}");
                }
                if let Some(code) = line.strip_prefix("FSTRACE_VM_RESULT:") {
                    result = code.trim().parse::<i32>().ok().or(Some(-1));
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if harness
                    .qemu
                    .as_mut()
                    .and_then(|c| c.try_wait().ok().flatten())
                    .is_some()
                {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if let Some(mut c) = harness.qemu.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    let _ = reader.join();
    let stderr = stderr_reader.join().unwrap_or_default();

    Ok(QemuOutcome {
        result,
        produced_console,
        stderr,
    })
}
