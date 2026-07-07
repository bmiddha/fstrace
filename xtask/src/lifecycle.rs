//! Repo lifecycle tasks: formatting, linting, unit tests, and the aggregate
//! local-CI gate. These wrap the canonical workspace invocations so contributors
//! (and CI) drive everything through `cargo xtask` rather than remembering the
//! exact flags.
//!
//! The eBPF crate (`fstrace-ebpf`) is excluded from clippy/test because it is a
//! `no_std` BPF target built by the `fstrace` build script, not a host crate.

use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

/// The BPF-target crate that host clippy/test cannot build directly.
const EBPF_CRATE: &str = "fstrace-ebpf";

fn log(msg: &str) {
    println!("\x1b[1;32m[xtask]\x1b[0m {msg}");
}

fn cargo(root: &Path, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(root).args(args);
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command {cmd:?} failed with {status}");
    }
    Ok(())
}

/// Formats the whole workspace. When `check` is set, only verifies formatting
/// (non-zero exit if anything is unformatted) without modifying files.
pub fn fmt(root: &Path, check: bool) -> Result<()> {
    if check {
        log("checking formatting (cargo fmt --all --check)...");
        cargo(root, &["fmt", "--all", "--check"])
    } else {
        log("formatting (cargo fmt --all)...");
        cargo(root, &["fmt", "--all"])
    }
}

/// Runs clippy across the host workspace with warnings denied.
pub fn lint(root: &Path) -> Result<()> {
    log("linting (cargo clippy -D warnings)...");
    cargo(
        root,
        &[
            "clippy",
            "--release",
            "--workspace",
            "--exclude",
            EBPF_CRATE,
            "--",
            "-D",
            "warnings",
        ],
    )
}

/// Runs the host unit-test suite.
pub fn test(root: &Path) -> Result<()> {
    log("testing (cargo test)...");
    cargo(
        root,
        &["test", "--release", "--workspace", "--exclude", EBPF_CRATE],
    )
}

/// The aggregate local-CI gate: formatting check, lint, then unit tests. This
/// mirrors what CI enforces on every push (minus the VM matrix).
pub fn check(root: &Path) -> Result<()> {
    fmt(root, true)?;
    lint(root)?;
    test(root)?;
    log("all checks passed");
    Ok(())
}

/// Removes build artifacts and the VM test cache (downloaded kernels +
/// generated initramfs).
pub fn clean(root: &Path) -> Result<()> {
    log("cargo clean...");
    cargo(root, &["clean"])?;
    let cache = root.join("tests/vm/.cache");
    if cache.exists() {
        log(&format!("removing {}...", cache.display()));
        std::fs::remove_dir_all(&cache).with_context(|| format!("removing {}", cache.display()))?;
    }
    Ok(())
}
