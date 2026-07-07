//! Cross-compiled release artifacts.
//!
//! `dist` builds `fstrace` + `fstrace-daemon` for every supported target and
//! stages a `.tar.gz` per target under `dist/`, bundling the two binaries, the
//! man pages and the README. The supported matrix is (arm64, x64) × (glibc,
//! musl):
//!
//! - `x86_64-unknown-linux-gnu`   — dynamically linked against glibc.
//! - `x86_64-unknown-linux-musl`  — fully static (musl).
//! - `aarch64-unknown-linux-gnu`  — dynamically linked against glibc.
//! - `aarch64-unknown-linux-musl` — fully static (musl).
//!
//! aarch64 targets need a cross linker (`aarch64-linux-gnu-gcc`, wired up in
//! `.cargo/config.toml`); install it with `apt-get install gcc-aarch64-linux-gnu`.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

/// Every release target in the (arch × libc) support matrix.
pub const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
];

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn log(msg: &str) {
    println!("\x1b[1;36m[dist]\x1b[0m {msg}");
}

fn run(mut cmd: Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command {cmd:?} failed with {status}");
    }
    Ok(())
}

/// Builds every requested target and stages a tarball per target. An empty
/// `requested` list builds the full [`TARGETS`] matrix.
pub fn dist(root: &Path, requested: &[String]) -> Result<()> {
    let targets: Vec<&str> = if requested.is_empty() {
        TARGETS.to_vec()
    } else {
        for t in requested {
            if !TARGETS.contains(&t.as_str()) {
                bail!("unknown target {t:?}; supported: {}", TARGETS.join(", "));
            }
        }
        requested.iter().map(String::as_str).collect()
    };

    let out = root.join("dist");
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;

    let mut artifacts = Vec::new();
    for target in targets {
        let tarball = build_target(root, &out, target)?;
        artifacts.push(tarball);
    }

    log("staged artifacts:");
    for a in &artifacts {
        println!("  {}", a.display());
    }
    Ok(())
}

/// Builds one target and returns the path to its `.tar.gz`.
fn build_target(root: &Path, out: &Path, target: &str) -> Result<PathBuf> {
    log(&format!("adding rustup target {target} (idempotent)..."));
    let mut add = Command::new("rustup");
    add.args(["target", "add", target]);
    // Non-fatal: the target may already be installed, or rustup may be absent
    // in an environment that provides the std target another way.
    let _ = add.status();

    log(&format!("building fstrace for {target}..."));
    let mut build = Command::new(env!("CARGO"));
    build
        .current_dir(root)
        .args(["build", "--release", "-p", "fstrace", "--target", target]);
    run(build).with_context(|| {
        format!("building {target} — aarch64 targets need `apt-get install gcc-aarch64-linux-gnu`")
    })?;

    let bin_dir = root.join("target").join(target).join("release");
    let stage_name = format!("fstrace-{VERSION}-{target}");
    let stage = out.join(&stage_name);
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;

    for bin in ["fstrace", "fstrace-daemon"] {
        let src = bin_dir.join(bin);
        if !src.is_file() {
            bail!("missing {} — build failed", src.display());
        }
        copy_into(&src, &stage.join(bin))?;
    }
    for extra in [
        "packaging/man/fstrace.1",
        "packaging/man/fstrace-daemon.1",
        "README.md",
        "LICENSE",
    ] {
        let src = root.join(extra);
        if src.is_file() {
            let name = src.file_name().expect("path has a file name");
            copy_into(&src, &stage.join(name))?;
        }
    }

    let tarball = out.join(format!("{stage_name}.tar.gz"));
    log(&format!("packaging {}...", tarball.display()));
    let mut tar = Command::new("tar");
    tar.current_dir(out)
        .args(["czf", &tarball.to_string_lossy(), &stage_name]);
    run(tar)?;

    Ok(tarball)
}

fn copy_into(src: &Path, dst: &Path) -> Result<()> {
    std::fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(())
}
