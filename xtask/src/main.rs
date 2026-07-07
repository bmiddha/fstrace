//! Development automation for the fstrace workspace.
//!
//! Subcommands:
//! - `build`        — build the release binaries (compiles the eBPF object too).
//! - `fmt`          — format the workspace (`--check` to verify only).
//! - `lint`         — run clippy across the host workspace with `-D warnings`.
//! - `test`         — run the host unit-test suite.
//! - `check`        — the aggregate local-CI gate: fmt-check + lint + test.
//! - `clean`        — remove build artifacts and the VM test cache.
//! - `vm-test`      — run the full privileged end-to-end suite inside a QEMU VM.
//! - `docker-build` — build the `FROM scratch` daemon image (static musl binary).
//! - `docker-test`  — run the containerized daemon end-to-end (needs rootful runtime).
//! - `dist`         — cross-compile release tarballs for the full target matrix.

use std::process::{Command, ExitCode};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};

mod dist;
mod docker;
mod initramfs;
mod kernel;
mod lifecycle;
mod vm;

#[derive(Parser)]
#[command(about = "fstrace development tasks")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the release binaries (fstrace + fstrace-daemon).
    Build,
    /// Format the workspace (`--check` verifies without modifying).
    Fmt {
        /// Only check formatting; do not modify files.
        #[arg(long)]
        check: bool,
    },
    /// Run clippy across the host workspace with warnings denied.
    Lint,
    /// Run the host unit-test suite.
    Test,
    /// Run the aggregate local-CI gate: fmt-check, lint, then tests.
    Check,
    /// Remove build artifacts and the VM test cache.
    Clean,
    /// Run the full end-to-end test suite inside a QEMU VM.
    VmTest {
        /// Kernel to boot (see `vm.rs` RELEASES): 5.10, 5.15, 6.1, 6.6, 6.12,
        /// 6.18, 7.1, 7.2-rc. Default: 6.12.
        #[arg(long, default_value = "6.12")]
        release: String,
        /// Extra arguments forwarded to the in-guest `fstrace-vmtest guest`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Build the `FROM scratch` daemon image (static musl `fstrace-daemon`).
    DockerBuild,
    /// Run the containerized daemon end-to-end (needs a rootful runtime).
    DockerTest,
    /// Cross-compile release tarballs for (arm64, x64) × (glibc, musl).
    Dist {
        /// Targets to build; defaults to the full supported matrix. Repeatable.
        #[arg(long = "target")]
        targets: Vec<String>,
    },
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

fn run(mut cmd: Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command {cmd:?} failed with {status}");
    }
    Ok(())
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let root = workspace_root();
    match cli.command {
        Cmd::Build => {
            let mut cmd = Command::new(env!("CARGO"));
            cmd.current_dir(&root)
                .args(["build", "--release", "-p", "fstrace"]);
            run(cmd)?;
        }
        Cmd::Fmt { check } => {
            lifecycle::fmt(&root, check)?;
        }
        Cmd::Lint => {
            lifecycle::lint(&root)?;
        }
        Cmd::Test => {
            lifecycle::test(&root)?;
        }
        Cmd::Check => {
            lifecycle::check(&root)?;
        }
        Cmd::Clean => {
            lifecycle::clean(&root)?;
        }
        Cmd::VmTest { release, args } => {
            let rel = vm::find_release(&release)?;
            vm::run_vm_test(&root, rel, &args)?;
        }
        Cmd::DockerBuild => {
            docker::docker_build(&root)?;
        }
        Cmd::DockerTest => {
            docker::docker_test(&root)?;
        }
        Cmd::Dist { targets } => {
            dist::dist(&root, &targets)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
