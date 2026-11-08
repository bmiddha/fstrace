//! In-guest test driver for the fstrace QEMU end-to-end suite.
//!
//! Subcommands:
//! - `guest` — privileged bootstrap (run as root inside the VM): create the
//!   unprivileged user, start the daemon, run the client suite, then the
//!   socket-activation test.
//! - `client` — the unprivileged client suite (run as `fstuser`).
//!
//! The raw-syscall scenarios that `fstrace` traces live in a separate thin
//! binary, `fstrace-scenario`. Built on the host and copied into the VM by
//! `cargo xtask vm-test`.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod client;
mod guest;

#[derive(Parser)]
#[command(about = "fstrace in-guest test driver")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Privileged bootstrap: start the daemon and run the full suite as root.
    Guest,
    /// The unprivileged client test suite.
    Client,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Guest => guest::run(),
        Cmd::Client => client::run(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("fstrace-vmtest: {err:#}");
            ExitCode::FAILURE
        }
    }
}
