//! Container packaging + end-to-end test for the fstrace daemon.
//!
//! `docker-build` produces a fully static (musl) `fstrace-daemon` and bakes it
//! into a `FROM scratch` image. `docker-test` then runs that image as a
//! privileged container with the daemon's socket bind-mounted to a host
//! directory, traces a command from the host (i.e. from a *different* pid and
//! mount namespace than the daemon), and asserts the reports are correct.
//!
//! The container runtime must be rootful (real root, not a rootless user
//! namespace): loading eBPF programs requires genuine `CAP_BPF`/`CAP_SYS_ADMIN`
//! over the host kernel, which a rootless container cannot grant.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";
const IMAGE_TAG: &str = "fstrace-daemon:xtask-test";

fn log(msg: &str) {
    println!("\x1b[1;35m[docker]\x1b[0m {msg}");
}

fn run(mut cmd: Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command {cmd:?} failed with {status}");
    }
    Ok(())
}

/// Picks a container runtime, preferring `docker` and falling back to `podman`.
fn container_runtime() -> Result<String> {
    for rt in ["docker", "podman"] {
        let ok = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {rt}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(rt.to_string());
        }
    }
    bail!("no container runtime found (install docker or podman)")
}

/// Builds the fully static musl `fstrace-daemon`, returning its path.
fn build_static_daemon(root: &Path) -> Result<PathBuf> {
    log("adding musl target (idempotent)...");
    let mut add = Command::new("rustup");
    add.args(["target", "add", MUSL_TARGET]);
    // Non-fatal: the target may already be installed, or rustup absent in an
    // environment that provides the target another way.
    let _ = add.status();

    log("building static fstrace-daemon (musl, static-PIE)...");
    let mut build = Command::new(env!("CARGO"));
    build.current_dir(root).args([
        "build",
        "--release",
        "--target",
        MUSL_TARGET,
        "-p",
        "fstrace",
        "--bin",
        "fstrace-daemon",
    ]);
    run(build)?;

    let bin = root
        .join("target")
        .join(MUSL_TARGET)
        .join("release/fstrace-daemon");
    if !bin.is_file() {
        bail!("missing {} — build failed", bin.display());
    }
    Ok(bin)
}

/// Builds the `FROM scratch` daemon image. Returns the runtime used.
pub fn docker_build(root: &Path) -> Result<String> {
    let rt = container_runtime()?;
    let bin = build_static_daemon(root)?;
    let dockerfile = root.join("packaging/docker/Dockerfile");

    // Assemble a minimal build context (just the binary) so we don't tar the
    // whole target directory.
    let context = std::env::temp_dir().join(format!("fstrace-img-ctx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&context);
    std::fs::create_dir_all(&context)?;
    std::fs::copy(&bin, context.join("fstrace-daemon"))
        .with_context(|| format!("copying {} into build context", bin.display()))?;

    log(&format!("building image {IMAGE_TAG} with {rt}..."));
    let mut cmd = Command::new(&rt);
    cmd.arg("build")
        .arg("-f")
        .arg(&dockerfile)
        .arg("-t")
        .arg(IMAGE_TAG)
        .arg(&context);
    let build_result = run(cmd);
    let _ = std::fs::remove_dir_all(&context);
    build_result?;
    log(&format!("built {IMAGE_TAG}"));
    Ok(rt)
}

/// Builds the release `fstrace` client, returning its path.
fn build_client(root: &Path) -> Result<PathBuf> {
    log("building host fstrace client...");
    let mut build = Command::new(env!("CARGO"));
    build
        .current_dir(root)
        .args(["build", "--release", "-p", "fstrace", "--bin", "fstrace"]);
    run(build)?;
    let bin = root.join("target/release/fstrace");
    if !bin.is_file() {
        bail!("missing {} — build failed", bin.display());
    }
    Ok(bin)
}

/// Waits up to ~15s for the daemon's socket to appear on the host.
fn wait_for_socket(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn rm_container(rt: &str, name: &str) {
    let _ = Command::new(rt)
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn dump_logs(rt: &str, name: &str) {
    log("container logs:");
    let _ = Command::new(rt).args(["logs", name]).status();
}

/// Runs the full container end-to-end test.
pub fn docker_test(root: &Path) -> Result<()> {
    let rt = docker_build(root)?;
    let client = build_client(root)?;

    // Verify a real host kernel with BTF is present (the daemon reads it).
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!("/sys/kernel/btf/vmlinux missing — kernel lacks BTF; cannot load eBPF");
    }

    let name = format!("fstrace-daemon-xtask-{}", std::process::id());
    let sock_dir = std::env::temp_dir().join(format!("fstrace-docker-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sock_dir);
    std::fs::create_dir_all(&sock_dir)?;
    let host_sock = sock_dir.join("fstrace.sock");

    rm_container(&rt, &name);

    log(&format!(
        "starting daemon container '{name}' (privileged)..."
    ));
    // No --pid=host: the daemon runs in its own pid+mount namespace on purpose,
    // proving it does not depend on sharing the client's namespaces. Only the
    // socket directory is shared, mimicking a real deployment.
    let mut cmd = Command::new(&rt);
    cmd.args(["run", "-d", "--name", &name, "--privileged"])
        .arg("-e")
        .arg("FSTRACE_SOCKET=/sock/fstrace.sock")
        .arg("-v")
        .arg(format!("{}:/sock", sock_dir.display()))
        .arg("-v")
        .arg("/sys/kernel/btf:/sys/kernel/btf:ro")
        .arg(IMAGE_TAG)
        .stdout(Stdio::null());
    if let Err(e) = run(cmd) {
        let _ = std::fs::remove_dir_all(&sock_dir);
        return Err(e);
    }

    let result = (|| -> Result<()> {
        if !wait_for_socket(&host_sock) {
            dump_logs(&rt, &name);
            bail!(
                "daemon socket never appeared at {} — the daemon likely failed to \
                 load eBPF. This test needs a ROOTFUL runtime; a rootless container \
                 cannot create BPF maps (EPERM).",
                host_sock.display()
            );
        }
        log("socket is up; tracing a command from the host namespace...");

        let target = sock_dir.join("target.txt");
        std::fs::write(&target, b"trace me\n")?;
        let out_path = sock_dir.join("reports.txt");

        // Trace `cat <target>` on the host; fd 3 (reports) redirected to a file.
        let script = format!(
            "FSTRACE_SOCKET='{sock}' FSTRACE_FILTER_PREFIX='{dir}' \
             '{client}' cat '{target}' 3>'{out}' 1>/dev/null 2>/dev/null",
            sock = host_sock.display(),
            dir = sock_dir.display(),
            client = client.display(),
            target = target.display(),
            out = out_path.display(),
        );
        run({
            let mut c = Command::new("sh");
            c.arg("-c").arg(&script);
            c
        })?;

        let reports = std::fs::read_to_string(&out_path).unwrap_or_default();
        let expected = format!("RF {}", target.display());
        if reports.contains(&expected) {
            log("PASS — containerized daemon traced a host command correctly");
            Ok(())
        } else {
            dump_logs(&rt, &name);
            bail!("expected a '{expected}' report from the containerized daemon, got:\n{reports}");
        }
    })();

    rm_container(&rt, &name);
    let _ = std::fs::remove_dir_all(&sock_dir);
    result
}
