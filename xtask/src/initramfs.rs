//! Build a QEMU initramfs for the VM tests from a *Docker image* rootfs plus the
//! host-built static-musl fstrace binaries.
//!
//! This decouples the guest userspace (any Docker image) from the guest kernel
//! (a prebuilt `bzImage`), so the kernel version is the only variable under
//! test. The generated initramfs boots straight into `/init` (as PID 1), mounts
//! the pseudo-filesystems fstrace needs, runs the privileged guest suite, prints
//! a machine-readable `FSTRACE_VM_RESULT:<code>` sentinel, and powers off via
//! magic-SysRq.
//!
//! Native Rust port of the former `tests/vm/build-initramfs.sh`. The rootfs must
//! be unpacked as root (via `sudo`) so setuid bits (notably on `su`, used by the
//! guest harness) and the `/dev` device nodes are preserved.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};

/// The four static binaries the guest suite needs.
const BINS: [&str; 4] = [
    "fstrace",
    "fstrace-daemon",
    "fstrace-vmtest",
    "fstrace-scenario",
];

/// PID 1 for the initramfs: mount pseudo-fs, run the guest suite, report the
/// result via a sentinel line, then power off cleanly with magic-SysRq.
const INIT_SCRIPT: &str = r#"#!/bin/sh
# fstrace VM-test PID 1: mount pseudo-fs, run the guest suite, report, poweroff.
mount -t proc     proc     /proc               2>/dev/null
mount -t sysfs    sys      /sys                2>/dev/null
mount -t devtmpfs dev      /dev                2>/dev/null
mount -t tmpfs    tmpfs    /run                2>/dev/null
mount -t tmpfs    tmpfs    /tmp                2>/dev/null
mkdir -p /dev/pts /dev/shm
mount -t devpts   devpts   /dev/pts            2>/dev/null
mount -t tmpfs    tmpfs    /dev/shm            2>/dev/null
mount -t tracefs  tracefs  /sys/kernel/tracing 2>/dev/null
mount -t debugfs  debugfs  /sys/kernel/debug   2>/dev/null
mount -t bpf      bpf      /sys/fs/bpf         2>/dev/null

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root

echo "[vm] guest kernel: $(uname -r)"
FSTRACE=/fstrace/fstrace \
FSTRACE_DAEMON=/fstrace/fstrace-daemon \
FSTRACE_SCENARIO=/fstrace/fstrace-scenario \
	/fstrace/fstrace-vmtest guest
code=$?
echo "FSTRACE_VM_RESULT:$code"

sync
echo o >/proc/sysrq-trigger 2>/dev/null
sleep 10
exec /bin/sh
"#;

fn require_tool(bin: &str) -> Result<()> {
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
        bail!("{bin} is required but was not found")
    }
}

fn run(mut cmd: Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command {cmd:?} failed with {status}");
    }
    Ok(())
}

/// Builds a `sudo <args...>` command.
fn sudo(args: &[&str]) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.args(args);
    cmd
}

/// Builds the initramfs at `out` from `image`'s rootfs plus the four static
/// binaries in `bin_dir`.
pub fn build_initramfs(image: &str, out: &Path, bin_dir: &Path) -> Result<()> {
    require_tool("docker")?;
    require_tool("cpio")?;
    require_tool("sudo")?;
    for b in BINS {
        let p = bin_dir.join(b);
        if !p.is_file() {
            bail!("missing binary: {}", p.display());
        }
    }

    // mktemp -d makes the dir 0700; the initramfs root ("/") inherits that mode,
    // which would stop the unprivileged fstuser from traversing "/" (su ->
    // EACCES), so force it to 0755.
    let stage = std::env::temp_dir().join(format!(
        "fstrace-initramfs-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;
    let mut perms = std::fs::metadata(&stage)?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&stage, perms)?;

    let result = stage_and_pack(image, out, bin_dir, &stage);
    // Always clean up the (root-owned) staging tree.
    let _ = sudo(&["rm", "-rf", &stage.to_string_lossy()]).status();
    result
}

fn stage_and_pack(image: &str, out: &Path, bin_dir: &Path, stage: &Path) -> Result<()> {
    eprintln!("build-initramfs: exporting rootfs from {image}");
    // Pull the image if it is not present locally.
    let present = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !present {
        run({
            let mut c = Command::new("docker");
            c.args(["pull", image]).stdout(Stdio::null());
            c
        })?;
    }

    // `docker export <container>` streams the flattened rootfs as a tar; pipe it
    // into `sudo tar -x` so setuid bits and ownership are preserved.
    let cid = {
        let out = Command::new("docker")
            .args(["create", image, "true"])
            .output()
            .context("docker create")?;
        if !out.status.success() {
            bail!(
                "docker create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let export_result = export_rootfs(&cid, stage);
    let _ = Command::new("docker")
        .args(["rm", &cid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    export_result?;

    // Stage mount points and the fstrace binaries.
    let stage_s = stage.to_string_lossy().into_owned();
    let dirs: Vec<String> = [
        "fstrace",
        "dev",
        "proc",
        "sys",
        "run",
        "tmp",
        "sys/kernel/tracing",
    ]
    .iter()
    .map(|d| format!("{stage_s}/{d}"))
    .collect();
    let mut mkdir_args = vec!["mkdir", "-p"];
    mkdir_args.extend(dirs.iter().map(|s| s.as_str()));
    run(sudo(&mkdir_args))?;

    let fstrace_dir = format!("{stage_s}/fstrace/");
    let mut cp_args = vec!["cp"];
    let bin_paths: Vec<String> = BINS
        .iter()
        .map(|b| bin_dir.join(b).to_string_lossy().into_owned())
        .collect();
    cp_args.extend(bin_paths.iter().map(|s| s.as_str()));
    cp_args.push(&fstrace_dir);
    run(sudo(&cp_args))?;

    // PID 1 needs /dev/console (its stdio) and /dev/null before devtmpfs is
    // mounted; the kernel opens these from the initramfs itself. Remove any
    // pre-existing entries first (some base images, e.g. Ubuntu, ship a
    // /dev/console) so mknod is idempotent.
    let console = format!("{stage_s}/dev/console");
    let null = format!("{stage_s}/dev/null");
    let _ = sudo(&["rm", "-f", &console, &null]).status();
    let _ = sudo(&["mknod", "-m", "0622", &console, "c", "5", "1"]).status();
    let _ = sudo(&["mknod", "-m", "0666", &null, "c", "1", "3"]).status();

    // Write /init (owned by root, mode 0755).
    let init_tmp = std::env::temp_dir().join(format!("fstrace-init-{}", nanos()));
    std::fs::write(&init_tmp, INIT_SCRIPT)?;
    let init_dst = format!("{stage_s}/init");
    run(sudo(&["cp", &init_tmp.to_string_lossy(), &init_dst]))?;
    run(sudo(&["chmod", "0755", &init_dst]))?;
    let _ = std::fs::remove_file(&init_tmp);

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    eprintln!("build-initramfs: packing {}", out.display());
    let tmp_out = format!("{}.tmp", out.to_string_lossy());
    let pack = format!(
        "cd '{stage_s}' && find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > '{tmp_out}'"
    );
    run(sudo(&["sh", "-c", &pack]))?;
    let uid_gid = format!("{}:{}", uid(), gid());
    run(sudo(&["chown", &uid_gid, &tmp_out]))?;
    std::fs::rename(&tmp_out, out)?;
    eprintln!("build-initramfs: wrote {}", out.display());
    Ok(())
}

/// Streams `docker export <cid>` into `sudo tar -C <stage> -xf -`.
fn export_rootfs(cid: &str, stage: &Path) -> Result<()> {
    let mut exporter = Command::new("docker")
        .args(["export", cid])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning docker export")?;
    let stdout = exporter
        .stdout
        .take()
        .context("capturing docker export stdout")?;

    let mut tar = Command::new("sudo")
        .args(["tar", "-C"])
        .arg(stage)
        .args(["-xf", "-"])
        .stdin(Stdio::from(stdout))
        .spawn()
        .context("spawning sudo tar")?;

    let tar_status = tar.wait().context("waiting for tar")?;
    let exp_status = exporter.wait().context("waiting for docker export")?;
    if !exp_status.success() {
        bail!("docker export failed with {exp_status}");
    }
    if !tar_status.success() {
        bail!("rootfs extraction (tar) failed with {tar_status}");
    }
    Ok(())
}

fn uid() -> String {
    id_value("-u")
}

fn gid() -> String {
    id_value("-g")
}

/// Returns the numeric `id <flag>` value (e.g. `-u` for uid), defaulting to
/// `"0"` if `id` is somehow unavailable.
fn id_value(flag: &str) -> String {
    Command::new("id")
        .arg(flag)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0".into())
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
