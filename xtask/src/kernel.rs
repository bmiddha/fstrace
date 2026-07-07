//! Download a *prebuilt* upstream Linux kernel image (`bzImage` / `vmlinuz`) for
//! use with QEMU direct-kernel-boot in the VM tests.
//!
//! Images come from the Ubuntu mainline build archive
//! (<https://kernel.ubuntu.com/mainline/>), which publishes an unsigned
//! `linux-image` `.deb` for every upstream tag — mainline, release candidates,
//! and stable point releases alike — with `CONFIG_DEBUG_INFO_BTF=y` (required
//! by fstrace's fexit/BTF eBPF programs).
//!
//! This is a native Rust port of the former `tests/vm/download-kernel.sh`; it
//! shells out only to ubiquitous system tools (`curl`, `ar`, `tar`).

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};

/// Default mirror for prebuilt kernels; override with `FSTRACE_KERNEL_MIRROR`.
const DEFAULT_MIRROR: &str = "https://kernel.ubuntu.com/mainline";

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

/// Runs `cmd`, returning its stdout bytes and failing on a non-zero exit.
fn capture(mut cmd: Command) -> Result<Vec<u8>> {
    let out = cmd.output().with_context(|| format!("spawning {cmd:?}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("command {cmd:?} failed with {}: {err}", out.status);
    }
    Ok(out.stdout)
}

/// Downloads (and caches) the prebuilt kernel image for `version`/`arch`,
/// returning the path to the cached `bzImage`. Re-runs are a no-op when the
/// image is already cached under `<cache>/kernels/`.
///
/// `version` is an upstream tag such as `6.12.95` or `7.2-rc2` (a leading `v`
/// is accepted and ignored); `arch` is `amd64` or `arm64`.
pub fn download_kernel(cache: &Path, version: &str, arch: &str) -> Result<PathBuf> {
    if arch != "amd64" && arch != "arm64" {
        bail!("unsupported arch {arch:?} (expected amd64 or arm64)");
    }
    let version = version.strip_prefix('v').unwrap_or(version);

    let kernels = cache.join("kernels");
    std::fs::create_dir_all(&kernels)?;
    let out = kernels.join(format!("bzImage-{version}-{arch}"));
    if out.is_file()
        && std::fs::metadata(&out)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    {
        return Ok(out);
    }

    require_tool("curl")?;
    require_tool("ar")?;

    let mirror = std::env::var("FSTRACE_KERNEL_MIRROR").unwrap_or_else(|_| DEFAULT_MIRROR.into());
    let base = format!("{mirror}/v{version}/{arch}");
    eprintln!("download-kernel: locating image for v{version} ({arch})...");

    // The exact `.deb` filename embeds an ABI + build timestamp that varies per
    // tag, so scrape the directory listing for the unsigned image package.
    let mut list = Command::new("curl");
    list.args(["-fsSL", "--max-time", "60"])
        .arg(format!("{base}/"));
    let listing = String::from_utf8_lossy(
        &capture(list).with_context(|| format!("no build found at {base}/ (unknown version?)"))?,
    )
    .into_owned();

    let deb = find_image_deb(&listing, arch)
        .with_context(|| format!("no linux-image-unsigned package listed at {base}/"))?;

    let work = tempdir()?;
    let deb_path = work.join("image.deb");
    eprintln!("download-kernel: fetching {deb}");
    let mut dl = Command::new("curl");
    dl.args(["-fSL", "--max-time", "600", "-o"])
        .arg(&deb_path)
        .arg(format!("{base}/{deb}"));
    if !dl.status().map(|s| s.success()).unwrap_or(false) {
        bail!("failed to download {base}/{deb}");
    }

    // A `.deb` is an `ar` archive whose payload is `data.tar[.zst|.xz|.gz]`;
    // extract just the kernel image out of `./boot/`.
    let mut arx = Command::new("ar");
    arx.arg("x").arg(&deb_path).current_dir(&work);
    capture(arx)?;

    let data = std::fs::read_dir(&work)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("data.tar"))
                .unwrap_or(false)
        })
        .context("no data.tar inside the .deb")?;

    let mut tarx = Command::new("tar");
    tarx.arg("-C")
        .arg(&work)
        .arg("-xf")
        .arg(&data)
        .args(["--wildcards", "./boot/vmlin*"]);
    // tar picks the right decompressor by content; older tars need a hint for
    // zstd, so add it when present.
    if data.extension().and_then(|e| e.to_str()) == Some("zst") {
        tarx.args(["--use-compress-program", "zstd -d"]);
    }
    capture(tarx)?;

    let boot = work.join("boot");
    let img = std::fs::read_dir(&boot)
        .with_context(|| format!("no ./boot in {}", data.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("vmlinuz-"))
                .unwrap_or(false)
        })
        .context("no vmlinuz found inside the .deb")?;

    let tmp = out.with_extension("tmp");
    std::fs::copy(&img, &tmp).with_context(|| format!("copying {}", img.display()))?;
    std::fs::rename(&tmp, &out)?;
    let _ = std::fs::remove_dir_all(&work);
    eprintln!("download-kernel: cached {}", out.display());
    Ok(out)
}

/// Finds the first `linux-image-unsigned-*-generic_*_<arch>.deb` in an HTML
/// directory listing.
fn find_image_deb(listing: &str, arch: &str) -> Option<String> {
    let suffix = format!("_{arch}.deb");
    let mut hits: Vec<&str> = Vec::new();
    for tok in listing.split('"') {
        if tok.starts_with("linux-image-unsigned-")
            && tok.contains("-generic_")
            && tok.ends_with(&suffix)
        {
            hits.push(tok);
        }
    }
    hits.sort_unstable();
    hits.first().map(|s| s.to_string())
}

/// Creates a unique temp directory owned by this process.
fn tempdir() -> Result<PathBuf> {
    let base =
        std::env::temp_dir().join(format!("fstrace-kernel-{}-{}", std::process::id(), nanos()));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
