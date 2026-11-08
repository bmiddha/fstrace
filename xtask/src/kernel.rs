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
//! shells out to system tools (`curl`, `ar`, `tar`, and `zstd` for EFI zboot).

use std::{
    io::{Read, Seek, SeekFrom},
    ops::Range,
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
        if arch == "arm64" {
            normalize_arm64_kernel(&out)?;
        }
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
    if arch == "arm64" {
        normalize_arm64_kernel(&tmp)?;
    }
    std::fs::rename(&tmp, &out)?;
    let _ = std::fs::remove_dir_all(&work);
    eprintln!("download-kernel: cached {}", out.display());
    Ok(out)
}

/// Ubuntu's newer ARM64 kernels are EFI zboot images. Older QEMU releases
/// cannot decompress zstd zboot payloads, even when the host has zstd installed.
fn normalize_arm64_kernel(path: &Path) -> Result<()> {
    let mut image = std::fs::File::open(path)?;
    let length = image.metadata()?.len();
    let mut header = [0; 64];
    let header_len = length.min(header.len() as u64) as usize;
    image.read_exact(&mut header[..header_len])?;
    let Some(payload) = zstd_payload(&header[..header_len], length)? else {
        return Ok(());
    };
    require_tool("zstd")?;
    eprintln!("download-kernel: decompressing ARM64 EFI zboot image");
    image.seek(SeekFrom::Start(payload.start))?;
    let output = path.with_extension("uncompressed");
    let result = (|| -> Result<()> {
        let mut decoder = Command::new("zstd")
            .args(["-d", "-q", "-c"])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(std::fs::File::create(&output)?))
            .spawn()
            .context("spawning zstd for EFI zboot kernel")?;
        let copy = {
            let mut input = decoder.stdin.take().context("zstd stdin missing")?;
            std::io::copy(&mut image.take(payload.end - payload.start), &mut input)
        };
        let status = decoder
            .wait()
            .context("waiting for EFI zboot decompression")?;
        copy.context("writing EFI zboot payload to zstd")?;
        if !status.success() {
            bail!("EFI zboot decompression failed with {status}");
        }
        let mut decoded = std::fs::File::open(&output)?;
        let mut header = [0; 64];
        decoded
            .read_exact(&mut header)
            .context("decompressed ARM64 kernel header")?;
        if &header[56..60] != b"ARM\x64" {
            bail!("decompressed EFI zboot payload is not an ARM64 Linux Image");
        }
        std::fs::rename(&output, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&output);
    }
    result
}

fn zstd_payload(header: &[u8], image_len: u64) -> Result<Option<Range<u64>>> {
    if header.get(4..8) != Some(b"zimg") {
        return Ok(None);
    }
    if header.len() < 64 {
        bail!("truncated EFI zboot header");
    }
    if &header[24..29] != b"zstd\0" {
        return Ok(None);
    }
    let offset = u32::from_le_bytes(header[8..12].try_into()?) as u64;
    let size = u32::from_le_bytes(header[12..16].try_into()?) as u64;
    let end = offset + size;
    if offset < 64 || size == 0 || end > image_len {
        bail!("invalid EFI zboot payload range {offset}..{end} for {image_len}-byte image");
    }
    Ok(Some(offset..end))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn zboot() -> [u8; 64] {
        let mut header = [0; 64];
        header[4..8].copy_from_slice(b"zimg");
        header[8..12].copy_from_slice(&64u32.to_le_bytes());
        header[12..16].copy_from_slice(&128u32.to_le_bytes());
        header[24..29].copy_from_slice(b"zstd\0");
        header
    }

    #[test]
    fn zstd_zboot_payload_uses_declared_offset_and_size() {
        assert_eq!(zstd_payload(&zboot(), 200).unwrap(), Some(64..192));
    }

    #[test]
    fn native_and_other_compressed_images_pass_through() {
        assert_eq!(zstd_payload(&[0; 64], 64).unwrap(), None);
        assert_eq!(zstd_payload(&[], 0).unwrap(), None);
        let mut header = zboot();
        header[24..29].copy_from_slice(b"gzip\0");
        assert_eq!(zstd_payload(&header, 200).unwrap(), None);
    }

    #[test]
    fn malformed_zboot_payloads_are_rejected() {
        let mut header = zboot();
        assert!(zstd_payload(&header[..32], 200).is_err());
        assert!(zstd_payload(&header, 191).is_err());
        header[8..12].copy_from_slice(&63u32.to_le_bytes());
        assert!(zstd_payload(&header, 200).is_err());
        header[8..12].copy_from_slice(&64u32.to_le_bytes());
        header[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(zstd_payload(&header, 200).is_err());
    }

    #[test]
    #[ignore = "downloads a kernel; requires curl, ar, GNU tar and zstd"]
    fn downloaded_arm64_zboot_image() -> Result<()> {
        let cache = tempdir()?;
        let result = (|| -> Result<()> {
            let version = crate::vm::find_release("6.18")?.version;
            let path = download_kernel(&cache, version, "arm64")?;
            let mut image = std::fs::File::open(&path)?;
            let mut header = [0; 64];
            image.read_exact(&mut header)?;
            assert_eq!(&header[56..60], b"ARM\x64");
            let length = image.metadata()?.len();
            assert_eq!(download_kernel(&cache, version, "arm64")?, path);
            assert_eq!(std::fs::metadata(path)?.len(), length);
            Ok(())
        })();
        std::fs::remove_dir_all(cache)?;
        result
    }

    #[test]
    #[ignore = "requires zstd"]
    fn normalizes_cached_zboot_and_preserves_invalid_images() -> Result<()> {
        let cache = tempdir()?;
        let result = (|| -> Result<()> {
            let raw = cache.join("Image");
            let path = cache.join("zboot");
            for valid in [true, false] {
                let mut image = [0; 64];
                if valid {
                    image[56..60].copy_from_slice(b"ARM\x64");
                }
                std::fs::write(&raw, image)?;
                let mut compress = Command::new("zstd");
                compress.args(["-q", "-c"]).arg(&raw);
                let payload = capture(compress)?;
                let mut header = zboot();
                header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                let encoded = [header.as_slice(), payload.as_slice()].concat();
                std::fs::write(&path, &encoded)?;
                if valid {
                    normalize_arm64_kernel(&path)?;
                    assert_eq!(std::fs::read(&path)?, image);
                    normalize_arm64_kernel(&path)?;
                    assert_eq!(std::fs::read(&path)?, image);
                } else {
                    assert!(normalize_arm64_kernel(&path).is_err());
                    assert_eq!(std::fs::read(&path)?, encoded);
                    assert!(!path.with_extension("uncompressed").exists());
                }
            }
            let encoded = [zboot().as_slice(), &[0; 128]].concat();
            std::fs::write(&path, &encoded)?;
            assert!(normalize_arm64_kernel(&path).is_err());
            assert_eq!(std::fs::read(&path)?, encoded);
            assert!(!path.with_extension("uncompressed").exists());
            Ok(())
        })();
        std::fs::remove_dir_all(cache)?;
        result
    }
}
