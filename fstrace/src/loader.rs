//! Loads and attaches the embedded eBPF programs. This is the privileged part
//! of fstrace, used exclusively by the daemon.

use std::path::Path;

use anyhow::Context as _;
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::Array,
    programs::{FEntry, FExit, RawTracePoint, TracePoint},
};
use tracing::{trace, warn};

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("fstrace supports Linux x86_64 and aarch64 targets only");

fn syscall_target(syscall: &str) -> String {
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    format!("__{arch}_sys_{syscall}")
}

/// Ensures tracefs is mounted at `/sys/kernel/tracing` so that tracepoint
/// attachment (which reads event ids from tracefs) works. If tracefs is already
/// present, or is instead available under debugfs, this is a no-op. A failed
/// mount is only a warning: the subsequent attach will surface a precise error
/// if tracefs really is unavailable (e.g. the daemon lacks `CAP_SYS_ADMIN`).
fn ensure_tracefs() {
    // Already mounted somewhere aya can find it.
    if Path::new("/sys/kernel/tracing/events/sched").exists()
        || Path::new("/sys/kernel/debug/tracing/events/sched").exists()
    {
        return;
    }

    let target = "/sys/kernel/tracing";
    if let Err(err) = std::fs::create_dir_all(target) {
        warn!("could not create {target}: {err}");
        return;
    }

    let src = c"tracefs";
    let tgt = c"/sys/kernel/tracing";
    let fstype = c"tracefs";
    // SAFETY: all pointers reference valid NUL-terminated C strings; data is NULL.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        warn!(
            "could not mount tracefs at {target}: {}",
            std::io::Error::last_os_error()
        );
    } else {
        trace!("mounted tracefs at {target}");
    }
}

/// Loads the embedded eBPF object and attaches every program:
/// `enter_*` and `sys_*` become fentry/fexit probes on the matching
/// architecture's `__x64_sys_*` / `__arm64_sys_*` kernel function, and
/// `sched_*` become tracepoints.
/// Every program compiled for the architecture is required. Load or attachment
/// failures are fatal: missing hooks cannot produce a complete trace.
pub fn load_programs(profile_enabled: bool) -> anyhow::Result<Ebpf> {
    // The daemon is the privileged component, so it takes responsibility for
    // making tracefs available. This lets it run in a minimal container (e.g.
    // `FROM scratch` with only `--privileged`) without the host having to
    // bind-mount tracefs, and covers bare-metal setups where nothing mounted
    // it yet.
    ensure_tracefs();

    // Bump the memlock rlimit for older kernels lacking memcg-based accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit with a valid pointer.
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }

    let profile_enabled = u32::from(profile_enabled);
    let mut loader = EbpfLoader::new();
    loader.override_global("PROFILE_ENABLED", &profile_enabled, true);
    let mut ebpf = loader
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/fstrace"
        )))
        .context("loading eBPF object")?;

    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    {
        let bytes = btf.to_bytes();
        let mut cfg: Array<_, u32> =
            Array::try_from(ebpf.map_mut("TASK_CFG").context("TASK_CFG missing")?)?;
        for (index, field) in [
            "pid",
            "tgid",
            "atomic_flags",
            "fs",
            "files",
            "cred",
            "real_parent",
            "start_time",
            "self_exec_id",
        ]
        .into_iter()
        .enumerate()
        {
            cfg.set(
                index as u32,
                &crate::kernel_btf::member_offset(&bytes, "task_struct", field)?,
                0,
            )?;
        }
    }

    trace!(
        profile_enabled = profile_enabled != 0,
        "configured eBPF profiling"
    );

    let names: Vec<String> = ebpf.programs().map(|(name, _)| name.to_string()).collect();
    for name in names {
        if let Some(program) = ebpf.program_mut(&name) {
            if let Some(syscall) = name.strip_prefix("enter_") {
                let kernel_fn = syscall_target(syscall);
                let prog: &mut FEntry = program.try_into()?;
                prog.load(&kernel_fn, &btf)
                    .with_context(|| format!("loading {name} for {kernel_fn}"))?;
                prog.attach()
                    .with_context(|| format!("attaching {name} to {kernel_fn}"))?;
                trace!(program = %name, target = %kernel_fn, "attached fentry probe");
            } else if let Some(kernel_fn) = name.strip_prefix("sys_").map(syscall_target) {
                let prog: &mut FExit = program
                    .try_into()
                    .with_context(|| format!("converting required program {name}"))?;
                prog.load(&kernel_fn, &btf)
                    .with_context(|| format!("loading required {name} for {kernel_fn}"))?;
                prog.attach()
                    .with_context(|| format!("attaching required {name} to {kernel_fn}"))?;
                trace!(program = %name, target = %kernel_fn, "attached fexit probe");
            } else if name == "task_fork" {
                let prog: &mut RawTracePoint = program.try_into()?;
                prog.load()?;
                prog.attach("sched_process_fork")
                    .context("attaching raw fork tracepoint")?;
            } else if name.starts_with("sched_") {
                let prog: &mut TracePoint = program.try_into()?;
                prog.load()?;
                prog.attach("sched", &name)
                    .with_context(|| format!("attaching tracepoint {name}"))?;
                trace!(program = %name, "attached tracepoint");
            }
        }
    }

    Ok(ebpf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_targets_match_userspace_architecture() {
        let prefix = if cfg!(target_arch = "aarch64") {
            "__arm64_sys_"
        } else {
            "__x64_sys_"
        };
        for syscall in ["openat", "execve", "execveat", "renameat2"] {
            assert_eq!(syscall_target(syscall), format!("{prefix}{syscall}"));
        }
    }
}
