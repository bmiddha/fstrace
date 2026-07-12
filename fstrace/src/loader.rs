//! Loads and attaches the embedded eBPF programs. This is the privileged part
//! of fstrace, used exclusively by the daemon.

use std::path::Path;

use anyhow::Context as _;
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::Array,
    programs::{FEntry, FExit, TracePoint},
};
use tracing::{trace, warn};

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

/// Reads the `child_pid` byte offset from the `sched_process_fork` tracepoint
/// format. The kernel exposes each field's offset in
/// `.../events/sched/sched_process_fork/format`; that offset shifted from 44 to
/// 20 when the comm fields became `__data_loc` strings (~6.16), so we must not
/// hardcode it. Falls back to the legacy 44 if the format can't be read.
fn fork_child_pid_offset() -> u32 {
    const LEGACY: u32 = 44;
    for path in [
        "/sys/kernel/tracing/events/sched/sched_process_fork/format",
        "/sys/kernel/debug/tracing/events/sched/sched_process_fork/format",
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            if line.contains("child_pid;")
                && let Some(off) = line
                    .split("offset:")
                    .nth(1)
                    .and_then(|s| s.split(';').next())
                    .and_then(|s| s.trim().parse::<u32>().ok())
            {
                return off;
            }
        }
    }
    LEGACY
}

/// Loads the embedded eBPF object and attaches every program:
/// `enter_*` and `sys_*` become fentry/fexit probes on the matching
/// `__x64_sys_*` kernel function, and `sched_*` become tracepoints. Per-syscall
/// fexit attach failures are warnings (some syscalls may not exist on every
/// kernel); exec fentry and lifecycle tracepoint failures are fatal because
/// correct exec paths and pid scoping depend on them.
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

    // Tell the fork tracepoint where child_pid lives on this kernel.
    let offset = fork_child_pid_offset();
    {
        let map = ebpf
            .map_mut("FORK_CFG")
            .context("FORK_CFG map missing from eBPF object")?;
        let mut cfg: Array<_, u32> = Array::try_from(map).context("FORK_CFG is not an array")?;
        cfg.set(0, offset, 0)
            .context("configuring sched_process_fork child_pid offset")?;
        trace!(offset, "configured sched_process_fork child_pid offset");
    }
    trace!(
        profile_enabled = profile_enabled != 0,
        "configured eBPF profiling"
    );

    let names: Vec<String> = ebpf.programs().map(|(name, _)| name.to_string()).collect();
    for name in names {
        if let Some(program) = ebpf.program_mut(&name) {
            if let Some(syscall) = name.strip_prefix("enter_") {
                let kernel_fn = format!("__x64_sys_{syscall}");
                let prog: &mut FEntry = program.try_into()?;
                prog.load(&kernel_fn, &btf)
                    .with_context(|| format!("loading {name} for {kernel_fn}"))?;
                prog.attach()
                    .with_context(|| format!("attaching {name} to {kernel_fn}"))?;
                trace!(program = %name, target = %kernel_fn, "attached fentry probe");
            } else if let Some(kernel_fn) =
                name.strip_prefix("sys_").map(|_| format!("__x64_{name}"))
            {
                let required_exec_probe = matches!(name.as_str(), "sys_execve" | "sys_execveat");
                let prog: &mut FExit = match program.try_into() {
                    Ok(prog) => prog,
                    Err(err) => {
                        if required_exec_probe {
                            return Err(err)
                                .with_context(|| format!("converting required program {name}"));
                        }
                        warn!("program {name} is not an FExit: {err}");
                        continue;
                    }
                };
                if let Err(err) = prog
                    .load(&kernel_fn, &btf)
                    .and_then(|()| prog.attach().map(|_| ()))
                {
                    if required_exec_probe {
                        return Err(err)
                            .with_context(|| format!("attaching required {name} to {kernel_fn}"));
                    }
                    warn!("skipping {name} (target {kernel_fn}): {err}");
                } else {
                    trace!(program = %name, target = %kernel_fn, "attached fexit probe");
                }
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
