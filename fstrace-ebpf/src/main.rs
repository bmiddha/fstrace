//! Capture syscall paths in fexit and send [`Event`]s through the ring buffer.
//! Exec paths are saved in fentry, before exec replaces userspace memory.
//! Registration and fork/exit hooks track task ownership.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

#[cfg(not(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64")))]
compile_error!("fstrace eBPF supports x86_64 and aarch64 only");

#[cfg(bpf_target_arch = "aarch64")]
use aya_ebpf::bindings::user_pt_regs;
#[cfg(bpf_target_arch = "x86_64")]
use aya_ebpf::cty::c_ulong;
use aya_ebpf::{
    Global,
    bindings::pt_regs,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{fentry, fexit, map, raw_tracepoint, tracepoint},
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{FEntryContext, FExitContext, RawTracePointContext, TracePointContext},
};
use fstrace_common::{
    EVENT_EXIT, EVENT_FORK, EbpfProfileStat, Event, PATH_MAX, REGISTER_PRCTL, Registration,
    SYSCALL_COUNT, Syscall, TaskKey,
};

/// `O_CREAT` from `<fcntl.h>` on Linux; `creat(2)` implies it.
#[cfg(bpf_target_arch = "x86_64")]
const O_CREAT: i64 = 0o100;

/// Saved exec path. Per-CPU scratch keeps PATH_MAX bytes off the BPF stack.
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecPath {
    original_birth: u64,
    dirfd: i64,
    flags: i64,
    original_tid: u32,
    len: u32,
    bytes: [u8; PATH_MAX],
}

/// Ring buffer carrying [`Event`]s to userspace (16 MiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[map]
static TASK_CFG: Array<u32> = Array::with_max_entries(9, 0);

#[inline(always)]
unsafe fn task_field<T: Copy>(task: u64, index: u32) -> Result<T, i32> {
    let offset = TASK_CFG.get(index).copied().ok_or(-1i32)?;
    unsafe { bpf_probe_read_kernel((task + offset as u64) as *const T) }
}

/// Read-only switch overridden by the loader when `FSTRACE_PROFILE=1`.
#[unsafe(no_mangle)]
static PROFILE_ENABLED: Global<u32> = Global::new(0);

/// Per-CPU, per-syscall capture timings. Disabled runs only pay one config-map
/// lookup after a pid has already matched [`TRACED`].
#[map]
static PROFILE_STATS: PerCpuArray<EbpfProfileStat> =
    PerCpuArray::with_max_entries(SYSCALL_COUNT as u32, 0);

/// Per-CPU staging buffer used while copying an exec pathname from userspace.
#[map]
static EXEC_PATH_SCRATCH: PerCpuArray<ExecPath> = PerCpuArray::with_max_entries(1, 0);

/// In-flight exec pathnames, keyed by `task_struct` so a non-leader thread's
/// successful exec survives the kernel's TID change during `de_thread()`.
#[map]
static EXEC_PATHS: HashMap<u64, ExecPath> = HashMap::with_max_entries(4096, 0);

/// One-use socket capabilities and kernel-observed parent/child identities.
#[map]
static REGISTRATIONS: HashMap<[u64; 2], Registration> = HashMap::with_max_entries(1024, 0);

#[map]
static REGISTERING_TASKS: HashMap<u64, [u64; 2]> = HashMap::with_max_entries(1024, 0);

/// Always-on loss generation, including lifecycle and map failures.
#[map]
static LOSSES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn lost() {
    if let Some(value) = LOSSES.get_ptr_mut(0) {
        unsafe {
            *value = (*value).wrapping_add(1);
        }
    }
}

/// Task lifetimes and their session IDs.
#[map]
static TRACED: HashMap<TaskKey, u64> = HashMap::with_max_entries(65536, 0);

#[inline(always)]
fn task_key(tid: u32, task: u64) -> Option<TaskKey> {
    match unsafe { task_field::<u64>(task, 7) } {
        Ok(birth) => Some(TaskKey::new(tid, birth)),
        Err(_) => {
            lost();
            None
        }
    }
}

#[map]
static SESSIONS: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static INFLIGHT: PerCpuHashMap<u64, u64> = PerCpuHashMap::with_max_entries(1024, 0);

struct CaptureGuard(*mut u64);

#[inline(always)]
unsafe fn capture_count(value: *mut u64, change: u64) {
    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::SeqCst }>(
            value, change,
        );
    }
}

impl Drop for CaptureGuard {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            capture_count(self.0, u64::MAX);
        }
    }
}

#[inline(always)]
fn begin_capture(session: u64) -> Option<CaptureGuard> {
    let value = INFLIGHT.get_ptr_mut(&session)?;
    unsafe {
        capture_count(value, 1);
    }
    let guard = CaptureGuard(value);
    if unsafe { SESSIONS.get(&session) }.copied() != Some(2) {
        return None;
    }
    Some(guard)
}

/// Bind the socket's one-use token to this task's next fork, never a supplied PID.
#[fentry]
pub fn enter_prctl(ctx: FEntryContext) -> u32 {
    let regs: *const pt_regs = ctx.arg(0);
    unsafe {
        if reg(regs, 0) as u32 != REGISTER_PRCTL {
            return 0;
        }
        let token = [reg(regs, 1), reg(regs, 2)];
        let Some(mut pending) = REGISTRATIONS.get(&token).copied() else {
            return 0;
        };
        let task = bpf_get_current_task();
        if pending.parent_task == 0 {
            let Ok(cred) = task_field::<u64>(task, 5) else {
                return 0;
            };
            let Ok(start) = task_field::<u64>(task, 7) else {
                return 0;
            };
            pending.parent_task = task;
            pending.parent_cred = cred;
            pending.parent_start = start;
            if REGISTRATIONS.insert(&token, &pending, 0).is_err()
                || REGISTERING_TASKS.insert(&task, &token, 0).is_err()
            {
                lost();
            }
            return 0;
        }
        // Start times reject task reuse; credential and exec checks reject
        // changes in authority before the child's acknowledgement.
        if pending.child_task != task
            || task_field::<u64>(task, 7) != Ok(pending.child_start)
            || task_field::<u64>(task, 6) != Ok(pending.parent_task)
            || task_field::<u64>(pending.parent_task, 7) != Ok(pending.parent_start)
            || task_field::<u64>(pending.parent_task, 5) != Ok(pending.parent_cred)
            || task_field::<u64>(task, 5) != Ok(pending.child_cred)
            || task_field::<u64>(task, 8) != Ok(pending.child_exec)
            || task_field::<u64>(task, 2).map_or(true, |flags| flags & 1 == 0)
            || SESSIONS.get(&pending.session).is_none()
        {
            return 0;
        }
        let key = TaskKey::new(pending.child, pending.child_start);
        if TRACED.insert(&key, &pending.session, 1).is_err() {
            lost();
        }
        if SESSIONS.get(&pending.session).is_none()
            && TRACED.get(&key).copied() == Some(pending.session)
        {
            let _ = TRACED.remove(&key);
        }
    }
    0
}

/// Where a syscall's open-style flags come from.
#[derive(Clone, Copy)]
enum Flags {
    /// No meaningful flags for this syscall.
    None,
    /// Flags are the `pt_regs` argument at this index.
    Arg(u8),
    /// Flags are a fixed constant (e.g. `creat` implies `O_CREAT`).
    #[cfg(bpf_target_arch = "x86_64")]
    Const(i64),
    /// Flags live in the first `u64` of a `struct open_how` pointed to by the
    /// `pt_regs` argument at this index (`openat2`).
    OpenHow(u8),
}

/// Describes how to extract paths / dirfds / flags from a syscall's registers.
#[derive(Clone, Copy)]
struct Spec {
    path1: Option<u8>,
    path2: Option<u8>,
    dirfd1: Option<u8>,
    dirfd2: Option<u8>,
    flags: Flags,
}

impl Spec {
    const fn new() -> Self {
        Spec {
            path1: None,
            path2: None,
            dirfd1: None,
            dirfd2: None,
            flags: Flags::None,
        }
    }
    const fn path1(mut self, i: u8) -> Self {
        self.path1 = Some(i);
        self
    }
    const fn path2(mut self, i: u8) -> Self {
        self.path2 = Some(i);
        self
    }
    const fn dirfd1(mut self, i: u8) -> Self {
        self.dirfd1 = Some(i);
        self
    }
    const fn dirfd2(mut self, i: u8) -> Self {
        self.dirfd2 = Some(i);
        self
    }
    const fn flags(mut self, f: Flags) -> Self {
        self.flags = f;
        self
    }
}

/// Read a syscall argument from kernel pt_regs.
/// x86-64 uses rdi, rsi, rdx, r10 (not rcx), r8, r9; ARM64 uses x0..x5.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
unsafe fn reg(regs: *const pt_regs, idx: u8) -> u64 {
    let field: *const c_ulong = unsafe {
        match idx {
            0 => &raw const (*regs).rdi,
            1 => &raw const (*regs).rsi,
            2 => &raw const (*regs).rdx,
            3 => &raw const (*regs).r10,
            4 => &raw const (*regs).r8,
            5 => &raw const (*regs).r9,
            _ => return 0,
        }
    };
    unsafe { bpf_probe_read_kernel(field).unwrap_or(0) }
}

/// aarch64 variant: `struct pt_regs` begins with the `user_pt_regs.regs[31]`
/// general-register array, so `x0..x5` are `regs[0..=5]`.
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
unsafe fn reg(regs: *const pt_regs, idx: u8) -> u64 {
    if idx > 5 {
        return 0;
    }
    let user = regs as *const user_pt_regs;
    let field = unsafe { &raw const (*user).regs[idx as usize] };
    unsafe { bpf_probe_read_kernel(field).unwrap_or(0) }
}

/// Reads a userspace C string into `dst`, returning the number of bytes copied
/// (excluding the NUL terminator). A NULL or unreadable pointer yields 0.
#[inline(always)]
fn read_user_path(ptr: u64, dst: &mut [u8; PATH_MAX]) -> u32 {
    if ptr == 0 {
        return 0;
    }
    match unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, dst) } {
        Ok(bytes) => bytes.len() as u32,
        Err(_) => 0,
    }
}

#[inline(always)]
fn profile_start() -> u64 {
    if PROFILE_ENABLED.load() != 0 {
        unsafe { bpf_ktime_get_ns() }
    } else {
        0
    }
}

#[inline(always)]
fn record_profile(
    syscall: Syscall,
    start_ns: u64,
    path_reads: u64,
    path_bytes: u64,
    path_read_ns: u64,
    submitted: bool,
) {
    if start_ns == 0 {
        return;
    }
    let capture_ns = unsafe { bpf_ktime_get_ns() } - start_ns;
    if let Some(stats) = PROFILE_STATS.get_ptr_mut(syscall as u32) {
        unsafe {
            (*stats).calls += 1;
            (*stats).submitted += submitted as u64;
            (*stats).ringbuf_drops += (!submitted) as u64;
            (*stats).path_reads += path_reads;
            (*stats).path_bytes += path_bytes;
            (*stats).capture_ns += capture_ns;
            (*stats).path_read_ns += path_read_ns;
        }
    }
}

/// Adds the separate exec-fentry work to the same per-syscall profile row
/// without counting a second syscall call or ring-buffer submission.
#[inline(always)]
fn record_exec_entry_profile(syscall: Syscall, start_ns: u64, path_bytes: u64, path_read_ns: u64) {
    if start_ns == 0 {
        return;
    }
    let capture_ns = unsafe { bpf_ktime_get_ns() } - start_ns;
    if let Some(stats) = PROFILE_STATS.get_ptr_mut(syscall as u32) {
        unsafe {
            (*stats).path_reads += 1;
            (*stats).path_bytes += path_bytes;
            (*stats).capture_ns += capture_ns;
            (*stats).path_read_ns += path_read_ns;
        }
    }
}

/// Saves an exec pathname while the caller's original userspace address space
/// still exists. `task_struct` is stable even when exec changes a non-leader
/// thread's TID to the process TGID.
#[inline(always)]
fn capture_exec_path(ctx: &FEntryContext, syscall: Syscall, path_arg: u8) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let task = unsafe { bpf_get_current_task() };
    let Some(key) = task_key(tid, task) else {
        return 0;
    };
    let Some(session) = unsafe { TRACED.get(&key) }.copied() else {
        return 0;
    };
    let Some(_capture) = begin_capture(session) else {
        return 0;
    };

    let profile_start_ns = profile_start();
    let regs_ptr: *const pt_regs = ctx.arg(0);
    let scratch = match EXEC_PATH_SCRATCH.get_ptr_mut(0) {
        Some(scratch) => scratch,
        None => return 0,
    };
    let path_start_ns = if profile_start_ns != 0 {
        unsafe { bpf_ktime_get_ns() }
    } else {
        0
    };

    unsafe {
        (*scratch).original_tid = tid;
        (*scratch).original_birth = key.birth;
        let path_ptr = reg(regs_ptr, path_arg);
        // ARM64 start_thread resets pt_regs during successful exec, including
        // the directory fd and flags needed to resolve relative execveat.
        (*scratch).dirfd = if syscall == Syscall::Execveat {
            reg(regs_ptr, 0) as i32 as i64
        } else {
            0
        };
        (*scratch).flags = if syscall == Syscall::Execveat {
            reg(regs_ptr, 4) as i64
        } else {
            0
        };
        (*scratch).len = read_user_path(path_ptr, &mut (*scratch).bytes);
        let path_read_ns = if path_start_ns != 0 {
            bpf_ktime_get_ns() - path_start_ns
        } else {
            0
        };
        let task = bpf_get_current_task();
        if EXEC_PATHS.insert(&task, &*scratch, 0).is_err() {
            lost();
        }
        record_exec_entry_profile(
            syscall,
            profile_start_ns,
            (*scratch).len as u64,
            path_read_ns,
        );
    }
    0
}

/// Shared body for every traced syscall's `fexit` program.
#[inline(always)]
fn handle(ctx: &FExitContext, syscall: Syscall, spec: Spec, captured_exec: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let exec_task = if captured_exec {
        unsafe { bpf_get_current_task() }
    } else {
        0
    };

    let ret: i64 = ctx.arg(1);
    let source_tid = if captured_exec {
        unsafe { EXEC_PATHS.get(&exec_task) }
            .map(|saved| saved.original_tid)
            .unwrap_or(tid)
    } else {
        tid
    };
    let task = unsafe { bpf_get_current_task() };
    let Some(key) = task_key(tid, task) else {
        return 0;
    };
    // de_thread also replaces a promoted exec thread's start time.
    let source_birth = if captured_exec {
        unsafe { EXEC_PATHS.get(&exec_task) }
            .map(|saved| saved.original_birth)
            .unwrap_or(key.birth)
    } else {
        key.birth
    };
    let source_key = TaskKey::new(source_tid, source_birth);
    let Some(session) = unsafe { TRACED.get(&source_key) }.copied() else {
        if captured_exec {
            let _ = EXEC_PATHS.remove(&exec_task);
        }
        return 0;
    };
    let Some(_capture) = begin_capture(session) else {
        return 0;
    };
    if captured_exec && ret == 0 && source_tid != tid {
        match unsafe { TRACED.get(&key) }.copied() {
            Some(owner) if owner != session => {
                lost();
                return 0;
            }
            Some(_) => {}
            None => {
                if TRACED.insert(&key, &session, 1).is_err() {
                    lost();
                    return 0;
                }
            }
        }
        if !emit_lifecycle(EVENT_FORK, tgid, source_key, key, tgid, 0, session) {
            let _ = TRACED.remove(&key);
        }
        emit_lifecycle(
            EVENT_EXIT,
            tgid,
            source_key,
            TaskKey::new(0, 0),
            0,
            0,
            session,
        );
        let _ = TRACED.remove(&source_key);
    }
    let profile_start_ns = profile_start();

    // fexit args: [ *const pt_regs, return_value ].
    let regs_ptr: *const pt_regs = ctx.arg(0);

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => {
            lost();
            if captured_exec {
                let _ = EXEC_PATHS.remove(&exec_task);
            }
            record_profile(syscall, profile_start_ns, 0, 0, 0, false);
            return 0;
        }
    };
    let ev = entry.as_mut_ptr();
    let mut path_reads = 0;
    let mut path_bytes = 0;

    unsafe {
        (*ev).session = session;
        (*ev).birth = key.birth;
        (*ev).child_birth = 0;
        (*ev).pid = tgid;
        (*ev).tid = tid;
        (*ev).syscall = syscall as u32;
        (*ev).ret = ret;
        (*ev).path_len = 0;
        (*ev).path2_len = 0;
        (*ev).dirfd = 0;
        (*ev).dirfd2 = 0;
        (*ev).flags = 0;

        if let Some(i) = spec.dirfd1 {
            // dirfd/fd are 32-bit `int`s; sign-extend so AT_FDCWD (-100) and
            // other negative values survive the widening to i64.
            (*ev).dirfd = reg(regs_ptr, i) as i32 as i64;
        }
        if let Some(i) = spec.dirfd2 {
            (*ev).dirfd2 = reg(regs_ptr, i) as i32 as i64;
        }
        (*ev).flags = match spec.flags {
            Flags::None => 0,
            Flags::Arg(i) => reg(regs_ptr, i) as i64,
            #[cfg(bpf_target_arch = "x86_64")]
            Flags::Const(c) => c,
            Flags::OpenHow(i) => {
                let how_ptr = reg(regs_ptr, i);
                // `struct open_how { u64 flags; ... }` — flags is the first field.
                bpf_probe_read_user::<u64>(how_ptr as *const u64).unwrap_or(0) as i64
            }
        };
        let mut used_captured_path = false;
        if captured_exec && let Some(saved) = EXEC_PATHS.get_ptr(&exec_task) {
            let saved = &*saved;
            (*ev).dirfd = saved.dirfd;
            (*ev).flags = saved.flags;
            let len = saved.len.min(PATH_MAX as u32);
            if bpf_probe_read_kernel_buf(saved.bytes.as_ptr(), &mut (*ev).path).is_ok() {
                (*ev).path_len = len;
                used_captured_path = true;
            }
        }
        let path_start_ns = if profile_start_ns != 0
            && ((spec.path1.is_some() && !used_captured_path) || spec.path2.is_some())
        {
            bpf_ktime_get_ns()
        } else {
            0
        };
        if !used_captured_path {
            if let Some(i) = spec.path1 {
                let p = reg(regs_ptr, i);
                (*ev).path_len = read_user_path(p, &mut (*ev).path);
                path_reads += 1;
                path_bytes += (*ev).path_len as u64;
            }
        }
        if let Some(i) = spec.path2 {
            let p = reg(regs_ptr, i);
            (*ev).path2_len = read_user_path(p, &mut (*ev).path2);
            path_reads += 1;
            path_bytes += (*ev).path2_len as u64;
        }
        let path_read_ns = if path_start_ns != 0 {
            bpf_ktime_get_ns() - path_start_ns
        } else {
            0
        };
        if captured_exec {
            let _ = EXEC_PATHS.remove(&exec_task);
        }
        record_profile(
            syscall,
            profile_start_ns,
            path_reads,
            path_bytes,
            path_read_ns,
            true,
        );
    }

    entry.submit(0);
    0
}

/// Generates a `fexit` program for a traced syscall.
macro_rules! syscall_probe {
    ($name:ident, $sys:expr, $spec:expr) => {
        #[fexit]
        pub fn $name(ctx: FExitContext) -> u32 {
            handle(&ctx, $sys, $spec, false)
        }
    };
}

// --- open family ---------------------------------------------------------
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(
    sys_open,
    Syscall::Open,
    Spec::new().path1(0).flags(Flags::Arg(1))
);
syscall_probe!(
    sys_openat,
    Syscall::Openat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(2))
);
syscall_probe!(
    sys_openat2,
    Syscall::Openat2,
    Spec::new().dirfd1(0).path1(1).flags(Flags::OpenHow(2))
);
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(
    sys_creat,
    Syscall::Creat,
    Spec::new().path1(0).flags(Flags::Const(O_CREAT))
);

// stat/access/readlink probes are intentionally omitted. These metadata-heavy
// families dominate Node-style workloads while adding no opened/created path,
// matching the original tracer's production seccomp filter.

// --- delete --------------------------------------------------------------
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(sys_unlink, Syscall::Unlink, Spec::new().path1(0));
syscall_probe!(
    sys_unlinkat,
    Syscall::Unlinkat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(2))
);
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(sys_rmdir, Syscall::Rmdir, Spec::new().path1(0));

// --- rename --------------------------------------------------------------
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(sys_rename, Syscall::Rename, Spec::new().path1(0).path2(1));
syscall_probe!(
    sys_renameat,
    Syscall::Renameat,
    Spec::new().dirfd1(0).path1(1).dirfd2(2).path2(3)
);
syscall_probe!(
    sys_renameat2,
    Syscall::Renameat2,
    Spec::new().dirfd1(0).path1(1).dirfd2(2).path2(3)
);

// --- mkdir / link / symlink ---------------------------------------------
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(sys_mkdir, Syscall::Mkdir, Spec::new().path1(0));
syscall_probe!(
    sys_mkdirat,
    Syscall::Mkdirat,
    Spec::new().dirfd1(0).path1(1)
);
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(sys_link, Syscall::Link, Spec::new().path1(1));
syscall_probe!(
    sys_linkat,
    Syscall::Linkat,
    Spec::new().dirfd1(2).path1(3).flags(Flags::Arg(4))
);
#[cfg(bpf_target_arch = "x86_64")]
syscall_probe!(sys_symlink, Syscall::Symlink, Spec::new().path1(1));
syscall_probe!(
    sys_symlinkat,
    Syscall::Symlinkat,
    Spec::new().dirfd1(1).path1(2)
);

// --- truncate ------------------------------------------------------------
syscall_probe!(sys_truncate, Syscall::Truncate, Spec::new().path1(0));
// getdents/getdents64 are likewise omitted: opening the directory is already
// reported, and reporting every enumeration adds high-volume duplicate noise.

// --- cwd / exec / close --------------------------------------------------
syscall_probe!(sys_chdir, Syscall::Chdir, Spec::new().path1(0));
syscall_probe!(sys_fchdir, Syscall::Fchdir, Spec::new().dirfd1(0));
#[fentry]
pub fn enter_execve(ctx: FEntryContext) -> u32 {
    capture_exec_path(&ctx, Syscall::Execve, 0)
}

#[fexit]
pub fn sys_execve(ctx: FExitContext) -> u32 {
    handle(&ctx, Syscall::Execve, Spec::new().path1(0), true)
}

#[fentry]
pub fn enter_execveat(ctx: FEntryContext) -> u32 {
    capture_exec_path(&ctx, Syscall::Execveat, 1)
}

#[fexit]
pub fn sys_execveat(ctx: FExitContext) -> u32 {
    handle(
        &ctx,
        Syscall::Execveat,
        Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(4)),
        true,
    )
}
syscall_probe!(sys_close, Syscall::Close, Spec::new().dirfd1(0));

/// Emit a fork/exit record for routing and path-state updates.
#[inline(always)]
fn emit_lifecycle(
    kind: u32,
    pid: u32,
    task: TaskKey,
    child: TaskKey,
    group: u32,
    flags: i64,
    session: u64,
) -> bool {
    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => {
            lost();
            return false;
        }
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).session = session;
        (*ev).birth = task.birth;
        (*ev).child_birth = child.birth;
        (*ev).pid = pid;
        (*ev).tid = task.tid;
        (*ev).syscall = kind;
        (*ev).ret = child.tid as i64;
        (*ev).path_len = 0;
        (*ev).path2_len = 0;
        (*ev).dirfd = group as i64;
        (*ev).dirfd2 = 0;
        (*ev).flags = flags;
    }
    entry.submit(0);
    true
}

/// Read kernel-BTF-selected fields before the new task can run.
#[raw_tracepoint(tracepoint = "sched_process_fork")]
pub fn task_fork(ctx: RawTracePointContext) -> u32 {
    let identity = bpf_get_current_pid_tgid();
    let tgid = (identity >> 32) as u32;
    let tid = identity as u32;
    let child_task: u64 = ctx.arg(1);
    let child_pid = match unsafe { task_field::<u32>(child_task, 0) } {
        Ok(pid) => pid,
        Err(_) => {
            lost();
            return 0;
        }
    };
    let task = unsafe { bpf_get_current_task() };
    let child_group = match unsafe { task_field::<u32>(child_task, 1) } {
        Ok(group) => group,
        Err(_) => {
            lost();
            return 0;
        }
    };
    if let Some(token) = unsafe { REGISTERING_TASKS.get(&task) }.copied() {
        let _ = REGISTERING_TASKS.remove(&task);
        if let Some(mut pending) = unsafe { REGISTRATIONS.get(&token) }.copied()
            && pending.parent_task == task
            && pending.child == 0
            && child_pid == child_group
        {
            pending.child = child_pid;
            pending.child_task = child_task;
            let Ok(start) = (unsafe { task_field::<u64>(child_task, 7) }) else {
                lost();
                return 0;
            };
            pending.child_start = start;
            let Ok(cred) = (unsafe { task_field::<u64>(child_task, 5) }) else {
                lost();
                return 0;
            };
            let Ok(exec) = (unsafe { task_field::<u64>(child_task, 8) }) else {
                lost();
                return 0;
            };
            pending.child_cred = cred;
            pending.child_exec = exec;
            if REGISTRATIONS.insert(&token, &pending, 0).is_err() {
                lost();
            }
        }
    }
    let Some(key) = task_key(tid, task) else {
        return 0;
    };
    let Some(child_key) = task_key(child_pid, child_task) else {
        return 0;
    };
    let Some(session) = unsafe { TRACED.get(&key) }.copied() else {
        return 0;
    };
    let Some(_capture) = begin_capture(session) else {
        return 0;
    };
    if TRACED.insert(&child_key, &session, 1).is_err() {
        lost();
        return 0;
    }
    // Commit the fork before the child can emit syscall events.
    let shared = unsafe {
        let fs = task_field::<u64>(task, 3);
        let files = task_field::<u64>(task, 4);
        if fs.is_err() || files.is_err() {
            lost();
        }
        i64::from(fs.is_ok() && fs == task_field::<u64>(child_task, 3))
            | (i64::from(files.is_ok() && files == task_field::<u64>(child_task, 4)) << 1)
    };
    if !emit_lifecycle(
        EVENT_FORK,
        tgid,
        key,
        child_key,
        child_group,
        shared,
        session,
    ) {
        let _ = TRACED.remove(&child_key);
    }
    0
}

/// Retire only the exiting task; other threads retain their membership.
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let task = unsafe { bpf_get_current_task() };
    let _ = EXEC_PATHS.remove(&task);
    let _ = REGISTERING_TASKS.remove(&task);
    let Some(key) = task_key(tid, task) else {
        return 0;
    };
    if let Some(session) = unsafe { TRACED.get(&key) }.copied() {
        if let Some(_capture) = begin_capture(session) {
            emit_lifecycle(EVENT_EXIT, tgid, key, TaskKey::new(0, 0), 0, 0, session);
        }
        let _ = TRACED.remove(&key);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
