//! fstrace eBPF programs.
//!
//! A `fexit` program is attached to each traced filesystem syscall. On syscall
//! exit it reads the syscall arguments out of the saved `pt_regs`, copies the
//! raw pathname argument(s) from user memory, and pushes a fixed-size
//! [`Event`] onto a ring buffer for the userspace loader to resolve, classify
//! and report. Successful execs replace userspace memory before fexit runs, so
//! their pathname is saved by a paired fentry probe.
//!
//! Two tracepoints maintain the set of traced pids: `sched_process_fork` adds
//! children of traced processes, and `sched_process_exit` removes them. The
//! userspace loader seeds the map with the launched process.
#![no_std]
#![no_main]

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
    macros::{fentry, fexit, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext, TracePointContext},
};
use fstrace_common::{
    EVENT_EXIT, EVENT_FORK, EbpfProfileStat, Event, PATH_MAX, SYSCALL_COUNT, Syscall,
};

/// `O_CREAT` from `<fcntl.h>` on Linux; `creat(2)` implies it.
const O_CREAT: i64 = 0o100;

/// Byte offset of `child_pid` in the `sched_process_fork` tracepoint record
/// when `parent_comm`/`child_comm` are fixed `char[16]` fields (kernels before
/// ~6.16).
const CHILD_PID_OFFSET_LEGACY: u32 = 44;
/// Byte offset of `child_pid` when the comm fields became `__data_loc` dynamic
/// strings (Linux ~6.16+), which shrank the record. Selected at runtime from
/// [`FORK_CFG`], populated by the userspace loader from the tracepoint format.
const CHILD_PID_OFFSET_DATALOC: u32 = 20;

/// Pathname captured before a successful exec replaces the caller's address
/// space. The per-CPU scratch map keeps this PATH_MAX-sized value off the BPF
/// stack; the LRU map holds it until the paired fexit probe runs.
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecPath {
    len: u32,
    bytes: [u8; PATH_MAX],
}

/// Ring buffer carrying [`Event`]s to userspace (16 MiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Single-slot config set by the loader: slot 0 holds the `child_pid` byte
/// offset in the `sched_process_fork` record for the running kernel.
#[map]
static FORK_CFG: Array<u32> = Array::with_max_entries(1, 0);

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
static EXEC_PATHS: LruHashMap<u64, ExecPath> = LruHashMap::with_max_entries(4096, 0);

/// TGIDs currently inside exec. During a secondary thread's successful exec,
/// the old group leader exits as part of `de_thread()`; this marker prevents
/// that synthetic leader exit from ending tracing for the surviving process.
#[map]
static EXECING_TGIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(4096, 0);

/// Set of thread-group ids (pids) currently being traced.
#[map]
static TRACED: HashMap<u32, u8> = HashMap::with_max_entries(65536, 0);

/// Where a syscall's open-style flags come from.
#[derive(Clone, Copy)]
enum Flags {
    /// No meaningful flags for this syscall.
    None,
    /// Flags are the `pt_regs` argument at this index.
    Arg(u8),
    /// Flags are a fixed constant (e.g. `creat` implies `O_CREAT`).
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

/// Reads the `idx`th syscall argument register out of the kernel `pt_regs`.
///
/// The registers follow each architecture's **syscall** calling convention. On
/// x86-64 that is `rdi, rsi, rdx, r10, r8, r9` (note `r10`, not `rcx`, in the
/// 4th slot). On aarch64 the first six general registers `x0..x5` carry the
/// arguments, read out of the `user_pt_regs.regs` array. `pt_regs` lives in
/// kernel memory, so each field is fetched with `bpf_probe_read_kernel`.
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
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if unsafe { TRACED.get(&tgid) }.is_none() {
        return 0;
    }
    if tid != tgid {
        // sched_process_fork initially seeds both process IDs and thread IDs.
        // A secondary thread that execs adopts the TGID without producing an
        // exit under its old TID, so retire that otherwise-stale key now.
        let _ = TRACED.remove(&tid);
    }

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
        let path_ptr = reg(regs_ptr, path_arg);
        (*scratch).len = read_user_path(path_ptr, &mut (*scratch).bytes);
        let path_read_ns = if path_start_ns != 0 {
            bpf_ktime_get_ns() - path_start_ns
        } else {
            0
        };
        let task = bpf_get_current_task();
        let _ = EXEC_PATHS.insert(&task, &*scratch, 0);
        let _ = EXECING_TGIDS.insert(&tgid, &1, 0);
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

    if unsafe { TRACED.get(&tgid) }.is_none() {
        if captured_exec {
            let _ = EXEC_PATHS.remove(&exec_task);
            let _ = EXECING_TGIDS.remove(&tgid);
        }
        return 0;
    }
    let profile_start_ns = profile_start();

    // fexit args: [ *const pt_regs, return_value ].
    let regs_ptr: *const pt_regs = ctx.arg(0);
    let ret: i64 = ctx.arg(1);

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => {
            if captured_exec {
                let _ = EXEC_PATHS.remove(&exec_task);
                let _ = EXECING_TGIDS.remove(&tgid);
            }
            record_profile(syscall, profile_start_ns, 0, 0, 0, false);
            return 0;
        }
    };
    let ev = entry.as_mut_ptr();
    let mut path_reads = 0;
    let mut path_bytes = 0;

    unsafe {
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
            let _ = EXECING_TGIDS.remove(&tgid);
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
    ($name:ident, $fn:literal, $sys:expr, $spec:expr) => {
        #[fexit(function = $fn)]
        pub fn $name(ctx: FExitContext) -> u32 {
            handle(&ctx, $sys, $spec, false)
        }
    };
}

// --- open family ---------------------------------------------------------
syscall_probe!(
    sys_open,
    "__x64_sys_open",
    Syscall::Open,
    Spec::new().path1(0).flags(Flags::Arg(1))
);
syscall_probe!(
    sys_openat,
    "__x64_sys_openat",
    Syscall::Openat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(2))
);
syscall_probe!(
    sys_openat2,
    "__x64_sys_openat2",
    Syscall::Openat2,
    Spec::new().dirfd1(0).path1(1).flags(Flags::OpenHow(2))
);
syscall_probe!(
    sys_creat,
    "__x64_sys_creat",
    Syscall::Creat,
    Spec::new().path1(0).flags(Flags::Const(O_CREAT))
);

// stat/access/readlink probes are intentionally omitted. These metadata-heavy
// families dominate Node-style workloads while adding no opened/created path,
// matching the original tracer's production seccomp filter.

// --- delete --------------------------------------------------------------
syscall_probe!(
    sys_unlink,
    "__x64_sys_unlink",
    Syscall::Unlink,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_unlinkat,
    "__x64_sys_unlinkat",
    Syscall::Unlinkat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(2))
);
syscall_probe!(
    sys_rmdir,
    "__x64_sys_rmdir",
    Syscall::Rmdir,
    Spec::new().path1(0)
);

// --- rename --------------------------------------------------------------
syscall_probe!(
    sys_rename,
    "__x64_sys_rename",
    Syscall::Rename,
    Spec::new().path1(0).path2(1)
);
syscall_probe!(
    sys_renameat,
    "__x64_sys_renameat",
    Syscall::Renameat,
    Spec::new().dirfd1(0).path1(1).dirfd2(2).path2(3)
);
syscall_probe!(
    sys_renameat2,
    "__x64_sys_renameat2",
    Syscall::Renameat2,
    Spec::new().dirfd1(0).path1(1).dirfd2(2).path2(3)
);

// --- mkdir / link / symlink ---------------------------------------------
syscall_probe!(
    sys_mkdir,
    "__x64_sys_mkdir",
    Syscall::Mkdir,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_mkdirat,
    "__x64_sys_mkdirat",
    Syscall::Mkdirat,
    Spec::new().dirfd1(0).path1(1)
);
syscall_probe!(
    sys_link,
    "__x64_sys_link",
    Syscall::Link,
    Spec::new().path1(1)
);
syscall_probe!(
    sys_linkat,
    "__x64_sys_linkat",
    Syscall::Linkat,
    Spec::new().dirfd1(2).path1(3).flags(Flags::Arg(4))
);
syscall_probe!(
    sys_symlink,
    "__x64_sys_symlink",
    Syscall::Symlink,
    Spec::new().path1(1)
);
syscall_probe!(
    sys_symlinkat,
    "__x64_sys_symlinkat",
    Syscall::Symlinkat,
    Spec::new().dirfd1(1).path1(2)
);

// --- truncate ------------------------------------------------------------
syscall_probe!(
    sys_truncate,
    "__x64_sys_truncate",
    Syscall::Truncate,
    Spec::new().path1(0)
);
// getdents/getdents64 are likewise omitted: opening the directory is already
// reported, and reporting every enumeration adds high-volume duplicate noise.

// --- cwd / exec / close --------------------------------------------------
syscall_probe!(
    sys_chdir,
    "__x64_sys_chdir",
    Syscall::Chdir,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_fchdir,
    "__x64_sys_fchdir",
    Syscall::Fchdir,
    Spec::new().dirfd1(0)
);
#[fentry(function = "__x64_sys_execve")]
pub fn enter_execve(ctx: FEntryContext) -> u32 {
    capture_exec_path(&ctx, Syscall::Execve, 0)
}

#[fexit(function = "__x64_sys_execve")]
pub fn sys_execve(ctx: FExitContext) -> u32 {
    handle(&ctx, Syscall::Execve, Spec::new().path1(0), true)
}

#[fentry(function = "__x64_sys_execveat")]
pub fn enter_execveat(ctx: FEntryContext) -> u32 {
    capture_exec_path(&ctx, Syscall::Execveat, 1)
}

#[fexit(function = "__x64_sys_execveat")]
pub fn sys_execveat(ctx: FExitContext) -> u32 {
    handle(
        &ctx,
        Syscall::Execveat,
        Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(4)),
        true,
    )
}
syscall_probe!(
    sys_close,
    "__x64_sys_close",
    Syscall::Close,
    Spec::new().dirfd1(0)
);

/// Emits a minimal lifecycle event (fork/exit) into the ring buffer so the
/// userspace daemon can maintain its pid→client routing table. `kind` is
/// [`EVENT_FORK`] or [`EVENT_EXIT`]; `child` is the new child pid for forks.
#[inline(always)]
fn emit_lifecycle(kind: u32, pid: u32, child: u32) {
    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => return,
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = pid;
        (*ev).tid = pid;
        (*ev).syscall = kind;
        (*ev).ret = child as i64;
        (*ev).path_len = 0;
        (*ev).path2_len = 0;
        (*ev).dirfd = 0;
        (*ev).dirfd2 = 0;
        (*ev).flags = 0;
    }
    entry.submit(0);
}

/// `sched_process_fork`: if the parent is traced, start tracing the child.
///
/// The `child_pid` field offset is not stable across kernels: when the comm
/// fields became `__data_loc` strings (~6.16) it moved from byte 44 to 20. The
/// loader detects the offset from the tracepoint format and stores it in
/// [`FORK_CFG`]; we branch on it so each `read_at` still uses a constant offset
/// (required by the verifier).
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { TRACED.get(&tgid) }.is_none() {
        return 0;
    }
    let off = FORK_CFG.get(0).copied().unwrap_or(CHILD_PID_OFFSET_LEGACY);
    let read = if off == CHILD_PID_OFFSET_DATALOC {
        unsafe { ctx.read_at::<i32>(CHILD_PID_OFFSET_DATALOC as usize) }
    } else {
        unsafe { ctx.read_at::<i32>(CHILD_PID_OFFSET_LEGACY as usize) }
    };
    let child_pid: i32 = match read {
        Ok(pid) => pid,
        Err(_) => return 0,
    };
    let _ = TRACED.insert(&(child_pid as u32), &1, 0);
    // Tell the daemon which client owns the new child (fork event is committed
    // before the child runs, so it precedes the child's own syscall events).
    emit_lifecycle(EVENT_FORK, tgid, child_pid as u32);
    0
}

/// `sched_process_exit`: stop tracing a process once its group leader exits.
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let task = unsafe { bpf_get_current_task() };
    let exiting_exec_task = unsafe { EXEC_PATHS.get(&task) }.is_some();
    let _ = EXEC_PATHS.remove(&task);
    if exiting_exec_task {
        // The exec'ing task itself died before fexit could clear its marker.
        // This is a real exit, not the old leader retired by de_thread().
        let _ = EXECING_TGIDS.remove(&tgid);
    }
    if tgid == tid {
        if !exiting_exec_task && unsafe { EXECING_TGIDS.get(&tgid) }.is_some() {
            return 0;
        }
        if unsafe { TRACED.get(&tgid) }.is_some() {
            emit_lifecycle(EVENT_EXIT, tgid, 0);
        }
        let _ = TRACED.remove(&tgid);
    } else {
        // sched_process_fork cannot distinguish a process from a thread and
        // initially seeds both child IDs. A non-leader exit can safely discard
        // that unused TID key without affecting the process's TGID key.
        let _ = TRACED.remove(&tid);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
