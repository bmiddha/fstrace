//! fstrace eBPF programs.
//!
//! A `fexit` program is attached to each traced filesystem syscall. On syscall
//! exit it reads the syscall arguments out of the saved `pt_regs`, copies the
//! raw pathname argument(s) from user memory, and pushes a fixed-size
//! [`Event`] onto a ring buffer for the userspace loader to resolve, classify
//! and report.
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
    bindings::pt_regs,
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{fexit, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{FExitContext, TracePointContext},
};
use fstrace_common::{EVENT_EXIT, EVENT_FORK, Event, PATH_MAX, Syscall};

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

/// Ring buffer carrying [`Event`]s to userspace (16 MiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Single-slot config set by the loader: slot 0 holds the `child_pid` byte
/// offset in the `sched_process_fork` record for the running kernel.
#[map]
static FORK_CFG: Array<u32> = Array::with_max_entries(1, 0);

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

/// Shared body for every traced syscall's `fexit` program.
#[inline(always)]
fn handle(ctx: &FExitContext, syscall: Syscall, spec: Spec) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if unsafe { TRACED.get(&tgid) }.is_none() {
        return 0;
    }

    // fexit args: [ *const pt_regs, return_value ].
    let regs_ptr: *const pt_regs = ctx.arg(0);
    let ret: i64 = ctx.arg(1);

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => return 0,
    };
    let ev = entry.as_mut_ptr();

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
        if let Some(i) = spec.path1 {
            let p = reg(regs_ptr, i);
            (*ev).path_len = read_user_path(p, &mut (*ev).path);
        }
        if let Some(i) = spec.path2 {
            let p = reg(regs_ptr, i);
            (*ev).path2_len = read_user_path(p, &mut (*ev).path2);
        }
    }

    entry.submit(0);
    0
}

/// Generates a `fexit` program for a traced syscall.
macro_rules! syscall_probe {
    ($name:ident, $fn:literal, $sys:expr, $spec:expr) => {
        #[fexit(function = $fn)]
        pub fn $name(ctx: FExitContext) -> u32 {
            handle(&ctx, $sys, $spec)
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

// --- stat / access family ------------------------------------------------
syscall_probe!(
    sys_newstat,
    "__x64_sys_newstat",
    Syscall::Stat,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_newlstat,
    "__x64_sys_newlstat",
    Syscall::Lstat,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_newfstatat,
    "__x64_sys_newfstatat",
    Syscall::Newfstatat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(3))
);
syscall_probe!(
    sys_statx,
    "__x64_sys_statx",
    Syscall::Statx,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(2))
);
syscall_probe!(
    sys_access,
    "__x64_sys_access",
    Syscall::Access,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_faccessat,
    "__x64_sys_faccessat",
    Syscall::Faccessat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(3))
);
syscall_probe!(
    sys_faccessat2,
    "__x64_sys_faccessat2",
    Syscall::Faccessat2,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(3))
);

// --- readlink ------------------------------------------------------------
syscall_probe!(
    sys_readlink,
    "__x64_sys_readlink",
    Syscall::Readlink,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_readlinkat,
    "__x64_sys_readlinkat",
    Syscall::Readlinkat,
    Spec::new().dirfd1(0).path1(1)
);

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

// --- truncate / dir enumeration -----------------------------------------
syscall_probe!(
    sys_truncate,
    "__x64_sys_truncate",
    Syscall::Truncate,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_getdents,
    "__x64_sys_getdents",
    Syscall::Getdents,
    Spec::new().dirfd1(0)
);
syscall_probe!(
    sys_getdents64,
    "__x64_sys_getdents64",
    Syscall::Getdents64,
    Spec::new().dirfd1(0)
);

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
syscall_probe!(
    sys_execve,
    "__x64_sys_execve",
    Syscall::Execve,
    Spec::new().path1(0)
);
syscall_probe!(
    sys_execveat,
    "__x64_sys_execveat",
    Syscall::Execveat,
    Spec::new().dirfd1(0).path1(1).flags(Flags::Arg(4))
);
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
    if tgid == tid {
        if unsafe { TRACED.get(&tgid) }.is_some() {
            emit_lifecycle(EVENT_EXIT, tgid, 0);
        }
        let _ = TRACED.remove(&tgid);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
