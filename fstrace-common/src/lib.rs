//! Types shared between the eBPF programs (`fstrace-ebpf`) and the userspace
//! loader (`fstrace`).
//!
//! The crate is `#![no_std]` so it can be compiled for the `bpfel-unknown-none`
//! target. When built with the `user` feature it additionally implements
//! [`aya::Pod`] for [`Event`] so the loader can read events directly out of the
//! ring buffer.
#![cfg_attr(not(test), no_std)]

/// Maximum length of a captured path, matching `PATH_MAX` on Linux.
pub const PATH_MAX: usize = 4096;

/// Sentinel used by the `*at` family of syscalls to mean "relative to the
/// current working directory". Mirrors `AT_FDCWD` from `<fcntl.h>`.
pub const AT_FDCWD: i64 = -100;

/// Pseudo-`syscall` value marking a process-fork lifecycle event. For these
/// events [`Event::pid`] is the parent and [`Event::ret`] carries the child
/// pid. Used by the daemon to route a child's events to the parent's client.
/// The value is deliberately outside the real [`Syscall`] discriminant range.
pub const EVENT_FORK: u32 = 0xFFFF_0001;

/// Pseudo-`syscall` value marking a process-exit lifecycle event. For these
/// events [`Event::pid`] is the exiting process. Used by the daemon to drop the
/// pid from its routing table.
pub const EVENT_EXIT: u32 = 0xFFFF_0002;

/// The set of syscalls fstrace traces.
///
/// The discriminants are stable wire values written into [`Event::syscall`] by
/// the eBPF programs and decoded by the userspace loader via
/// [`Syscall::from_u32`].
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Syscall {
    Open = 0,
    Openat = 1,
    Openat2 = 2,
    Creat = 3,
    Stat = 4,
    Lstat = 5,
    Newfstatat = 6,
    Statx = 7,
    Access = 8,
    Faccessat = 9,
    Faccessat2 = 10,
    Readlink = 11,
    Readlinkat = 12,
    Unlink = 13,
    Unlinkat = 14,
    Rmdir = 15,
    Rename = 16,
    Renameat = 17,
    Renameat2 = 18,
    Mkdir = 19,
    Mkdirat = 20,
    Link = 21,
    Linkat = 22,
    Symlink = 23,
    Symlinkat = 24,
    Truncate = 25,
    Getdents = 26,
    Getdents64 = 27,
    Chdir = 28,
    Fchdir = 29,
    Execve = 30,
    Execveat = 31,
    Close = 32,
}

impl Syscall {
    /// Decodes a wire value written by the eBPF side back into a [`Syscall`].
    pub fn from_u32(value: u32) -> Option<Self> {
        use Syscall::*;
        let syscall = match value {
            0 => Open,
            1 => Openat,
            2 => Openat2,
            3 => Creat,
            4 => Stat,
            5 => Lstat,
            6 => Newfstatat,
            7 => Statx,
            8 => Access,
            9 => Faccessat,
            10 => Faccessat2,
            11 => Readlink,
            12 => Readlinkat,
            13 => Unlink,
            14 => Unlinkat,
            15 => Rmdir,
            16 => Rename,
            17 => Renameat,
            18 => Renameat2,
            19 => Mkdir,
            20 => Mkdirat,
            21 => Link,
            22 => Linkat,
            23 => Symlink,
            24 => Symlinkat,
            25 => Truncate,
            26 => Getdents,
            27 => Getdents64,
            28 => Chdir,
            29 => Fchdir,
            30 => Execve,
            31 => Execveat,
            32 => Close,
            _ => return None,
        };
        Some(syscall)
    }
}

/// How a path was accessed. Serialised as the first output character.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AccessType {
    /// `R` — read.
    Read,
    /// `W` — write / create.
    Write,
    /// `D` — delete.
    Delete,
    /// `E` — enumerate (directory listing).
    Enumerate,
}

impl AccessType {
    /// The single-character code used in fstrace output.
    pub fn code(self) -> u8 {
        match self {
            AccessType::Read => b'R',
            AccessType::Write => b'W',
            AccessType::Delete => b'D',
            AccessType::Enumerate => b'E',
        }
    }
}

/// The kind of filesystem object a path referred to. Serialised as the second
/// output character.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileType {
    /// `F` — regular file.
    File,
    /// `D` — directory.
    Directory,
    /// `X` — does not exist.
    Missing,
    /// `L` — symbolic link.
    Symlink,
    /// `?` — unknown / unresolved.
    Unknown,
}

impl FileType {
    /// The single-character code used in fstrace output.
    pub fn code(self) -> u8 {
        match self {
            FileType::File => b'F',
            FileType::Directory => b'D',
            FileType::Missing => b'X',
            FileType::Symlink => b'L',
            FileType::Unknown => b'?',
        }
    }
}

/// A single traced syscall exit, produced in the kernel and consumed by the
/// loader. Path buffers hold the raw (possibly relative) userspace pathname
/// arguments; resolution against the process cwd / dirfd happens in userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    /// Thread group id (process id) of the tracee.
    pub pid: u32,
    /// Thread id of the tracee.
    pub tid: u32,
    /// Which syscall this event describes (a [`Syscall`] discriminant).
    pub syscall: u32,
    /// Length of valid bytes in [`Event::path`].
    pub path_len: u32,
    /// Length of valid bytes in [`Event::path2`].
    pub path2_len: u32,
    /// Syscall return value (negative errno on failure).
    pub ret: i64,
    /// Primary directory fd for `*at` syscalls, or a plain fd for
    /// `close`/`fchdir`/`getdents`. Unused syscalls set this to 0.
    pub dirfd: i64,
    /// Secondary directory fd for `renameat`/`linkat`.
    pub dirfd2: i64,
    /// Open/at flags (for `open`, `openat`, `openat2`, stat/access `*at`).
    pub flags: i64,
    /// First raw pathname argument.
    pub path: [u8; PATH_MAX],
    /// Second raw pathname argument (rename/link old vs new path).
    pub path2: [u8; PATH_MAX],
}

impl Event {
    /// A fully zeroed event, used as scratch space before population.
    pub const fn zeroed() -> Self {
        Event {
            pid: 0,
            tid: 0,
            syscall: 0,
            path_len: 0,
            path2_len: 0,
            ret: 0,
            dirfd: 0,
            dirfd2: 0,
            flags: 0,
            path: [0; PATH_MAX],
            path2: [0; PATH_MAX],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_roundtrips_through_u32() {
        for value in 0..=32u32 {
            let syscall = Syscall::from_u32(value).expect("known discriminant");
            assert_eq!(syscall as u32, value);
        }
        assert_eq!(Syscall::from_u32(33), None);
        assert_eq!(Syscall::from_u32(u32::MAX), None);
    }

    #[test]
    fn access_type_codes() {
        assert_eq!(AccessType::Read.code(), b'R');
        assert_eq!(AccessType::Write.code(), b'W');
        assert_eq!(AccessType::Delete.code(), b'D');
        assert_eq!(AccessType::Enumerate.code(), b'E');
    }

    #[test]
    fn file_type_codes() {
        assert_eq!(FileType::File.code(), b'F');
        assert_eq!(FileType::Directory.code(), b'D');
        assert_eq!(FileType::Missing.code(), b'X');
        assert_eq!(FileType::Symlink.code(), b'L');
        assert_eq!(FileType::Unknown.code(), b'?');
    }
}
