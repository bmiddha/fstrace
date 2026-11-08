//! Abstraction over the host facilities the engine needs (`/proc` lookups and
//! `stat`). The trait keeps [`crate::engine::Engine`] testable with mock
//! providers. Production path bases use captured state only.

use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

use fstrace_common::FileType;

/// Result of a `stat`-style lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatResult {
    /// The path exists; carries its [`FileType`] (`Directory`, `File`, or
    /// `Unknown` for other object kinds).
    Type(FileType),
    /// The path does not exist (`ENOENT`/`ENOTDIR`/`EBADF`).
    Missing,
    /// The stat failed for some other reason (e.g. `EACCES`).
    Error,
}

/// Host facilities used to resolve and classify paths.
pub trait System {
    /// Optional live cwd fallback for library callers.
    fn cwd(&self, pid: u32) -> Option<String>;
    /// Optional live FD path fallback for library callers.
    fn fd_path(&self, pid: u32, fd: i64) -> Option<String>;
    /// `stat(2)` the path, following symlinks, returning its type / existence.
    fn stat_type(&self, path: &str) -> StatResult;
}

/// Best-effort live lookups for library callers; not event-time or namespace-safe.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSystem;

/// Never guesses path bases from asynchronous, namespace-dependent `/proc` IDs.
#[derive(Debug, Default, Clone, Copy)]
pub struct CapturedSystem;

impl System for CapturedSystem {
    fn cwd(&self, _: u32) -> Option<String> {
        None
    }
    fn fd_path(&self, _: u32, _: i64) -> Option<String> {
        None
    }
    fn stat_type(&self, path: &str) -> StatResult {
        RealSystem.stat_type(path)
    }
}

fn file_type_from_mode(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFREG => FileType::File,
        libc::S_IFLNK => FileType::Symlink,
        _ => FileType::Unknown,
    }
}

impl System for RealSystem {
    fn cwd(&self, pid: u32) -> Option<String> {
        let link = PathBuf::from(format!("/proc/{pid}/cwd"));
        fs::read_link(link)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn fd_path(&self, pid: u32, fd: i64) -> Option<String> {
        if fd < 0 {
            return None;
        }
        let link = PathBuf::from(format!("/proc/{pid}/fd/{fd}"));
        fs::read_link(link)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn stat_type(&self, path: &str) -> StatResult {
        match fs::metadata(path) {
            Ok(meta) => StatResult::Type(file_type_from_mode(meta.mode())),
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ENOTDIR) | Some(libc::EBADF) => StatResult::Missing,
                _ => StatResult::Error,
            },
        }
    }
}
