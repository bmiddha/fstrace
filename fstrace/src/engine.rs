//! The tracing engine: turns raw syscall-exit [`Event`]s into resolved,
//! classified filesystem-access reports, mirroring the original C
//! implementation's semantics.
//!
//! Path resolution (cwd / dirfd) is delegated to a [`System`] provider so the
//! logic can be unit-tested against mocks.

use std::collections::HashMap;

use fstrace_common::{AT_FDCWD, AccessType, Event, FileType, PATH_MAX, Syscall};

use crate::{
    pathnorm::normalize_path,
    proc::{StatResult, System},
};

// Open flags (subset used for classification).
const O_WRONLY: i64 = 0o1;
const O_RDWR: i64 = 0o2;
const O_CREAT: i64 = 0o100;
const O_DIRECTORY: i64 = 0o200000;

/// A single classified filesystem access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub access: AccessType,
    pub file: FileType,
    pub path: String,
}

impl Access {
    fn new(access: AccessType, file: FileType, path: String) -> Self {
        Access { access, file, path }
    }
}

/// The set of accesses produced by one syscall, plus the path used to decide
/// whether the whole event is reported (the filter is applied once, to the
/// primary path, matching the original behaviour).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emit {
    pub filter_path: String,
    pub accesses: Vec<Access>,
}

/// Stateful engine holding per-pid cwd / fd caches and a [`System`] provider.
pub struct Engine<S: System> {
    sys: S,
    cwd_cache: HashMap<u32, String>,
    fd_cache: HashMap<(u32, i64), String>,
}

fn errno_is_missing(errno: i32) -> bool {
    errno == libc::ENOENT || errno == libc::ENOTDIR || errno == libc::EBADF
}

fn cstr(buf: &[u8; PATH_MAX], len: u32) -> String {
    let len = (len as usize).min(PATH_MAX);
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

impl<S: System> Engine<S> {
    /// Creates an engine backed by `sys`.
    pub fn new(sys: S) -> Self {
        Engine {
            sys,
            cwd_cache: HashMap::new(),
            fd_cache: HashMap::new(),
        }
    }

    fn get_cwd(&mut self, pid: u32) -> String {
        if let Some(cwd) = self.cwd_cache.get(&pid) {
            return cwd.clone();
        }
        let cwd = self.sys.cwd(pid).unwrap_or_default();
        // Don't cache an empty result: the process may simply have exited before
        // we could read `/proc/<pid>/cwd`; a later `chdir` event (or retry) can
        // still populate it correctly.
        if !cwd.is_empty() {
            self.cwd_cache.insert(pid, cwd.clone());
        }
        cwd
    }

    /// Seeds the cwd cache for `pid` (used to record the launched process's
    /// initial working directory, which it inherits from the launcher).
    pub fn seed_cwd(&mut self, pid: u32, cwd: String) {
        self.cwd_cache.insert(pid, cwd);
    }

    fn get_fd(&mut self, pid: u32, fd: i64) -> Option<String> {
        if let Some(path) = self.fd_cache.get(&(pid, fd)) {
            return Some(path.clone());
        }
        let path = self.sys.fd_path(pid, fd);
        if let Some(ref p) = path {
            self.fd_cache.insert((pid, fd), p.clone());
        }
        path
    }

    /// Resolves a path that is relative to the process cwd (non-`*at` syscalls).
    fn resolve_cwd_relative(&mut self, pid: u32, raw: &str) -> String {
        if raw.starts_with('/') {
            return raw.to_string();
        }
        let cwd = self.get_cwd(pid);
        if raw == "." {
            cwd
        } else if let Some(rest) = raw.strip_prefix('.') {
            if rest.starts_with('/') {
                format!("{cwd}{rest}")
            } else {
                format!("{cwd}/{raw}")
            }
        } else {
            format!("{cwd}/{raw}")
        }
    }

    /// Resolves a path relative to a directory fd, normalising the result.
    fn resolve_dirfd(&mut self, pid: u32, dirfd: i64, raw: &str) -> String {
        if raw.starts_with('/') {
            return raw.to_string();
        }
        let dirpath = self.get_fd(pid, dirfd).unwrap_or_default();
        let full = if raw.is_empty() {
            dirpath
        } else {
            format!("{dirpath}/{raw}")
        };
        normalize_path(&full)
    }

    /// Resolves an `*at` path, honouring `AT_FDCWD`.
    fn resolve_at(&mut self, pid: u32, dirfd: i64, raw: &str) -> String {
        if dirfd == AT_FDCWD {
            self.resolve_cwd_relative(pid, raw)
        } else {
            self.resolve_dirfd(pid, dirfd, raw)
        }
    }

    /// Processes one syscall-exit event, returning the accesses it produced (if
    /// any) along with the path used for filtering. Also maintains the cwd / fd
    /// caches as a side effect.
    pub fn process(&mut self, ev: &Event) -> Option<Emit> {
        let syscall = Syscall::from_u32(ev.syscall)?;
        let pid = ev.pid;
        let ret = ev.ret;
        let is_err = ret < 0;
        let errno = if is_err { (-ret) as i32 } else { 0 };
        let missing = errno_is_missing(errno);
        let raw1 = cstr(&ev.path, ev.path_len);
        let raw2 = cstr(&ev.path2, ev.path2_len);
        tracing::debug!(?syscall, pid, ret, dirfd = ev.dirfd, raw1 = %raw1, raw2 = %raw2, "event");

        use Syscall::*;
        match syscall {
            // --- state-only syscalls (no output) ---------------------------
            Close => {
                self.fd_cache.remove(&(pid, ev.dirfd));
                None
            }
            Chdir => {
                if !is_err {
                    let path = self.resolve_cwd_relative(pid, &raw1);
                    self.cwd_cache.insert(pid, path);
                }
                None
            }
            Fchdir => {
                if !is_err && let Some(path) = self.get_fd(pid, ev.dirfd) {
                    self.cwd_cache.insert(pid, path);
                }
                None
            }

            // --- open family ----------------------------------------------
            Open | Openat | Openat2 | Creat => {
                let path = match syscall {
                    Open | Creat => self.resolve_cwd_relative(pid, &raw1),
                    _ => self.resolve_at(pid, ev.dirfd, &raw1),
                };
                if !is_err {
                    self.fd_cache.insert((pid, ret), path.clone());
                }
                if syscall == Creat {
                    if is_err {
                        return None;
                    }
                    return Some(single(AccessType::Write, FileType::File, path));
                }

                let flags = ev.flags;
                let access = if flags & O_WRONLY != 0 || flags & O_RDWR != 0 || flags & O_CREAT != 0
                {
                    AccessType::Write
                } else {
                    AccessType::Read
                };
                let mut file = if flags & O_DIRECTORY != 0 {
                    FileType::Directory
                } else {
                    FileType::File
                };
                if file == FileType::File && access == AccessType::Read && !is_err {
                    if path.ends_with('/') {
                        file = FileType::Directory;
                    }
                } else if is_err {
                    if errno == libc::EISDIR {
                        file = FileType::Directory;
                    } else if missing {
                        file = FileType::Missing;
                    } else {
                        return None;
                    }
                }
                Some(single(access, file, path))
            }

            // --- stat / access family (success => unknown type) -----------
            Stat | Lstat | Access => {
                let path = self.resolve_cwd_relative(pid, &raw1);
                self.stat_like(is_err, missing, path)
            }
            Newfstatat | Statx | Faccessat | Faccessat2 => {
                let path = self.resolve_at(pid, ev.dirfd, &raw1);
                self.stat_like(is_err, missing, path)
            }

            // --- readlink -------------------------------------------------
            Readlink | Readlinkat => {
                let path = if syscall == Readlink {
                    self.resolve_cwd_relative(pid, &raw1)
                } else {
                    self.resolve_at(pid, ev.dirfd, &raw1)
                };
                let file = if is_err {
                    if missing {
                        FileType::Missing
                    } else {
                        return None;
                    }
                } else {
                    FileType::Symlink
                };
                Some(single(AccessType::Read, file, path))
            }

            // --- delete ---------------------------------------------------
            Unlink | Unlinkat => {
                let path = if syscall == Unlink {
                    self.resolve_cwd_relative(pid, &raw1)
                } else {
                    self.resolve_at(pid, ev.dirfd, &raw1)
                };
                if is_err {
                    return None;
                }
                Some(single(AccessType::Delete, FileType::Missing, path))
            }
            Rmdir => {
                let path = self.resolve_cwd_relative(pid, &raw1);
                if is_err {
                    return None;
                }
                Some(single(AccessType::Delete, FileType::Missing, path))
            }

            // --- rename ---------------------------------------------------
            Rename | Renameat | Renameat2 => {
                if is_err {
                    return None;
                }
                let (old, new) = if syscall == Rename {
                    (
                        self.resolve_cwd_relative(pid, &raw1),
                        self.resolve_cwd_relative(pid, &raw2),
                    )
                } else {
                    (
                        self.resolve_at(pid, ev.dirfd, &raw1),
                        self.resolve_at(pid, ev.dirfd2, &raw2),
                    )
                };
                Some(rename_emit(old, new))
            }

            // --- directory enumeration ------------------------------------
            Getdents | Getdents64 => {
                let path = self.get_fd(pid, ev.dirfd).unwrap_or_default();
                let file = if is_err {
                    if missing {
                        FileType::Missing
                    } else {
                        return None;
                    }
                } else {
                    FileType::Directory
                };
                Some(single(AccessType::Enumerate, file, path))
            }

            // --- symlink / link -------------------------------------------
            Symlink | Symlinkat => {
                let path = if syscall == Symlink {
                    self.resolve_cwd_relative(pid, &raw1)
                } else {
                    self.resolve_at(pid, ev.dirfd, &raw1)
                };
                if is_err {
                    return None;
                }
                Some(single(AccessType::Write, FileType::Symlink, path))
            }
            Link | Linkat => {
                let path = if syscall == Link {
                    self.resolve_cwd_relative(pid, &raw1)
                } else {
                    self.resolve_at(pid, ev.dirfd, &raw1)
                };
                if is_err {
                    return None;
                }
                Some(single(AccessType::Write, FileType::File, path))
            }

            // --- mkdir ----------------------------------------------------
            Mkdir | Mkdirat => {
                let path = if syscall == Mkdir {
                    self.resolve_cwd_relative(pid, &raw1)
                } else {
                    self.resolve_at(pid, ev.dirfd, &raw1)
                };
                if is_err {
                    return None;
                }
                Some(single(AccessType::Write, FileType::Directory, path))
            }

            // --- truncate (stat to determine type on success) -------------
            Truncate => {
                let path = self.resolve_cwd_relative(pid, &raw1);
                let mut file = FileType::Unknown;
                if is_err {
                    if missing {
                        file = FileType::Missing;
                    } else {
                        return None;
                    }
                }
                if file == FileType::Unknown {
                    match self.sys.stat_type(&path) {
                        StatResult::Type(t) => file = t,
                        StatResult::Missing => file = FileType::Missing,
                        StatResult::Error => {}
                    }
                }
                Some(single(AccessType::Write, file, path))
            }

            // --- exec -----------------------------------------------------
            Execve | Execveat => {
                let path = if syscall == Execve {
                    self.resolve_cwd_relative(pid, &raw1)
                } else {
                    self.resolve_at(pid, ev.dirfd, &raw1)
                };
                let file = if is_err {
                    if missing {
                        FileType::Missing
                    } else {
                        return None;
                    }
                } else {
                    FileType::File
                };
                Some(single(AccessType::Read, file, path))
            }
        }
    }

    /// Shared classification for the stat / access family: read access, whose
    /// file type is `Missing` on a not-found error, `Unknown` on success, and
    /// which is skipped entirely on any other error.
    fn stat_like(&mut self, is_err: bool, missing: bool, path: String) -> Option<Emit> {
        let file = if is_err {
            if missing {
                FileType::Missing
            } else {
                return None;
            }
        } else {
            FileType::Unknown
        };
        Some(single(AccessType::Read, file, path))
    }
}

fn single(access: AccessType, file: FileType, path: String) -> Emit {
    let path = normalize_path(&path);
    Emit {
        filter_path: path.clone(),
        accesses: vec![Access::new(access, file, path)],
    }
}

/// Builds the two-access [`Emit`] for a successful rename: the old path is
/// deleted and the new path is written. Filtering keys on the new path.
fn rename_emit(old: String, new: String) -> Emit {
    let old = normalize_path(&old);
    let new = normalize_path(&new);
    Emit {
        filter_path: new.clone(),
        accesses: vec![
            Access::new(AccessType::Delete, FileType::Missing, old),
            Access::new(AccessType::Write, FileType::Unknown, new),
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A [`System`] backed by in-memory maps.
    #[derive(Default)]
    struct MockSystem {
        cwd: HashMap<u32, String>,
        fds: HashMap<(u32, i64), String>,
        stats: HashMap<String, StatResult>,
    }

    impl System for MockSystem {
        fn cwd(&self, pid: u32) -> Option<String> {
            self.cwd.get(&pid).cloned()
        }
        fn fd_path(&self, pid: u32, fd: i64) -> Option<String> {
            self.fds.get(&(pid, fd)).cloned()
        }
        fn stat_type(&self, path: &str) -> StatResult {
            self.stats.get(path).copied().unwrap_or(StatResult::Missing)
        }
    }

    fn event(syscall: Syscall) -> Event {
        let mut ev = Event::zeroed();
        ev.pid = 1000;
        ev.tid = 1000;
        ev.syscall = syscall as u32;
        ev
    }

    fn set_path(ev: &mut Event, raw: &str) {
        let bytes = raw.as_bytes();
        ev.path[..bytes.len()].copy_from_slice(bytes);
        ev.path_len = bytes.len() as u32;
    }

    fn set_path2(ev: &mut Event, raw: &str) {
        let bytes = raw.as_bytes();
        ev.path2[..bytes.len()].copy_from_slice(bytes);
        ev.path2_len = bytes.len() as u32;
    }

    fn engine() -> Engine<MockSystem> {
        Engine::new(MockSystem::default())
    }

    #[test]
    fn open_absolute_read_file() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/etc/hosts");
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses,
            vec![Access::new(
                AccessType::Read,
                FileType::File,
                "/etc/hosts".into()
            )]
        );
    }

    #[test]
    fn open_write_flag_marks_write() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/tmp/out");
        ev.flags = O_WRONLY;
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].access, AccessType::Write);
        assert_eq!(emit.accesses[0].file, FileType::File);
    }

    #[test]
    fn open_directory_flag() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/tmp");
        ev.flags = O_DIRECTORY;
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Directory);
    }

    #[test]
    fn open_trailing_slash_read_is_directory() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/tmp/dir/");
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Directory);
    }

    #[test]
    fn open_enoent_is_missing() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/nope");
        ev.ret = -libc::ENOENT as i64;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Missing);
    }

    #[test]
    fn open_eisdir_is_directory() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/somedir");
        ev.flags = O_WRONLY;
        ev.ret = -libc::EISDIR as i64;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Directory);
    }

    #[test]
    fn open_other_error_skipped() {
        let mut e = engine();
        let mut ev = event(Syscall::Open);
        set_path(&mut ev, "/denied");
        ev.ret = -libc::EACCES as i64;
        assert!(e.process(&ev).is_none());
    }

    #[test]
    fn openat_uses_dirfd_from_cache() {
        let mut sys = MockSystem::default();
        sys.fds.insert((1000, 7), "/base/dir".into());
        let mut e = Engine::new(sys);
        let mut ev = event(Syscall::Openat);
        ev.dirfd = 7;
        set_path(&mut ev, "child.txt");
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].path, "/base/dir/child.txt");
    }

    #[test]
    fn openat_at_fdcwd_uses_cwd() {
        let mut sys = MockSystem::default();
        sys.cwd.insert(1000, "/work".into());
        let mut e = Engine::new(sys);
        let mut ev = event(Syscall::Openat);
        ev.dirfd = AT_FDCWD;
        set_path(&mut ev, "rel.txt");
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].path, "/work/rel.txt");
    }

    #[test]
    fn openat_dirfd_relative_is_normalized() {
        let mut sys = MockSystem::default();
        sys.fds.insert((1000, 7), "/base/dir".into());
        let mut e = Engine::new(sys);
        let mut ev = event(Syscall::Openat);
        ev.dirfd = 7;
        set_path(&mut ev, "../sibling/./x");
        ev.ret = 3;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].path, "/base/sibling/x");
    }

    #[test]
    fn creat_success_write_file_and_caches_fd() {
        let mut e = engine();
        let mut ev = event(Syscall::Creat);
        set_path(&mut ev, "/tmp/new");
        ev.ret = 5;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses,
            vec![Access::new(
                AccessType::Write,
                FileType::File,
                "/tmp/new".into()
            )]
        );
        // fd 5 should now resolve to the created path.
        assert_eq!(e.get_fd(1000, 5).as_deref(), Some("/tmp/new"));
    }

    #[test]
    fn creat_error_skipped() {
        let mut e = engine();
        let mut ev = event(Syscall::Creat);
        set_path(&mut ev, "/tmp/new");
        ev.ret = -libc::EACCES as i64;
        assert!(e.process(&ev).is_none());
    }

    #[test]
    fn stat_success_is_unknown_type() {
        let mut e = engine();
        let mut ev = event(Syscall::Stat);
        set_path(&mut ev, "/etc/hosts");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Read, FileType::Unknown, "/etc/hosts".into())
        );
    }

    #[test]
    fn stat_missing() {
        let mut e = engine();
        let mut ev = event(Syscall::Stat);
        set_path(&mut ev, "/nope");
        ev.ret = -libc::ENOENT as i64;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Missing);
    }

    #[test]
    fn access_other_error_skipped() {
        let mut e = engine();
        let mut ev = event(Syscall::Access);
        set_path(&mut ev, "/x");
        ev.ret = -libc::EACCES as i64;
        assert!(e.process(&ev).is_none());
    }

    #[test]
    fn readlink_success_is_symlink() {
        let mut e = engine();
        let mut ev = event(Syscall::Readlink);
        set_path(&mut ev, "/link");
        ev.ret = 10;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Read, FileType::Symlink, "/link".into())
        );
    }

    #[test]
    fn unlink_success_delete_missing() {
        let mut e = engine();
        let mut ev = event(Syscall::Unlink);
        set_path(&mut ev, "/tmp/gone");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Delete, FileType::Missing, "/tmp/gone".into())
        );
    }

    #[test]
    fn unlink_error_skipped() {
        let mut e = engine();
        let mut ev = event(Syscall::Unlink);
        set_path(&mut ev, "/tmp/gone");
        ev.ret = -libc::ENOENT as i64;
        assert!(e.process(&ev).is_none());
    }

    #[test]
    fn rename_emits_delete_old_and_write_new() {
        let mut e = engine();
        let mut ev = event(Syscall::Rename);
        set_path(&mut ev, "/tmp/a");
        set_path2(&mut ev, "/tmp/b");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.filter_path, "/tmp/b");
        assert_eq!(
            emit.accesses,
            vec![
                Access::new(AccessType::Delete, FileType::Missing, "/tmp/a".into()),
                Access::new(AccessType::Write, FileType::Unknown, "/tmp/b".into()),
            ]
        );
    }

    #[test]
    fn renameat_resolves_both_dirfds() {
        let mut sys = MockSystem::default();
        sys.fds.insert((1000, 3), "/old/dir".into());
        sys.fds.insert((1000, 4), "/new/dir".into());
        let mut e = Engine::new(sys);
        let mut ev = event(Syscall::Renameat);
        ev.dirfd = 3;
        ev.dirfd2 = 4;
        set_path(&mut ev, "a");
        set_path2(&mut ev, "b");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].path, "/old/dir/a");
        assert_eq!(emit.accesses[1].path, "/new/dir/b");
    }

    #[test]
    fn getdents_resolves_fd_and_enumerates() {
        let mut sys = MockSystem::default();
        sys.fds.insert((1000, 9), "/some/dir".into());
        let mut e = Engine::new(sys);
        let mut ev = event(Syscall::Getdents64);
        ev.dirfd = 9;
        ev.ret = 100;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(
                AccessType::Enumerate,
                FileType::Directory,
                "/some/dir".into()
            )
        );
    }

    #[test]
    fn symlink_write_symlink() {
        let mut e = engine();
        let mut ev = event(Syscall::Symlink);
        set_path(&mut ev, "/tmp/link");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Write, FileType::Symlink, "/tmp/link".into())
        );
    }

    #[test]
    fn link_write_file() {
        let mut e = engine();
        let mut ev = event(Syscall::Link);
        set_path(&mut ev, "/tmp/hardlink");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Write, FileType::File, "/tmp/hardlink".into())
        );
    }

    #[test]
    fn mkdir_write_directory() {
        let mut e = engine();
        let mut ev = event(Syscall::Mkdir);
        set_path(&mut ev, "/tmp/d");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Write, FileType::Directory, "/tmp/d".into())
        );
    }

    #[test]
    fn truncate_uses_stat_type() {
        let mut sys = MockSystem::default();
        sys.stats
            .insert("/tmp/f".into(), StatResult::Type(FileType::File));
        let mut e = Engine::new(sys);
        let mut ev = event(Syscall::Truncate);
        set_path(&mut ev, "/tmp/f");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Write, FileType::File, "/tmp/f".into())
        );
    }

    #[test]
    fn truncate_missing() {
        let mut e = engine();
        let mut ev = event(Syscall::Truncate);
        set_path(&mut ev, "/tmp/f");
        ev.ret = -libc::ENOENT as i64;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Missing);
    }

    #[test]
    fn execve_success_reads_file() {
        let mut e = engine();
        let mut ev = event(Syscall::Execve);
        set_path(&mut ev, "/usr/bin/touch");
        ev.ret = 0;
        let emit = e.process(&ev).unwrap();
        assert_eq!(
            emit.accesses[0],
            Access::new(AccessType::Read, FileType::File, "/usr/bin/touch".into())
        );
    }

    #[test]
    fn execve_missing() {
        let mut e = engine();
        let mut ev = event(Syscall::Execve);
        set_path(&mut ev, "/no/such");
        ev.ret = -libc::ENOENT as i64;
        let emit = e.process(&ev).unwrap();
        assert_eq!(emit.accesses[0].file, FileType::Missing);
    }

    #[test]
    fn chdir_updates_cwd_used_by_later_relative_open() {
        let mut e = engine();
        let mut chdir = event(Syscall::Chdir);
        set_path(&mut chdir, "/newcwd");
        chdir.ret = 0;
        assert!(e.process(&chdir).is_none());

        let mut open = event(Syscall::Open);
        set_path(&mut open, "rel.txt");
        open.ret = 3;
        let emit = e.process(&open).unwrap();
        assert_eq!(emit.accesses[0].path, "/newcwd/rel.txt");
    }

    #[test]
    fn close_removes_fd_from_cache() {
        let mut sys = MockSystem::default();
        sys.fds.insert((1000, 7), "/base".into());
        let mut e = Engine::new(sys);
        // Prime the cache.
        assert_eq!(e.get_fd(1000, 7).as_deref(), Some("/base"));
        let mut close = event(Syscall::Close);
        close.dirfd = 7;
        close.ret = 0;
        assert!(e.process(&close).is_none());
        // Cache entry removed; falls back to (now empty) provider miss.
        let mut e2 = Engine::new(MockSystem::default());
        assert!(e2.get_fd(1000, 7).is_none());
    }

    #[test]
    fn unknown_syscall_ignored() {
        let mut e = engine();
        let mut ev = Event::zeroed();
        ev.syscall = 9999;
        assert!(e.process(&ev).is_none());
    }
}
