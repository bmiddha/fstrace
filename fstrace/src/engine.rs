//! Resolve syscall events into filesystem accesses using a [`System`] provider.

use std::{cell::RefCell, collections::HashMap, io, rc::Rc};

use fstrace_common::{
    AT_FDCWD, AccessType, EVENT_EXIT, EVENT_FORK, Event, FileType, PATH_MAX, Syscall,
};

use crate::{
    pathnorm::normalize_path,
    proc::{StatResult, System},
};

// Open flags (subset used for classification).
const O_WRONLY: i64 = libc::O_WRONLY as i64;
const O_RDWR: i64 = libc::O_RDWR as i64;
const O_CREAT: i64 = libc::O_CREAT as i64;
const O_DIRECTORY: i64 = libc::O_DIRECTORY as i64;

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

/// One syscall's accesses, filtered together using `filter_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emit {
    pub filter_path: String,
    pub accesses: Vec<Access>,
}

/// Per-task cwd/FD caches and a [`System`] provider.
pub struct Engine<S: System> {
    sys: S,
    cwd_cache: HashMap<u32, Rc<RefCell<String>>>,
    fd_cache: HashMap<u32, Rc<RefCell<HashMap<i64, CachedFd>>>>,
    tasks: HashMap<u32, u32>,
}

#[derive(Clone)]
struct CachedFd {
    path: String,
    close_on_exec: Option<bool>,
}

fn errno_is_missing(errno: i32) -> bool {
    errno == libc::ENOENT || errno == libc::ENOTDIR || errno == libc::EBADF
}

fn cstr(buf: &[u8; PATH_MAX], len: u32) -> String {
    let len = (len as usize).min(PATH_MAX);
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

impl<S: System> Engine<S> {
    fn forget(&mut self, pid: u32) {
        self.cwd_cache.remove(&pid);
        self.fd_cache.remove(&pid);
    }

    fn inherit(&mut self, parent: u32, child: u32, shared: i64) {
        if parent == child {
            return;
        }
        self.forget(child);
        if let Some(cwd) = self.cwd_cache.get(&parent) {
            self.cwd_cache.insert(
                child,
                if shared & 1 != 0 {
                    cwd.clone()
                } else {
                    Rc::new(RefCell::new(cwd.borrow().clone()))
                },
            );
        }
        let fds = self.fd_cache.entry(parent).or_default().clone();
        let inherited = if shared & 2 != 0 {
            fds
        } else {
            Rc::new(RefCell::new(fds.borrow().clone()))
        };
        self.fd_cache.insert(child, inherited);
    }
    /// Creates an engine backed by `sys`.
    pub fn new(sys: S) -> Self {
        Engine {
            sys,
            cwd_cache: HashMap::new(),
            fd_cache: HashMap::new(),
            tasks: HashMap::new(),
        }
    }

    fn get_cwd(&mut self, pid: u32) -> String {
        if let Some(cwd) = self.cwd_cache.get(&pid) {
            return cwd.borrow().clone();
        }
        let cwd = self.sys.cwd(pid).unwrap_or_default();
        // A missing /proc entry must not cache an empty cwd.
        if !cwd.is_empty() {
            self.set_cwd(pid, cwd.clone());
        }
        cwd
    }

    /// Record the child's inherited cwd before it starts.
    pub fn seed_cwd(&mut self, pid: u32, cwd: String) {
        self.tasks.insert(pid, pid);
        self.set_cwd(pid, cwd);
    }

    fn set_cwd(&mut self, pid: u32, cwd: String) {
        *self.cwd_cache.entry(pid).or_default().borrow_mut() = cwd;
    }

    #[cfg(test)]
    fn set_fd(&mut self, pid: u32, fd: i64, path: String) {
        self.set_fd_flags(pid, fd, path, Some(false));
    }

    fn set_fd_flags(&mut self, pid: u32, fd: i64, path: String, close_on_exec: Option<bool>) {
        self.fd_cache.entry(pid).or_default().borrow_mut().insert(
            fd,
            CachedFd {
                path,
                close_on_exec,
            },
        );
    }

    fn get_fd(&mut self, pid: u32, fd: i64) -> Option<String> {
        if let Some(fds) = self.fd_cache.get(&pid)
            && let Some(path) = fds.borrow().get(&fd)
        {
            return Some(path.path.clone());
        }
        let path = self.sys.fd_path(pid, fd);
        if let Some(ref p) = path {
            self.set_fd_flags(pid, fd, p.clone(), None);
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

    /// Best-effort adapter that logs unresolved state. Use [`Self::process_checked`]
    /// when incomplete traces must fail.
    pub fn process(&mut self, ev: &Event) -> Option<Emit> {
        match self.process_checked(ev) {
            Ok(emit) => emit,
            Err(error) => {
                tracing::warn!(tid = ev.tid, syscall = ev.syscall, %error);
                None
            }
        }
    }

    fn check_base(&mut self, tid: u32, dirfd: i64, raw: &str) -> io::Result<()> {
        if raw.starts_with('/') {
            return Ok(());
        }
        let base = if dirfd == AT_FDCWD {
            Some(self.get_cwd(tid))
        } else {
            self.get_fd(tid, dirfd)
        };
        if base.as_deref().is_some_and(|path| path.starts_with('/')) {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "trace incomplete: unresolved path base for tid {tid}, dirfd {dirfd}"
        )))
    }

    /// Resolve an event or fail before applying state changes with an unknown base.
    pub fn process_checked(&mut self, ev: &Event) -> io::Result<Option<Emit>> {
        let Some(syscall) = Syscall::from_u32(ev.syscall) else {
            return Ok(self.process_resolved(ev));
        };
        use Syscall::*;
        if ev.ret < 0 {
            let errno = (-ev.ret) as i32;
            let reports_failure = match syscall {
                Open | Openat | Openat2 => errno_is_missing(errno) || errno == libc::EISDIR,
                Execve | Execveat | Truncate => errno_is_missing(errno),
                _ => false,
            };
            if !reports_failure {
                return Ok(None);
            }
        }
        let raw1 = cstr(&ev.path, ev.path_len);
        let raw2 = cstr(&ev.path2, ev.path2_len);
        let empty_fd_exec = syscall == Execveat && ev.flags & libc::AT_EMPTY_PATH as i64 != 0;
        if (raw1.is_empty() && !matches!(syscall, Close | Fchdir) && !empty_fd_exec)
            || (raw2.is_empty() && matches!(syscall, Rename | Renameat | Renameat2))
        {
            return Err(io::Error::other(
                "trace incomplete: missing captured syscall path",
            ));
        }
        match syscall {
            Close => {}
            Fchdir => self.check_base(ev.tid, ev.dirfd, "")?,
            Chdir => {
                let cached = self
                    .cwd_cache
                    .get(&ev.tid)
                    .is_some_and(|cwd| cwd.borrow().starts_with('/'));
                if !raw1.starts_with('/') && !cached {
                    let cwd = self
                        .sys
                        .cwd(ev.tid)
                        .filter(|path| path.starts_with('/'))
                        .ok_or_else(|| {
                            io::Error::other("trace incomplete: cannot establish cwd after chdir")
                        })?;
                    self.set_cwd(ev.tid, cwd);
                    return Ok(None);
                }
                self.check_base(ev.tid, AT_FDCWD, &raw1)?;
            }
            Rename => {
                self.check_base(ev.tid, AT_FDCWD, &raw1)?;
                self.check_base(ev.tid, AT_FDCWD, &raw2)?;
            }
            Renameat | Renameat2 => {
                self.check_base(ev.tid, ev.dirfd, &raw1)?;
                self.check_base(ev.tid, ev.dirfd2, &raw2)?;
            }
            Openat | Openat2 | Unlinkat | Mkdirat | Linkat | Symlinkat | Execveat => {
                self.check_base(ev.tid, ev.dirfd, &raw1)?
            }
            Open | Creat | Unlink | Rmdir | Mkdir | Link | Symlink | Truncate | Execve => {
                self.check_base(ev.tid, AT_FDCWD, &raw1)?
            }
        }
        Ok(self.process_resolved(ev))
    }

    fn process_resolved(&mut self, ev: &Event) -> Option<Emit> {
        match ev.syscall {
            EVENT_FORK => {
                let group = ev.dirfd as u32;
                self.tasks.entry(ev.tid).or_insert(ev.pid);
                self.inherit(ev.tid, ev.ret as u32, ev.flags);
                self.tasks.insert(ev.ret as u32, group);
                return None;
            }
            EVENT_EXIT => {
                self.tasks.remove(&ev.tid);
                self.forget(ev.tid);
                return None;
            }
            _ => {}
        }
        let syscall = Syscall::from_u32(ev.syscall)?;
        let pid = ev.tid;
        self.tasks.entry(ev.tid).or_insert(ev.pid);
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
                if let Some(fds) = self.fd_cache.get(&pid) {
                    fds.borrow_mut().remove(&ev.dirfd);
                }
                None
            }
            Chdir => {
                if !is_err {
                    let path = if raw1.starts_with('/') || self.cwd_cache.contains_key(&pid) {
                        normalize_path(&self.resolve_cwd_relative(pid, &raw1))
                    } else {
                        self.sys.cwd(pid).unwrap_or_default()
                    };
                    if !path.is_empty() {
                        self.set_cwd(pid, path);
                    }
                }
                None
            }
            Fchdir => {
                if !is_err && let Some(path) = self.get_fd(pid, ev.dirfd) {
                    self.set_cwd(pid, path);
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
                    self.set_fd_flags(
                        pid,
                        ret,
                        path.clone(),
                        Some(ev.flags & libc::O_CLOEXEC as i64 != 0),
                    );
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
                    if let Some(fds) = self.fd_cache.get(&pid) {
                        let fds = fds
                            .borrow()
                            .iter()
                            .filter(|(_, entry)| entry.close_on_exec == Some(false))
                            .map(|(fd, entry)| (*fd, entry.clone()))
                            .collect();
                        self.fd_cache.insert(pid, Rc::new(RefCell::new(fds)));
                    }
                    FileType::File
                };
                Some(single(AccessType::Read, file, path))
            }
        }
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

    fn fork_event(parent: u32, child: u32, group: u32, shared: i64) -> Event {
        let mut ev = Event::zeroed();
        ev.pid = parent;
        ev.tid = parent;
        ev.syscall = EVENT_FORK;
        ev.ret = child as i64;
        ev.dirfd = group as i64;
        ev.flags = shared;
        ev
    }

    fn relative_open(pid: u32, fd: i64) -> Event {
        let mut ev = event(Syscall::Openat);
        ev.pid = pid;
        ev.tid = pid;
        ev.dirfd = fd;
        ev.ret = 8;
        set_path(&mut ev, "input");
        ev
    }

    #[test]
    fn fork_inherits_cwd_and_directory_fds_without_proc() {
        let mut e = engine();
        e.seed_cwd(1000, "/project".into());
        e.set_fd(1000, 7, "/project/sub".into());
        e.process(&fork_event(1000, 1001, 1001, 0));
        assert_eq!(
            e.process(&relative_open(1001, AT_FDCWD))
                .unwrap()
                .filter_path,
            "/project/input"
        );
        assert_eq!(
            e.process(&relative_open(1001, 7)).unwrap().filter_path,
            "/project/sub/input"
        );
        assert_eq!(
            e.process(&relative_open(1000, AT_FDCWD))
                .unwrap()
                .filter_path,
            "/project/input"
        );
    }

    #[test]
    fn cache_miss_chdir_does_not_append_the_change_twice() {
        let mut sys = MockSystem::default();
        sys.cwd.insert(1000, "/project/sub".into());
        let mut e = Engine::new(sys);
        let mut change = event(Syscall::Chdir);
        set_path(&mut change, "sub");
        e.process(&change);
        assert_eq!(
            e.process(&relative_open(1000, AT_FDCWD))
                .unwrap()
                .filter_path,
            "/project/sub/input"
        );
    }

    #[test]
    fn leader_exit_preserves_shared_state_until_last_thread_exits() {
        let mut e = engine();
        e.seed_cwd(1000, "/project".into());
        e.process(&fork_event(1000, 1001, 1000, 3));
        let mut exit = event(Syscall::Close);
        exit.syscall = EVENT_EXIT;
        e.process(&exit);
        let mut open = relative_open(1000, AT_FDCWD);
        open.tid = 1001;
        assert_eq!(e.process(&open).unwrap().filter_path, "/project/input");
        exit.tid = 1001;
        e.process(&exit);
        assert!(e.tasks.is_empty());
        assert!(e.cwd_cache.is_empty());
        assert!(e.fd_cache.is_empty());
    }

    #[test]
    fn shared_clone_state_is_shared_but_fork_state_is_copied() {
        for shared in [0, 3] {
            let mut e = engine();
            e.seed_cwd(1000, "/project".into());
            e.set_fd(1000, 7, "/project/dir".into());
            e.process(&fork_event(1000, 1001, 1001, shared));
            let mut change = event(Syscall::Chdir);
            change.pid = 1001;
            change.tid = 1001;
            set_path(&mut change, "sub");
            e.process(&change);
            let mut close = event(Syscall::Close);
            close.pid = 1001;
            close.tid = 1001;
            close.dirfd = 7;
            e.process(&close);
            assert_eq!(
                e.get_cwd(1000),
                if shared == 0 {
                    "/project"
                } else {
                    "/project/sub"
                }
            );
            assert_eq!(e.get_fd(1000, 7).is_some(), shared == 0);
        }
    }

    #[test]
    fn exec_preserves_shared_cwd_but_detaches_files_on_success() {
        for ret in [0, -(libc::ENOENT as i64)] {
            let mut e = engine();
            e.seed_cwd(1000, "/project".into());
            e.set_fd(1000, 7, "/project/dir".into());
            e.set_fd_flags(1000, 8, "/project/private".into(), Some(true));
            e.process(&fork_event(1000, 1001, 1001, 3));
            let mut exec = event(Syscall::Execve);
            exec.pid = 1001;
            exec.tid = 1001;
            exec.ret = ret;
            set_path(&mut exec, "/bin/tool");
            e.process(&exec);
            assert_eq!(e.fd_cache[&1001].borrow().contains_key(&8), ret != 0);
            assert!(e.fd_cache[&1000].borrow().contains_key(&8));
            let mut change = event(Syscall::Chdir);
            change.pid = 1001;
            change.tid = 1001;
            set_path(&mut change, "sub");
            e.process(&change);
            let mut close = event(Syscall::Close);
            close.pid = 1001;
            close.tid = 1001;
            close.dirfd = 7;
            e.process(&close);
            assert_eq!(e.get_cwd(1000), "/project/sub");
            assert_eq!(e.fd_cache[&1000].borrow().contains_key(&7), ret == 0);
        }
    }

    #[test]
    fn empty_shared_fd_table_tracks_first_open_close_and_reuse() {
        for shared in [0, 2] {
            let mut e = engine();
            e.seed_cwd(1000, "/project".into());
            e.process_checked(&fork_event(1000, 1001, 1001, shared))
                .unwrap();
            let mut open = event(Syscall::Openat);
            open.dirfd = AT_FDCWD;
            open.ret = 7;
            set_path(&mut open, "/first");
            e.process_checked(&open).unwrap();
            assert_eq!(e.get_fd(1001, 7).is_some(), shared == 2);
            let mut close = event(Syscall::Close);
            close.tid = 1001;
            close.dirfd = 7;
            e.process_checked(&close).unwrap();
            assert_eq!(e.get_fd(1000, 7).is_some(), shared == 0);
            open.tid = 1001;
            set_path(&mut open, "/reused");
            e.process_checked(&open).unwrap();
            assert_eq!(
                e.get_fd(1000, 7).unwrap(),
                if shared == 2 { "/reused" } else { "/first" }
            );
        }
    }

    #[test]
    fn unknown_bases_fail_before_output_or_state_mutation() {
        let mut e = Engine::new(crate::proc::CapturedSystem);
        e.seed_cwd(1000, "/project".into());
        for ret in [8, -(libc::ENOENT as i64), -(libc::EISDIR as i64)] {
            let mut open = relative_open(1000, 7);
            open.ret = ret;
            assert!(
                e.process_checked(&open)
                    .unwrap_err()
                    .to_string()
                    .contains("trace incomplete")
            );
            assert!(!e.fd_cache.contains_key(&1000));
        }
        let mut fchdir = event(Syscall::Fchdir);
        fchdir.dirfd = 7;
        assert!(e.process_checked(&fchdir).is_err());
        assert_eq!(e.get_cwd(1000), "/project");
        for (old, new) in [(7, 9), (9, 7)] {
            e.set_fd(1000, 9, "/known".into());
            let mut rename = event(Syscall::Renameat);
            rename.dirfd = old;
            rename.dirfd2 = new;
            set_path(&mut rename, "old");
            set_path2(&mut rename, "new");
            assert!(e.process_checked(&rename).is_err());
        }
        let mut unseeded = Engine::new(crate::proc::CapturedSystem);
        assert!(
            unseeded
                .process_checked(&relative_open(1000, AT_FDCWD))
                .is_err()
        );
        let mut irrelevant = relative_open(1000, 7);
        irrelevant.ret = -(libc::EACCES as i64);
        assert!(e.process_checked(&irrelevant).unwrap().is_none());
        let mut empty = event(Syscall::Execve);
        empty.ret = -(libc::ENOENT as i64);
        assert!(
            e.process_checked(&empty)
                .unwrap_err()
                .to_string()
                .contains("missing captured syscall path")
        );
    }

    #[test]
    fn reused_process_identity_cannot_recover_retired_paths() {
        let mut e = engine();
        e.seed_cwd(1000, "/project".into());
        e.process(&fork_event(1000, 1001, 1001, 0));
        e.set_fd(1001, 7, "/secret".into());
        let mut exit = Event::zeroed();
        exit.pid = 1001;
        exit.tid = 1001;
        exit.syscall = EVENT_EXIT;
        e.process(&exit);
        assert!(!e.cwd_cache.contains_key(&1001));
        e.set_cwd(1000, "/other".into());
        e.process(&fork_event(1000, 1001, 1001, 0));
        assert_eq!(
            e.process(&relative_open(1001, AT_FDCWD))
                .unwrap()
                .filter_path,
            "/other/input"
        );
        assert!(e.get_fd(1001, 7).is_none());
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
        ev.flags = libc::O_DIRECTORY as i64;
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
