use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use nix::{
    errno::Errno,
    sys::{
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};

pub(crate) struct Child {
    pid: Pid,
    fd: OwnedFd,
}

pub(crate) enum Fork {
    Parent(Child),
    Child,
}

/// The child must use async-signal-safe operations that do not depend on libc's
/// thread bookkeeping, which raw clone leaves unchanged.
pub(crate) unsafe fn fork() -> io::Result<Fork> {
    let mut fd = -1;
    // Both supported architectures take parent_tid third; unused TLS and
    // child_tid arguments are zero. CLONE_PIDFD creates the handle atomically.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_PIDFD | libc::SIGCHLD,
            0usize,
            &mut fd as *mut libc::c_int,
            0usize,
            0usize,
        )
    };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Fork::Child),
        _ => Ok(Fork::Parent(Child {
            pid: Pid::from_raw(pid as libc::pid_t),
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })),
    }
}

impl Child {
    pub(crate) fn pid(&self) -> Pid {
        self.pid
    }

    pub(crate) fn signal(&self, signal: Signal) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal as libc::c_int,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn wait(&self, options: WaitPidFlag) -> nix::Result<WaitStatus> {
        let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let flags = libc::WEXITED
            | if options.contains(WaitPidFlag::WNOHANG) {
                libc::WNOHANG
            } else {
                0
            }
            | if options.contains(WaitPidFlag::WUNTRACED) {
                libc::WSTOPPED
            } else {
                0
            };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.fd.as_raw_fd() as libc::id_t,
                status.as_mut_ptr(),
                flags,
            )
        };
        if result == -1 {
            return Err(Errno::last());
        }
        let status = unsafe { status.assume_init() };
        if unsafe { status.si_pid() } == 0 {
            return Ok(WaitStatus::StillAlive);
        }
        let code = unsafe { status.si_status() };
        match status.si_code {
            libc::CLD_EXITED => Ok(WaitStatus::Exited(self.pid, code)),
            libc::CLD_KILLED | libc::CLD_DUMPED => Ok(WaitStatus::Signaled(
                self.pid,
                Signal::try_from(code)?,
                status.si_code == libc::CLD_DUMPED,
            )),
            libc::CLD_STOPPED => Ok(WaitStatus::Stopped(self.pid, Signal::try_from(code)?)),
            _ => Err(Errno::EPROTO),
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if let Err(error) = self.signal(Signal::SIGKILL)
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            tracing::warn!(pid = self.pid.as_raw(), %error, "cannot terminate child");
            return;
        }
        loop {
            match self.wait(WaitPidFlag::empty()) {
                Ok(_) | Err(Errno::ECHILD) => return,
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    tracing::warn!(pid = self.pid.as_raw(), %error, "cannot reap child");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_stays_bound_to_the_original_child_after_external_reaping() {
        let child = match unsafe { fork() }.unwrap() {
            Fork::Child => unsafe { libc::_exit(0) },
            Fork::Parent(child) => child,
        };
        assert_eq!(
            nix::sys::wait::waitpid(child.pid(), None).unwrap(),
            nix::sys::wait::WaitStatus::Exited(child.pid(), 0)
        );
        assert_eq!(
            child.signal(Signal::SIGKILL).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(child.wait(WaitPidFlag::WNOHANG), Err(Errno::ECHILD));
        drop(child);
    }
}
