use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};

use crate::child::{self, Child, Fork};

enum Mode {
    File,
    Pipe,
    Socket,
    Worker(PipeWriter),
}

struct PipeWriter {
    socket: UnixStream,
    _child: Child,
}

impl PipeWriter {
    fn new(source: libc::c_int) -> io::Result<Self> {
        let (socket, peer) = UnixStream::pair()?;
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        socket.set_write_timeout(Some(Duration::from_secs(30)))?;
        let parent = unsafe { libc::getpid() };
        let child = match unsafe { child::fork() }? {
            Fork::Child => {
                unsafe {
                    libc::close(socket.as_raw_fd());
                }
                pipe_worker(source, peer.as_raw_fd(), parent);
            }
            Fork::Parent(child) => child,
        };
        drop(peer);
        let mut writer = Self {
            socket,
            _child: child,
        };
        let mut ready = [0; 4];
        writer.socket.read_exact(&mut ready)?;
        let error = i32::from_le_bytes(ready);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(writer)
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let size = bytes.len().min(4096);
        self.socket.write_all(&(size as u32).to_le_bytes())?;
        self.socket.write_all(&bytes[..size])?;
        let mut ack = [0; 4];
        self.socket.read_exact(&mut ack).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "report destination remained blocked",
                )
            } else {
                error
            }
        })?;
        let error = i32::from_le_bytes(ack);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(size)
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

// The forked fallback never allocates or executes Rust destructors. It permits
// bounded cancellation even for an inherited pipe the client cannot reopen.
fn pipe_worker(source: i32, socket: i32, parent: i32) -> ! {
    unsafe {
        let mut error = 0i32;
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
            libc::_exit(125);
        }
        let (first, last) = (source.min(socket) as u32, source.max(socket) as u32);
        for (start, end) in [
            (0, first.wrapping_sub(1)),
            (first + 1, last.wrapping_sub(1)),
            (last + 1, u32::MAX),
        ] {
            if start <= end
                && !(start == 0 && first == 0)
                && libc::syscall(libc::SYS_close_range, start, end, 0) != 0
            {
                error = *libc::__errno_location();
                break;
            }
        }
        raw_write(socket, error.to_le_bytes().as_ptr(), 4);
        if error != 0 {
            libc::_exit(125);
        }
        let mut bytes = [0; 4096];
        loop {
            let mut size = [0; 4];
            if !raw_read(socket, size.as_mut_ptr(), 4) {
                libc::_exit(0);
            }
            let size = u32::from_le_bytes(size) as usize;
            if size > bytes.len() || !raw_read(socket, bytes.as_mut_ptr(), size) {
                libc::_exit(125);
            }
            let error = raw_write(source, bytes.as_ptr(), size);
            raw_write(socket, error.to_le_bytes().as_ptr(), 4);
            if error != 0 {
                libc::_exit(1);
            }
        }
    }
}

unsafe fn raw_read(fd: i32, mut bytes: *mut u8, mut size: usize) -> bool {
    while size != 0 {
        let result =
            unsafe { libc::syscall(libc::SYS_read, fd, bytes.cast::<libc::c_void>(), size) };
        if result <= 0 {
            if result < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return false;
        }
        bytes = unsafe { bytes.add(result as usize) };
        size -= result as usize;
    }
    true
}

unsafe fn raw_write(fd: i32, mut bytes: *const u8, mut size: usize) -> i32 {
    while size != 0 {
        let result =
            unsafe { libc::syscall(libc::SYS_write, fd, bytes.cast::<libc::c_void>(), size) };
        if result <= 0 {
            if result == 0 {
                return libc::EIO;
            }
            let error = unsafe { *libc::__errno_location() };
            if error == libc::EINTR {
                continue;
            }
            return error;
        }
        bytes = unsafe { bytes.add(result as usize) };
        size -= result as usize;
    }
    0
}

pub(crate) struct ReportSink {
    file: File,
    _inherited: Option<File>,
    mode: Mode,
    timeout: Duration,
}

impl ReportSink {
    pub(crate) fn new(file: File) -> io::Result<Self> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
        let (file, mode, inherited) = match mode {
            libc::S_IFIFO => {
                // dup/F_SETFL would change the caller's shared open-file flags.
                // Reopening this pipe creates an independent nonblocking writer.
                let path =
                    std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
                let fd = unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    tracing::debug!(error = %io::Error::last_os_error(), "using cancellable inherited-pipe writer");
                    let worker = PipeWriter::new(file.as_raw_fd())?;
                    return Ok(Self {
                        file,
                        _inherited: None,
                        mode: Mode::Worker(worker),
                        timeout: Duration::from_secs(30),
                    });
                }
                (unsafe { File::from_raw_fd(fd) }, Mode::Pipe, Some(file))
            }
            libc::S_IFSOCK => (file, Mode::Socket, None),
            _ => (file, Mode::File, None),
        };
        Ok(Self {
            file,
            _inherited: inherited,
            mode,
            timeout: Duration::from_secs(30),
        })
    }
}

impl Write for ReportSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Mode::Worker(writer) = &mut self.mode {
            return writer.write(bytes);
        }
        if matches!(self.mode, Mode::File) {
            return self.file.write(bytes);
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            let result = if matches!(self.mode, Mode::Socket) {
                let result = unsafe {
                    libc::send(
                        self.file.as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            } else {
                self.file.write(bytes)
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "report destination remained blocked",
                ));
            }
            let mut fd = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let result =
                unsafe { libc::poll(&mut fd, 1, remaining.as_millis().clamp(1, 250) as i32) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_pipe_times_out_without_changing_shared_descriptor_flags() {
        let (_reader, writer) = nix::unistd::pipe().unwrap();
        let file = File::from(writer);
        let inherited = file.try_clone().unwrap();
        let original_flags = unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFL) };
        let mut sink = ReportSink::new(file).unwrap();
        sink.timeout = Duration::from_millis(20);
        let start = Instant::now();
        assert_eq!(
            sink.write_all(&vec![0; 2 * 1024 * 1024])
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
    }

    #[test]
    fn blocked_socket_times_out_without_changing_shared_descriptor_flags() {
        let (writer, _reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let original_flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        let owned: std::os::fd::OwnedFd = writer.try_clone().unwrap().into();
        let mut sink = ReportSink::new(owned.into()).unwrap();
        sink.timeout = Duration::from_millis(20);
        assert_eq!(
            sink.write_all(&vec![0; 2 * 1024 * 1024])
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
    }

    #[test]
    fn inherited_pipe_worker_is_bounded_cancellable_and_reaped() {
        let (_reader, writer) = nix::unistd::pipe().unwrap();
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        let mut worker = PipeWriter::new(writer.as_raw_fd()).unwrap();
        let pid = worker._child.pid().as_raw();
        worker
            .socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let start = Instant::now();
        loop {
            match worker.write(&[0; 4096]) {
                Ok(_) => {}
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    break;
                }
            }
        }
        drop(worker);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
