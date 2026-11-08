use std::{
    io,
    os::fd::RawFd,
    sync::atomic::{AtomicU64, Ordering},
};

/// Read-only views of the BPF ring's UAPI position pages. Aya owns and advances
/// the consumer; these views only measure when a producer snapshot is drained.
pub(crate) struct RingFence {
    consumer: *mut libc::c_void,
    producer: *mut libc::c_void,
    page: usize,
}

impl RingFence {
    pub(crate) fn new(fd: RawFd) -> io::Result<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::last_os_error());
        }
        let page = page as usize;
        let consumer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if consumer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let producer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                page as libc::off_t,
            )
        };
        if producer == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            unsafe {
                libc::munmap(consumer, page);
            }
            return Err(error);
        }
        Ok(Self {
            consumer,
            producer,
            page,
        })
    }

    pub(crate) fn snapshot(&self) -> u64 {
        unsafe { (*self.producer.cast::<AtomicU64>()).load(Ordering::Acquire) }
    }

    pub(crate) fn drained(&self, position: u64) -> bool {
        let consumer = unsafe { (*self.consumer.cast::<AtomicU64>()).load(Ordering::Acquire) };
        reached(consumer, position)
    }
}

fn reached(consumer: u64, position: u64) -> bool {
    consumer.wrapping_sub(position) as i64 >= 0
}

impl Drop for RingFence {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.consumer, self.page);
            libc::munmap(self.producer, self.page);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn completion_requires_consumer_to_pass_fence_including_wrap() {
        assert!(!super::reached(23, 24));
        assert!(super::reached(24, 24));
        assert!(super::reached(25, 24));
        assert!(super::reached(0, u64::MAX));
        assert!(!super::reached(u64::MAX, 0));
    }
}
