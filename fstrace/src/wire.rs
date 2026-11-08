//! Wire protocol between the unprivileged `fstrace` client and the privileged
//! `fstrace-daemon`.
//!
//! A versioned one-use capability binds the client's actual kernel-observed
//! child. A zero ready message requests validation; ACK includes the global
//! root TID. FINISH revokes capture and orders accepted events before DONE.

use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

use fstrace_common::{Event, PATH_MAX};

/// Default Unix socket path the daemon listens on.
pub const DEFAULT_SOCKET: &str = "/run/fstrace/fstrace.sock";

/// Environment variable overriding the socket path (client and daemon).
pub const SOCKET_ENV: &str = "FSTRACE_SOCKET";

/// Byte acknowledging kernel-authenticated registration.
pub const ACK: u8 = 0x06;
pub const FINISH: u8 = 0x04;
pub const REJECT: u8 = 0x15;
const VERSION: [u8; 8] = *b"FSTRACE2";
pub use fstrace_common::EVENT_DONE;

/// Fixed portion: session `u64`, five `u32`s, then four `i64`s.
const HEADER_LEN: usize = 3 * 8 + 5 * 4 + 4 * 8;

pub fn write_challenge<W: Write>(w: &mut W, token: [u64; 2]) -> io::Result<()> {
    w.write_all(&VERSION)?;
    for word in token {
        w.write_all(&word.to_le_bytes())?;
    }
    w.flush()
}

pub fn read_challenge<R: Read>(r: &mut R) -> io::Result<[u64; 2]> {
    let mut version = [0; 8];
    r.read_exact(&mut version)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incompatible daemon protocol",
        ));
    }
    let mut token = [0; 16];
    r.read_exact(&mut token)?;
    Ok([
        u64::from_le_bytes(token[..8].try_into().unwrap()),
        u64::from_le_bytes(token[8..].try_into().unwrap()),
    ])
}

pub fn write_finish<W: Write>(w: &mut W) -> io::Result<()> {
    w.write_all(&[FINISH])?;
    w.flush()
}

/// Number of bytes this event occupies in the compact socket representation.
pub fn encoded_len(ev: &Event) -> usize {
    let p1 = (ev.path_len as usize).min(PATH_MAX);
    let p2 = (ev.path2_len as usize).min(PATH_MAX);
    HEADER_LEN + p1 + p2
}

/// Resolves the socket path from `FSTRACE_SOCKET` or the default.
pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

/// Signals that the claimed child is stopped. Only zero is accepted; a PID
/// supplied here never authorizes tracing.
pub fn write_hello<W: Write>(w: &mut W, ready: u32) -> io::Result<()> {
    w.write_all(&ready.to_le_bytes())?;
    w.flush()
}

/// Reads a [`write_hello`] message.
pub fn read_hello<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Sends the acknowledgement byte after registering the client's pid.
pub fn write_ack<W: Write>(w: &mut W, root: u32) -> io::Result<()> {
    w.write_all(&[ACK])?;
    w.write_all(&root.to_le_bytes())?;
    w.flush()
}

/// Waits for the daemon's acknowledgement byte.
pub fn read_ack<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    if buf[0] != ACK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon rejected registration (unauthorized, duplicate, or expired task)",
        ));
    }
    let mut root = [0; 4];
    r.read_exact(&mut root)?;
    Ok(u32::from_le_bytes(root))
}

/// Serialises an [`Event`] into the compact wire form (only the populated path
/// bytes are sent, not the full `PATH_MAX` buffers).
pub fn encode_event(ev: &Event) -> Vec<u8> {
    let p1 = (ev.path_len as usize).min(PATH_MAX);
    let p2 = (ev.path2_len as usize).min(PATH_MAX);
    let mut buf = Vec::with_capacity(encoded_len(ev));
    buf.extend_from_slice(&ev.session.to_le_bytes());
    buf.extend_from_slice(&ev.birth.to_le_bytes());
    buf.extend_from_slice(&ev.child_birth.to_le_bytes());
    buf.extend_from_slice(&ev.pid.to_le_bytes());
    buf.extend_from_slice(&ev.tid.to_le_bytes());
    buf.extend_from_slice(&ev.syscall.to_le_bytes());
    buf.extend_from_slice(&(p1 as u32).to_le_bytes());
    buf.extend_from_slice(&(p2 as u32).to_le_bytes());
    buf.extend_from_slice(&ev.ret.to_le_bytes());
    buf.extend_from_slice(&ev.dirfd.to_le_bytes());
    buf.extend_from_slice(&ev.dirfd2.to_le_bytes());
    buf.extend_from_slice(&ev.flags.to_le_bytes());
    buf.extend_from_slice(&ev.path[..p1]);
    buf.extend_from_slice(&ev.path2[..p2]);
    buf
}

/// Reads one compact-encoded [`Event`] from the stream.
pub fn read_event<R: Read>(r: &mut R) -> io::Result<Event> {
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header)?;

    let u32_at = |i: usize| u32::from_le_bytes(header[i + 24..i + 28].try_into().unwrap());
    let i64_at = |i: usize| i64::from_le_bytes(header[i + 24..i + 32].try_into().unwrap());

    let mut ev = Event::zeroed();
    ev.session = u64::from_le_bytes(header[..8].try_into().unwrap());
    ev.birth = u64::from_le_bytes(header[8..16].try_into().unwrap());
    ev.child_birth = u64::from_le_bytes(header[16..24].try_into().unwrap());
    ev.pid = u32_at(0);
    ev.tid = u32_at(4);
    ev.syscall = u32_at(8);
    ev.path_len = u32_at(12);
    ev.path2_len = u32_at(16);
    ev.ret = i64_at(20);
    ev.dirfd = i64_at(28);
    ev.dirfd2 = i64_at(36);
    ev.flags = i64_at(44);

    let p1 = ev.path_len as usize;
    let p2 = ev.path2_len as usize;
    if p1 > PATH_MAX || p2 > PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "path length exceeds PATH_MAX",
        ));
    }
    r.read_exact(&mut ev.path[..p1])?;
    r.read_exact(&mut ev.path2[..p2])?;
    Ok(ev)
}

#[cfg(test)]
mod tests {
    use fstrace_common::Syscall;

    use super::*;

    fn sample() -> Event {
        let mut ev = Event::zeroed();
        ev.session = 91;
        ev.birth = 123456789;
        ev.child_birth = 987654321;
        ev.pid = 4242;
        ev.tid = 4243;
        ev.syscall = Syscall::Openat as u32;
        ev.ret = 3;
        ev.dirfd = -100;
        ev.dirfd2 = 7;
        ev.flags = 0o2;
        let a = b"/tmp/one";
        let b = b"../two";
        ev.path[..a.len()].copy_from_slice(a);
        ev.path_len = a.len() as u32;
        ev.path2[..b.len()].copy_from_slice(b);
        ev.path2_len = b.len() as u32;
        ev
    }

    #[test]
    fn event_roundtrips_through_wire() {
        let ev = sample();
        let bytes = encode_event(&ev);
        let mut cursor = io::Cursor::new(bytes);
        let out = read_event(&mut cursor).unwrap();
        assert_eq!(out.session, ev.session);
        assert_eq!(out.birth, ev.birth);
        assert_eq!(out.child_birth, ev.child_birth);
        assert_eq!(out.pid, ev.pid);
        assert_eq!(out.tid, ev.tid);
        assert_eq!(out.syscall, ev.syscall);
        assert_eq!(out.ret, ev.ret);
        assert_eq!(out.dirfd, ev.dirfd);
        assert_eq!(out.dirfd2, ev.dirfd2);
        assert_eq!(out.flags, ev.flags);
        assert_eq!(&out.path[..out.path_len as usize], &ev.path[..a_len(&ev)]);
        assert_eq!(&out.path2[..out.path2_len as usize], b"../two");
    }

    fn a_len(ev: &Event) -> usize {
        ev.path_len as usize
    }

    #[test]
    fn hello_and_ack_roundtrip() {
        let mut buf = Vec::new();
        write_hello(&mut buf, 1234).unwrap();
        let mut cur = io::Cursor::new(buf);
        assert_eq!(read_hello(&mut cur).unwrap(), 1234);

        let mut ack = Vec::new();
        write_ack(&mut ack, 1234).unwrap();
        let mut cur = io::Cursor::new(ack);
        read_ack(&mut cur).unwrap();
    }
}
