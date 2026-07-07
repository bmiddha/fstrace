//! Formatting and writing of access reports in the `<access><type> <path>`
//! wire format, to a configurable sink (file descriptor 3 in production).

use std::io::{self, Write};

use crate::engine::Access;

/// Writes access reports to an underlying sink.
pub struct Reporter<W: Write> {
    sink: W,
}

impl<W: Write> Reporter<W> {
    /// Creates a reporter writing to `sink`.
    pub fn new(sink: W) -> Self {
        Reporter { sink }
    }

    /// Writes a single access as `"<access><type> <path>\n"`.
    pub fn report(&mut self, access: &Access) -> io::Result<()> {
        let mut line = Vec::with_capacity(access.path.len() + 4);
        line.push(access.access.code());
        line.push(access.file.code());
        line.push(b' ');
        line.extend_from_slice(access.path.as_bytes());
        line.push(b'\n');
        self.sink.write_all(&line)
    }

    /// Flushes the underlying sink.
    pub fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use fstrace_common::{AccessType, FileType};

    use super::*;

    #[test]
    fn formats_report_line() {
        let mut buf = Vec::new();
        {
            let mut r = Reporter::new(&mut buf);
            r.report(&Access {
                access: AccessType::Write,
                file: FileType::File,
                path: "/tmp/foo".into(),
            })
            .unwrap();
        }
        assert_eq!(buf, b"WF /tmp/foo\n");
    }

    #[test]
    fn formats_missing_and_enumerate() {
        let mut buf = Vec::new();
        {
            let mut r = Reporter::new(&mut buf);
            r.report(&Access {
                access: AccessType::Enumerate,
                file: FileType::Directory,
                path: "/etc".into(),
            })
            .unwrap();
            r.report(&Access {
                access: AccessType::Read,
                file: FileType::Missing,
                path: "/nope".into(),
            })
            .unwrap();
        }
        assert_eq!(buf, b"ED /etc\nRX /nope\n");
    }
}
