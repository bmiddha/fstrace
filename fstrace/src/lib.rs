//! fstrace library: the reusable, host-testable core of the tracer.
//!
//! The eBPF programs (`fstrace-ebpf`) capture raw syscall exits; this crate
//! turns them into resolved, classified, filtered and debounced filesystem
//! access reports. The [`Tracer`] ties the pieces together and is exercised
//! both by the `fstrace` binary and by the integration tests.

pub mod daemon;
pub mod debounce;
pub mod engine;
pub mod filter;
pub mod loader;
pub mod options;
pub mod pathnorm;
pub mod proc;
pub mod report;
pub mod runtime;
pub mod wire;

use std::io::{self, Write};

use fstrace_common::Event;
use tracing::trace;

use crate::{debounce::Debounce, engine::Engine, filter::Filter, proc::System, report::Reporter};

/// End-to-end event processor: resolve + classify (via [`Engine`]), filter,
/// debounce, and report.
pub struct Tracer<S: System, W: Write> {
    engine: Engine<S>,
    filter: Filter,
    debounce: Debounce,
    reporter: Reporter<W>,
}

impl<S: System, W: Write> Tracer<S, W> {
    /// Builds a tracer from its collaborators.
    pub fn new(sys: S, filter: Filter, debounce: Debounce, sink: W) -> Self {
        Tracer {
            engine: Engine::new(sys),
            filter,
            debounce,
            reporter: Reporter::new(sink),
        }
    }

    /// Processes one raw event: any resulting accesses that pass the filter and
    /// debounce are written to the sink.
    pub fn handle_event(&mut self, event: &Event) -> io::Result<()> {
        let Some(emit) = self.engine.process(event) else {
            return Ok(());
        };
        if !self.filter.is_interesting(&emit.filter_path) {
            trace!(path = %emit.filter_path, "filtered out (not interesting)");
            return Ok(());
        }
        for access in &emit.accesses {
            if self
                .debounce
                .should_log(access.access, access.file, &access.path)
            {
                trace!(?access.access, ?access.file, path = %access.path, "reporting access");
                self.reporter.report(access)?;
            } else {
                trace!(?access.access, ?access.file, path = %access.path, "debounced (suppressed)");
            }
        }
        Ok(())
    }

    /// Seeds the initial working directory for a pid (the launched process
    /// inherits the launcher's cwd).
    pub fn seed_cwd(&mut self, pid: u32, cwd: String) {
        self.engine.seed_cwd(pid, cwd);
    }

    /// Flushes the debounce cache (invoked on `SIGUSR1`).
    pub fn flush_debounce(&mut self) {
        self.debounce.flush();
    }

    /// Flushes the output sink.
    pub fn flush(&mut self) -> io::Result<()> {
        self.reporter.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fstrace_common::Syscall;

    use super::*;
    use crate::proc::StatResult;

    #[derive(Default)]
    struct MockSystem {
        cwd: HashMap<u32, String>,
    }

    impl System for MockSystem {
        fn cwd(&self, pid: u32) -> Option<String> {
            self.cwd.get(&pid).cloned()
        }
        fn fd_path(&self, _pid: u32, _fd: i64) -> Option<String> {
            None
        }
        fn stat_type(&self, _path: &str) -> StatResult {
            StatResult::Missing
        }
    }

    fn open_event(path: &str) -> Event {
        let mut ev = Event::zeroed();
        ev.pid = 1;
        ev.syscall = Syscall::Open as u32;
        ev.ret = 3;
        let bytes = path.as_bytes();
        ev.path[..bytes.len()].copy_from_slice(bytes);
        ev.path_len = bytes.len() as u32;
        ev
    }

    #[test]
    fn filter_excludes_uninteresting_paths() {
        let filter = Filter::new(vec!["/tmp".into()], vec![], vec![], vec![]);
        let mut sink = Vec::new();
        {
            let mut t = Tracer::new(
                MockSystem::default(),
                filter,
                Debounce::new(false),
                &mut sink,
            );
            t.handle_event(&open_event("/tmp/keep")).unwrap();
            t.handle_event(&open_event("/etc/skip")).unwrap();
        }
        assert_eq!(sink, b"RF /tmp/keep\n");
    }

    #[test]
    fn debounce_suppresses_repeats_until_flush() {
        let mut sink = Vec::new();
        {
            let mut t = Tracer::new(
                MockSystem::default(),
                Filter::default(),
                Debounce::new(true),
                &mut sink,
            );
            t.handle_event(&open_event("/tmp/foo")).unwrap();
            t.handle_event(&open_event("/tmp/foo")).unwrap();
            t.flush_debounce();
            t.handle_event(&open_event("/tmp/foo")).unwrap();
        }
        assert_eq!(sink, b"RF /tmp/foo\nRF /tmp/foo\n");
    }
}
