//! Debounce cache: suppresses duplicate `(path, access, file)` reports until
//! the cache is flushed (the loader flushes it on `SIGUSR1`).

use std::collections::HashSet;

use fstrace_common::{AccessType, FileType};

/// Deduplicates access reports. When disabled, every report passes through.
#[derive(Debug, Default)]
pub struct Debounce {
    enabled: bool,
    seen: HashSet<String>,
}

impl Debounce {
    /// Creates a debounce cache. When `enabled` is false, [`Debounce::should_log`]
    /// always returns `true`.
    pub fn new(enabled: bool) -> Self {
        Debounce {
            enabled,
            seen: HashSet::new(),
        }
    }

    /// Returns whether this `(path, access, file)` tuple should be logged,
    /// recording it so subsequent identical tuples are suppressed.
    pub fn should_log(&mut self, access: AccessType, file: FileType, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let mut key = String::with_capacity(path.len() + 2);
        key.push_str(path);
        key.push(access.code() as char);
        key.push(file.code() as char);
        self.seen.insert(key)
    }

    /// Clears the cache so previously-seen tuples are reported again.
    pub fn flush(&mut self) {
        self.seen.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_always_logs() {
        let mut d = Debounce::new(false);
        assert!(d.should_log(AccessType::Read, FileType::File, "/a"));
        assert!(d.should_log(AccessType::Read, FileType::File, "/a"));
    }

    #[test]
    fn enabled_suppresses_duplicates() {
        let mut d = Debounce::new(true);
        assert!(d.should_log(AccessType::Read, FileType::File, "/a"));
        assert!(!d.should_log(AccessType::Read, FileType::File, "/a"));
    }

    #[test]
    fn distinct_tuples_are_independent() {
        let mut d = Debounce::new(true);
        assert!(d.should_log(AccessType::Read, FileType::File, "/a"));
        assert!(d.should_log(AccessType::Write, FileType::File, "/a"));
        assert!(d.should_log(AccessType::Read, FileType::Directory, "/a"));
        assert!(d.should_log(AccessType::Read, FileType::File, "/b"));
    }

    #[test]
    fn flush_allows_relogging() {
        let mut d = Debounce::new(true);
        assert!(d.should_log(AccessType::Read, FileType::File, "/a"));
        assert!(!d.should_log(AccessType::Read, FileType::File, "/a"));
        d.flush();
        assert!(d.should_log(AccessType::Read, FileType::File, "/a"));
    }
}
