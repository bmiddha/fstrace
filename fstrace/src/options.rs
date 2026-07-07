//! Parsing of the `FSTRACE_*` environment variables into runtime [`Options`].

use crate::filter::Filter;

/// Runtime options derived from the environment.
#[derive(Debug, Clone)]
pub struct Options {
    /// Compiled path filter.
    pub filter: Filter,
    /// Whether duplicate reports should be debounced.
    pub debounce: bool,
}

/// Splits a colon-separated environment value into its parts, dropping empties.
fn split_list(value: Option<String>) -> Vec<String> {
    match value {
        Some(v) => v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        None => Vec::new(),
    }
}

impl Options {
    /// Builds [`Options`] using `get` to look up environment variables. This
    /// indirection keeps the parsing logic unit-testable.
    pub fn from_env_with<F>(get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let filter = Filter::new(
            split_list(get("FSTRACE_FILTER_PREFIX")),
            split_list(get("FSTRACE_NEGATIVE_FILTER_PREFIX")),
            split_list(get("FSTRACE_FILTER_SUBSTRING")),
            split_list(get("FSTRACE_NEGATIVE_FILTER_SUBSTRING")),
        );
        let debounce = get("FSTRACE_DEBOUNCE")
            .map(|v| v.starts_with('1'))
            .unwrap_or(false);
        Options { filter, debounce }
    }

    /// Builds [`Options`] from the process environment.
    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_getter(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> {
        move |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, val)| val.to_string())
        }
    }

    #[test]
    fn empty_environment_defaults() {
        let opts = Options::from_env_with(|_| None);
        assert!(!opts.debounce);
        // Default filter allows everything.
        assert!(opts.filter.is_interesting("/anything"));
    }

    #[test]
    fn debounce_enabled_by_leading_one() {
        let opts = Options::from_env_with(map_getter(&[("FSTRACE_DEBOUNCE", "1")]));
        assert!(opts.debounce);
        let opts = Options::from_env_with(map_getter(&[("FSTRACE_DEBOUNCE", "0")]));
        assert!(!opts.debounce);
    }

    #[test]
    fn colon_separated_lists_parsed() {
        let opts = Options::from_env_with(map_getter(&[(
            "FSTRACE_NEGATIVE_FILTER_PREFIX",
            "/proc:/sys",
        )]));
        assert!(!opts.filter.is_interesting("/proc/x"));
        assert!(!opts.filter.is_interesting("/sys/x"));
        assert!(opts.filter.is_interesting("/tmp/x"));
    }

    #[test]
    fn empty_segments_ignored() {
        let opts = Options::from_env_with(map_getter(&[("FSTRACE_FILTER_PREFIX", "/tmp::/var")]));
        assert!(opts.filter.is_interesting("/tmp/a"));
        assert!(opts.filter.is_interesting("/var/a"));
        assert!(!opts.filter.is_interesting("/usr/a"));
    }
}
