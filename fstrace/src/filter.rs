//! Path filtering, mirroring the original filter precedence:
//!
//! ```text
//! if negative prefix    matches -> IGNORE
//! if negative substring matches -> IGNORE
//! if positive prefix    matches -> ALLOW
//! if positive substring matches -> ALLOW
//! default                       -> IGNORE
//! ```

/// A compiled set of path filters.
#[derive(Debug, Clone)]
pub struct Filter {
    filter_prefixes: Vec<String>,
    negative_filter_prefixes: Vec<String>,
    filter_substrings: Vec<String>,
    negative_filter_substrings: Vec<String>,
}

impl Default for Filter {
    /// The default filter allows every path (positive prefix `/`), matching the
    /// original tool when no `FSTRACE_*` filter variables are set.
    fn default() -> Self {
        Filter::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
    }
}

impl Filter {
    /// Builds a filter from the four filter lists. When `filter_prefixes` is
    /// empty it defaults to `/` (allow everything not otherwise excluded),
    /// matching the original behaviour.
    pub fn new(
        mut filter_prefixes: Vec<String>,
        negative_filter_prefixes: Vec<String>,
        filter_substrings: Vec<String>,
        negative_filter_substrings: Vec<String>,
    ) -> Self {
        if filter_prefixes.is_empty() {
            filter_prefixes.push("/".to_string());
        }
        Filter {
            filter_prefixes,
            negative_filter_prefixes,
            filter_substrings,
            negative_filter_substrings,
        }
    }

    /// Returns whether `path` should be reported.
    pub fn is_interesting(&self, path: &str) -> bool {
        if self
            .negative_filter_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()))
        {
            return false;
        }
        if self
            .negative_filter_substrings
            .iter()
            .any(|s| path.contains(s.as_str()))
        {
            return false;
        }
        if self
            .filter_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()))
        {
            return true;
        }
        if self
            .filter_substrings
            .iter()
            .any(|s| path.contains(s.as_str()))
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_allows_everything() {
        let f = Filter::new(vec![], vec![], vec![], vec![]);
        assert!(f.is_interesting("/anything"));
        assert!(f.is_interesting("/tmp/foo"));
    }

    #[test]
    fn positive_prefix_restricts() {
        let f = Filter::new(v(&["/tmp"]), vec![], vec![], vec![]);
        assert!(f.is_interesting("/tmp/foo"));
        assert!(!f.is_interesting("/usr/bin/touch"));
    }

    #[test]
    fn positive_substring_allows() {
        let f = Filter::new(v(&["/does-not-match"]), vec![], v(&["secret"]), vec![]);
        assert!(f.is_interesting("/var/secret/file"));
        assert!(!f.is_interesting("/var/public/file"));
    }

    #[test]
    fn negative_prefix_takes_precedence_over_positive() {
        let f = Filter::new(v(&["/"]), v(&["/proc"]), vec![], vec![]);
        assert!(!f.is_interesting("/proc/self/status"));
        assert!(f.is_interesting("/tmp/foo"));
    }

    #[test]
    fn negative_substring_takes_precedence_over_positive() {
        let f = Filter::new(v(&["/"]), vec![], vec![], v(&[".cache"]));
        assert!(!f.is_interesting("/home/u/.cache/x"));
        assert!(f.is_interesting("/home/u/data"));
    }

    #[test]
    fn negative_beats_positive_on_same_path() {
        // Negative prefix is evaluated before positive prefix.
        let f = Filter::new(v(&["/tmp"]), v(&["/tmp/ignore"]), vec![], vec![]);
        assert!(!f.is_interesting("/tmp/ignore/x"));
        assert!(f.is_interesting("/tmp/keep/x"));
    }
}
