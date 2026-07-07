//! Normalises a path in the same way as the original C implementation:
//! collapsing `//`, resolving `/./` and `/../` lexically (without touching the
//! filesystem).

/// Lexically normalises `input`, collapsing redundant separators and resolving
/// `.` / `..` components. This is a pure string operation and does not resolve
/// symlinks.
pub fn normalize_path(input: &str) -> String {
    let bytes = input.as_bytes();
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let at = |i: usize| -> u8 { if i < n { bytes[i] } else { 0 } };

    let mut i = 0;
    while i < n {
        let (c0, c1, c2, c3) = (at(i), at(i + 1), at(i + 2), at(i + 3));
        if c0 == b'/' && c1 == b'/' {
            // Collapse consecutive slashes.
            i += 1;
        } else if c0 == b'/' && c1 == b'.' && c2 == b'/' {
            // Skip "/./"; the trailing slash is handled on the next iteration.
            i += 2;
        } else if c0 == b'/' && c1 == b'.' && c2 == b'.' && c3 == b'/' {
            // "/../": drop the previous component, including its leading slash.
            i += 3;
            while let Some(&last) = out.last() {
                out.pop();
                if last == b'/' {
                    break;
                }
            }
        } else {
            out.push(c0);
            i += 1;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_simple_absolute_paths() {
        assert_eq!(normalize_path("/usr/bin/touch"), "/usr/bin/touch");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "");
    }

    #[test]
    fn collapses_double_slashes() {
        assert_eq!(normalize_path("//"), "/");
        assert_eq!(normalize_path("/a//b"), "/a/b");
        assert_eq!(normalize_path("/a///b//c"), "/a/b/c");
    }

    #[test]
    fn resolves_single_dot() {
        assert_eq!(normalize_path("/a/./b"), "/a/b");
        assert_eq!(normalize_path("/./a"), "/a");
    }

    #[test]
    fn resolves_parent_dot_dot() {
        assert_eq!(normalize_path("/a/../b"), "/b");
        assert_eq!(normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn mixed_components() {
        assert_eq!(normalize_path("/a//b/./c/../d"), "/a/b/d");
    }

    #[test]
    fn trailing_dot_dot_without_slash_is_left_untouched() {
        // The rule requires a trailing slash, matching the original behaviour.
        assert_eq!(normalize_path("/a/.."), "/a/..");
    }
}
