pub mod base64;
pub mod fs;
pub mod inflate;
pub mod md5;
pub mod proc;
pub mod sha256;
pub mod time;

/// Quote a string for safe pasting into a POSIX shell. Fix commands embed
/// attacker-controlled file names, so they must never be interpolated raw.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+:,@%=".contains(&b)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Replace terminal control characters (including ANSI escapes) so file
/// names and file contents cannot rewrite the user's terminal.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let u = c as u32;
        if u < 0x20 || u == 0x7f || (0x80..0xa0).contains(&u) {
            out.push_str(&format!("\\x{u:02x}"));
        } else {
            out.push(c);
        }
    }
    out
}

/// Truncate to at most `n` characters, appending an ellipsis.
pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/etc/foo.service"), "/etc/foo.service");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("x'; rm -rf / #"), "'x'\\''; rm -rf / #'");
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn sanitizing() {
        assert_eq!(sanitize("a\x1b[31mb\n"), "a\\x1b[31mb\\x0a");
        assert_eq!(sanitize("ok ü"), "ok ü");
        assert_eq!(truncate("abcdef", 3), "abc…");
    }
}
