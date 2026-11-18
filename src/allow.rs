//! `--allow FILE`: suppress reviewed, known-good findings.
//!
//! One pattern per line; `#` starts a comment. A pattern matches a finding's
//! path or its baseline subject (`check:/path`). A trailing `*` matches any
//! suffix. Prefix a pattern with `check:` to limit it to one check, e.g.
//! `shell:/etc/profile.d/*` or `network:tcp 127.0.0.1:631`.

use crate::finding::Finding;

#[derive(Debug, Default)]
pub struct Allow {
    patterns: Vec<String>,
}

fn matches(pat: &str, s: &str) -> bool {
    match pat.strip_suffix('*') {
        Some(prefix) => s.starts_with(prefix),
        None => pat == s,
    }
}

impl Allow {
    pub fn parse(text: &str) -> Allow {
        Allow {
            patterns: text.lines().map(|l| l.split(" #").next().unwrap_or("").trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect(),
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Allow, String> {
        std::fs::read_to_string(path).map(|t| Allow::parse(&t)).map_err(|e| format!("cannot read allowlist {}: {e}", path.display()))
    }

    pub fn allows(&self, f: &Finding) -> bool {
        self.patterns.iter().any(|p| {
            if matches(p, &f.path) || matches(p, &f.subject) {
                return true;
            }
            // `check:pattern` scoped to one check, matched against the path.
            p.split_once(':').is_some_and(|(c, rest)| c == f.check && !rest.is_empty() && matches(rest, &f.path))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn allowlist_matching() {
        let a = Allow::parse("# reviewed 2026-11-18\n/etc/profile.d/*\nshell:/home/u/.zshrc\nnetwork:tcp 127.0.0.1:631  # cups\n\n");
        let f = |check: &'static str, path: &str| Finding::new(check, Severity::Low, path, format!("{check}:{path}"), "", "");
        assert!(a.allows(&f("shell", "/etc/profile.d/nvm.sh")));
        assert!(a.allows(&f("shell", "/home/u/.zshrc")));
        assert!(!a.allows(&f("cron", "/home/u/.zshrc")));
        assert!(a.allows(&f("network", "tcp 127.0.0.1:631")));
        assert!(!a.allows(&f("shell", "/etc/profile")));
    }
}
