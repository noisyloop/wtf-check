//! Human-readable and JSON output.

use std::fmt::Write as _;

use crate::finding::{Finding, Severity};
use crate::util::sanitize;

pub struct Meta<'a> {
    pub version: &'a str,
    pub root: String,
    pub distro: String,
    pub package_manager: &'a str,
    pub user_mode: String,
    pub homes: Vec<String>,
    pub checks: Vec<&'a str>,
    pub baseline: Option<String>,
    pub notes: Vec<String>,
}

pub fn counts(f: &[Finding]) -> [usize; 4] {
    let mut c = [0; 4];
    for x in f {
        c[x.severity as usize] += 1;
    }
    c
}

/// JSON string escaping (RFC 8259), also escaping DEL and C1 controls.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f || (0x80..0xa0).contains(&(c as u32)) || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_arr(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| json_escape(s)).collect::<Vec<_>>().join(","))
}

pub fn to_json(meta: &Meta, findings: &[Finding]) -> String {
    let c = counts(findings);
    let mut s = String::from("{");
    let _ = write!(s, "\"tool\":\"wtf-check\",\"version\":{},", json_escape(meta.version));
    let _ = write!(s, "\"root\":{},\"distro\":{},\"package_manager\":{},", json_escape(&meta.root), json_escape(&meta.distro), json_escape(meta.package_manager));
    let _ = write!(s, "\"user_mode\":{},\"homes\":{},", json_escape(&meta.user_mode), json_arr(&meta.homes));
    let checks: Vec<String> = meta.checks.iter().map(|c| c.to_string()).collect();
    let _ = write!(s, "\"checks\":{},", json_arr(&checks));
    let _ = write!(s, "\"baseline\":{},", meta.baseline.as_deref().map(json_escape).unwrap_or_else(|| "null".into()));
    let _ = write!(s, "\"summary\":{{\"high\":{},\"med\":{},\"low\":{},\"info\":{}}},", c[3], c[2], c[1], c[0]);
    s.push_str("\"findings\":[");
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"check\":{},\"severity\":{},\"path\":{},\"reason\":{},\"fix\":{}}}",
            json_escape(f.check),
            json_escape(f.severity.as_str()),
            json_escape(&f.path),
            json_escape(&f.reason),
            json_escape(&f.fix)
        );
    }
    let _ = write!(s, "],\"notes\":{}}}", json_arr(&meta.notes));
    s.push('\n');
    s
}

struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn sev(&self, sev: Severity, s: &str) -> String {
        let code = match sev {
            Severity::High => "1;31",
            Severity::Med => "1;33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.paint(code, s)
    }
}

pub fn to_human(meta: &Meta, findings: &[Finding], color: bool) -> String {
    let st = Style { on: color };
    let mut s = String::new();
    let _ = writeln!(s, "{}", st.paint("1", &format!("wtf-check {} — read-only persistence audit", meta.version)));
    let _ = writeln!(s, "root: {}   distro: {}   packages: {}", sanitize(&meta.root), sanitize(&meta.distro), meta.package_manager);
    let _ = writeln!(s, "mode: {}   homes: {}", meta.user_mode, if meta.homes.is_empty() { "(none)".to_string() } else { sanitize(&meta.homes.join(", ")) });
    let _ = writeln!(s, "checks: {}", meta.checks.join(", "));
    if let Some(b) = &meta.baseline {
        let _ = writeln!(s, "baseline: {} (showing only new/changed items)", sanitize(b));
    }
    let c = counts(findings);
    for sev in Severity::ALL_DESC {
        let group: Vec<&Finding> = findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(s, "\n{}", st.sev(sev, &format!("== {} ({}) ==", sev, group.len())));
        for f in group {
            let _ = writeln!(s, "{} {}", st.sev(sev, &format!("[{}]", f.check)), st.paint("1", &sanitize(&f.path)));
            let _ = writeln!(s, "    why: {}", sanitize(&f.reason));
            for (i, line) in f.fix.lines().enumerate() {
                let label = if i == 0 { "    fix: " } else { "         " };
                let _ = writeln!(s, "{label}{}", sanitize(line));
            }
        }
    }
    let _ = writeln!(s, "\n{}", st.paint("1", "== Summary =="));
    let _ = writeln!(
        s,
        "{}  {}  {}  {}",
        st.sev(Severity::High, &format!("HIGH {}", c[3])),
        st.sev(Severity::Med, &format!("MED {}", c[2])),
        st.sev(Severity::Low, &format!("LOW {}", c[1])),
        st.sev(Severity::Info, &format!("INFO {}", c[0])),
    );
    if c[3] + c[2] == 0 {
        let _ = writeln!(s, "No HIGH/MED findings. (An in-kernel rootkit can hide from any in-host tool; for assurance, scan from a live USB with --root.)");
    } else {
        let _ = writeln!(s, "Fix commands are suggestions only — wtf-check never changes anything. Review before running them.");
    }
    if !meta.notes.is_empty() {
        let _ = writeln!(s, "\nnotes:");
        for n in &meta.notes {
            let _ = writeln!(s, "  - {}", sanitize(n));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape("plain"), "\"plain\"");
        assert_eq!(json_escape("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_escape("l1\nl2\t\r"), "\"l1\\nl2\\t\\r\"");
        assert_eq!(json_escape("\x1b[31m\x00\x7f"), "\"\\u001b[31m\\u0000\\u007f\"");
        assert_eq!(json_escape("ü✓"), "\"ü✓\"");
        assert_eq!(json_escape("\u{2028}"), "\"\\u2028\"");
    }

    #[test]
    fn json_document_shape() {
        let meta = Meta {
            version: "0.1.0",
            root: "/".into(),
            distro: "Arch \"Linux\"".into(),
            package_manager: "pacman",
            user_mode: "root".into(),
            homes: vec!["/root".into()],
            checks: vec!["ssh"],
            baseline: None,
            notes: vec![],
        };
        let f = vec![Finding::new("ssh", Severity::High, "/x\n", "k", "r", "f")];
        let j = to_json(&meta, &f);
        assert!(j.contains("\"distro\":\"Arch \\\"Linux\\\"\""));
        assert!(j.contains("\"summary\":{\"high\":1,\"med\":0,\"low\":0,\"info\":0}"));
        assert!(j.contains("\"path\":\"/x\\n\""));
        assert!(j.contains("\"baseline\":null"));
        let h = to_human(&meta, &f, false);
        assert!(h.contains("== HIGH (1) ==") && h.contains("/x\\x0a") && !h.contains('\x1b'));
    }
}
