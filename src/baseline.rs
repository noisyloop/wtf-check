//! Baselines: SHA-256 of every checked file plus unit / eBPF / package lists.
//! With `--baseline`, only new or changed items are reported.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};

const HEADER: &str = "# wtf-check baseline v1";

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n").replace('\r', "\\r")
}

fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn serialize(inv: &BTreeMap<String, String>) -> String {
    let mut s = format!("{HEADER}\n");
    for (k, v) in inv {
        s.push_str(&format!("{}\t{}\n", esc(k), esc(v)));
    }
    s
}

pub fn parse(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err("not a wtf-check baseline file (bad header)".into());
    }
    let mut m = BTreeMap::new();
    for (i, l) in lines.enumerate() {
        if l.is_empty() {
            continue;
        }
        let (k, v) = l.split_once('\t').ok_or_else(|| format!("malformed baseline line {}", i + 2))?;
        m.insert(unesc(k), unesc(v));
    }
    Ok(m)
}

pub fn save(path: &Path, inv: &BTreeMap<String, String>) -> io::Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(serialize(inv).as_bytes())
}

pub fn load(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let t = fs::read_to_string(path).map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
    parse(&t)
}

fn rest_is_path(key: &str) -> bool {
    key.split_once(':').is_some_and(|(_, r)| r.starts_with('/'))
}

fn kind_severity(key: &str) -> Severity {
    match key.split(':').next().unwrap_or("") {
        "ebpf" | "ioc" => Severity::High,
        "systemd" | "systemd-link" | "cron" | "autostart" | "udev" | "preload" | "ssh" | "tmpexec" | "kernel" => Severity::Med,
        _ => Severity::Low,
    }
}

fn check_of(key: &str) -> &'static str {
    match key.split(':').next().unwrap_or("") {
        "systemd" | "systemd-link" => "systemd",
        "cron" => "cron",
        "shell" => "shell",
        "preload" => "preload",
        "autostart" => "autostart",
        "udev" => "udev",
        "ssh" | "ssh-perm" | "ssh-legacy" => "ssh",
        "tmpexec" => "tmpexec",
        "ebpf" | "kernel" => "kernel",
        "aur" => "aur",
        "ioc" => "ioc",
        _ => "baseline",
    }
}

/// Keep only findings about new/changed items, and add findings for
/// new/changed/removed inventory entries that no check flagged.
pub fn diff(ctx: &Ctx, findings: Vec<Finding>, current: &BTreeMap<String, String>, base: &BTreeMap<String, String>, checks: &HashSet<&str>) -> Vec<Finding> {
    let changed = |k: &str| -> Option<&'static str> {
        match (current.get(k), base.get(k)) {
            (Some(_), None) => Some("new since baseline"),
            (Some(a), Some(b)) if a != b => Some("changed since baseline"),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut covered = HashSet::new();
    for mut f in findings {
        if !current.contains_key(&f.subject) {
            out.push(f); // not baseline-tracked (e.g. live processes): always report
            continue;
        }
        if let Some(why) = changed(&f.subject) {
            covered.insert(f.subject.clone());
            f.reason = format!("{} ({why})", f.reason);
            out.push(f);
        } else {
            covered.insert(f.subject.clone());
        }
    }
    let display = |k: &str| {
        let rest = k.split_once(':').map(|x| x.1).unwrap_or(k);
        if rest.starts_with('/') {
            ctx.disp(Path::new(rest))
        } else {
            rest.to_string()
        }
    };
    for k in current.keys() {
        if covered.contains(k) || ctx.is_quiet(k) {
            continue;
        }
        if let Some(why) = changed(k) {
            out.push(Finding::new(check_of(k), kind_severity(k), display(k), k.clone(), format!("{why}: {k}"), if rest_is_path(k) { format!("Review what changed (compare with a backup or the package copy): less {}", crate::util::shell_quote(&display(k))) } else { "Confirm this change was expected.".to_string() }));
        }
    }
    for k in base.keys() {
        if !current.contains_key(k) && checks.contains(check_of(k)) {
            out.push(Finding::new(check_of(k), Severity::Info, display(k), k.clone(), format!("removed since baseline: {k}"), ""));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_escapes() {
        let mut m = BTreeMap::new();
        m.insert("systemd:/etc/a\tb\nc\\d".to_string(), "abc".to_string());
        m.insert("ebpf:x:y:z".to_string(), "t".to_string());
        assert_eq!(parse(&serialize(&m)).unwrap(), m);
        assert!(parse("garbage").is_err());
    }
}
