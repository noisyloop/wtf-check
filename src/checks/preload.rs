//! /etc/ld.so.preload, LD_PRELOAD in environment files, ld.so.conf.d.

use std::path::{Path, PathBuf};

use super::{finish, logical_lines, review_fix, snip};
use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::pkg::Ownership;
use crate::util::fs::in_temp;

const NAME: &str = "preload";

pub fn env_issues(text: &str) -> Acc {
    let mut acc = Acc::default();
    for (ln, line) in logical_lines(text, &['#']) {
        let l = line.trim_start_matches("export ").trim();
        if l.starts_with("LD_PRELOAD") || l.starts_with("LD_AUDIT") {
            acc.add(Severity::High, format!("line {ln}: global library injection [{}]", snip(l)));
        } else if l.starts_with("LD_LIBRARY_PATH") {
            acc.add(Severity::Med, format!("line {ln}: global LD_LIBRARY_PATH [{}]", snip(l)));
        }
    }
    acc
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();

    let pre = Path::new("/etc/ld.so.preload");
    if let Some(text) = ctx.read_text(pre) {
        ctx.record_file(&Ctx::key(NAME, pre), pre, false);
        let libs: Vec<String> = logical_lines(&text, &['#']).into_iter().map(|(_, l)| l).collect();
        if !libs.is_empty() {
            out.push(Finding::new(
                NAME,
                Severity::High,
                ctx.disp(pre),
                Ctx::key(NAME, pre),
                format!("/etc/ld.so.preload injects libraries into every process: {}", snip(&libs.join(" "))),
                format!(
                    "Inspect each library (do not run it): ls -l {libs}\nIf not intended: sudo cp {q} /root/ld.so.preload.bak && sudo truncate -s 0 {q}\nA preload rootkit can hide itself from in-host tools: verify from a live USB with --root.",
                    libs = libs.iter().map(|l| ctx.q(Path::new(l))).collect::<Vec<_>>().join(" "),
                    q = ctx.q(pre)
                ),
            ));
        }
    }

    let mut env_files: Vec<(PathBuf, bool)> = vec![(PathBuf::from("/etc/environment"), true), (PathBuf::from("/etc/security/pam_env.conf"), true)];
    for d in ["/etc/environment.d", "/usr/lib/environment.d", "/usr/local/lib/environment.d"] {
        env_files.extend(ctx.list(Path::new(d)).into_iter().map(|p| (p, true)));
    }
    for h in &ctx.homes {
        env_files.push((h.path.join(".pam_environment"), false));
        env_files.extend(ctx.list(&h.path.join(".config/environment.d")).into_iter().map(|p| (p, false)));
    }
    for (p, system) in env_files {
        let Some(text) = ctx.read_text(&p) else { continue };
        let owner = if system { ctx.owner(&p) } else { Ownership::Unknown };
        ctx.record_file(&Ctx::key(NAME, &p), &p, matches!(owner, Ownership::Owned(_)));
        let acc = env_issues(&text);
        if acc.is_empty() {
            continue; // unowned env files are common and harmless by themselves
        }
        if let Some(f) = finish(ctx, NAME, &p, acc, &owner, None, |_| review_fix(ctx, &p)) {
            out.push(f);
        }
    }

    let mut conf: Vec<PathBuf> = vec![PathBuf::from("/etc/ld.so.conf")];
    conf.extend(ctx.list(Path::new("/etc/ld.so.conf.d")));
    for p in conf {
        let Some(text) = ctx.read_text(&p) else { continue };
        let owner = ctx.owner(&p);
        ctx.record_file(&Ctx::key(NAME, &p), &p, matches!(owner, Ownership::Owned(_)));
        let mut acc = Acc::default();
        for (ln, line) in logical_lines(&text, &['#']) {
            if line.starts_with("include") {
                continue;
            }
            if in_temp(&line) {
                acc.add(Severity::High, format!("line {ln}: library search path in a temp dir: {line}"));
            } else if line.starts_with("/home/") || line.starts_with("/root") {
                acc.add(Severity::High, format!("line {ln}: library search path in a home dir: {line}"));
            }
        }
        if let Some(f) = finish(ctx, NAME, &p, acc, &owner, Some(Severity::Low), |_| format!("{}\nThen: sudo ldconfig", review_fix(ctx, &p))) {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{find, run_check};
    use crate::util::fs::testutil::FakeRoot;

    #[test]
    fn preload_detection() {
        let r = FakeRoot::new("preload");
        r.write("/etc/ld.so.preload", "# nothing\n/usr/lib/libprocesshider.so\n");
        r.write("/etc/environment", "EDITOR=vim\nLD_PRELOAD=/opt/x.so\n");
        r.write("/etc/ld.so.conf.d/evil.conf", "/dev/shm/lib\n");
        let (_, v) = run_check(&r, run);
        assert_eq!(find(&v, "ld.so.preload").unwrap().severity, Severity::High);
        assert_eq!(find(&v, "/etc/environment").unwrap().severity, Severity::High);
        assert_eq!(find(&v, "evil.conf").unwrap().severity, Severity::High);
    }

    #[test]
    fn empty_preload_is_clean() {
        let r = FakeRoot::new("preload2");
        r.write("/etc/ld.so.preload", "# comment only\n\n");
        r.write("/etc/environment", "LANG=C\n");
        let (_, v) = run_check(&r, run);
        assert!(v.is_empty(), "{v:?}");
    }
}
