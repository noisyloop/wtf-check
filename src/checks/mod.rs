//! One module per check. Each check is a pure read of the filesystem/procfs
//! that returns findings; nothing found is ever modified or executed.

pub mod aur;
pub mod autostart;
pub mod cron;
pub mod ioc;
pub mod kernel;
pub mod preload;
pub mod process;
pub mod shell;
pub mod ssh;
pub mod systemd;
pub mod tmpexec;
pub mod udev;

use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::pkg::Ownership;

pub type CheckFn = fn(&Ctx) -> Vec<Finding>;

pub struct Check {
    pub name: &'static str,
    pub about: &'static str,
    pub run: CheckFn,
}

pub const CHECKS: &[Check] = &[
    Check { name: "systemd", about: "systemd units, timers and drop-ins (system + user)", run: systemd::run },
    Check { name: "cron", about: "crontab, cron.d, cron.*, spool crontabs, anacron", run: cron::run },
    Check { name: "shell", about: "shell startup files (bash, zsh, fish, profile)", run: shell::run },
    Check { name: "preload", about: "ld.so.preload, LD_PRELOAD in environment files, ld.so.conf.d", run: preload::run },
    Check { name: "autostart", about: "XDG autostart .desktop entries", run: autostart::run },
    Check { name: "udev", about: "udev rules that RUN programs", run: udev::run },
    Check { name: "ssh", about: "authorized_keys, key options, ~/.ssh permissions", run: ssh::run },
    Check { name: "tmpexec", about: "executables / ELF files in /tmp, /var/tmp, /dev/shm", run: tmpexec::run },
    Check { name: "process", about: "running processes (deleted/temp/memfd exe, disguised names)", run: process::run },
    Check { name: "kernel", about: "kernel taint flags, unknown modules, eBPF programs (bpftool)", run: kernel::run },
    Check { name: "aur", about: "Arch: foreign/AUR packages and install dates", run: aur::run },
    Check { name: "ioc", about: "known IOC sweep (atomic-lockfile dirs)", run: ioc::run },
];

pub fn names() -> Vec<&'static str> {
    CHECKS.iter().map(|c| c.name).collect()
}

/// Iterate "logical" lines: joins backslash continuations, keeps the first
/// physical line number, trims, and drops blank and comment lines.
pub fn logical_lines(text: &str, comment: &[char]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0;
    for (i, raw) in text.lines().enumerate() {
        if cur.is_empty() {
            start = i + 1;
        }
        let l = raw.trim_end();
        if let Some(stripped) = l.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
            continue;
        }
        cur.push_str(l);
        let t = cur.trim();
        if !t.is_empty() && !t.starts_with(comment) {
            out.push((start, t.to_string()));
        }
        cur.clear();
    }
    let t = cur.trim();
    if !t.is_empty() && !t.starts_with(comment) {
        out.push((start, t.to_string()));
    }
    out
}

pub fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Shorten a content snippet for use in a reason.
pub fn snip(s: &str) -> String {
    crate::util::truncate(s, 120)
}

/// Common tail of every file-based check: apply ownership rules and build
/// the finding. `unowned_base` is the minimum severity for an unowned file
/// in a system path (None = system ownership not applicable).
pub fn finish(
    ctx: &Ctx,
    check: &'static str,
    logical: &Path,
    mut acc: Acc,
    owner: &Ownership,
    unowned_base: Option<Severity>,
    fix: impl FnOnce(&Ownership) -> String,
) -> Option<Finding> {
    if let (Ownership::Unowned, Some(base)) = (owner, unowned_base) {
        acc.unowned(base);
    }
    let sev = acc.sev?;
    let mut reason = acc.reason();
    if let Ownership::Owned(p) = owner {
        reason.push_str(&format!(" [owned by package {p}]"));
    }
    let mut fix = fix(owner);
    if let Ownership::Owned(p) = owner {
        let v = ctx.pkg.verify_cmd(p);
        if !v.is_empty() {
            fix = format!("Verify the package's files: {v}\n{fix}");
        }
    }
    Some(Finding::new(check, sev, ctx.disp(logical), Ctx::key(check, logical), reason, fix))
}

/// Generic "review then remove" fix text for a file.
pub fn review_fix(ctx: &Ctx, logical: &Path) -> String {
    let sudo = if ctx.home_of(logical).is_some() { "" } else { "sudo " };
    format!("Review: less {q}\nIf unwanted: {sudo}rm -i {q}", q = ctx.q(logical))
}

#[cfg(test)]
pub mod testutil {
    use crate::ctx::Ctx;
    use crate::finding::Finding;
    use crate::util::fs::testutil::FakeRoot;

    pub fn run_check(r: &FakeRoot, f: super::CheckFn) -> (Ctx, Vec<Finding>) {
        let ctx = Ctx::new(r.0.clone());
        let v = f(&ctx);
        (ctx, v)
    }

    pub fn find<'a>(v: &'a [Finding], path_suffix: &str) -> Option<&'a Finding> {
        v.iter().find(|f| f.path.ends_with(path_suffix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_and_comments() {
        let t = "# c\nExecStart=/bin/a \\\n  --flag\n\n; other\nX=1";
        let l = logical_lines(t, &['#', ';']);
        assert_eq!(l, vec![(2, "ExecStart=/bin/a    --flag".to_string()), (6, "X=1".to_string())]);
    }
}
