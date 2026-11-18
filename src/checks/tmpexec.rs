//! Executables and ELF binaries in world-writable temp dirs.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};

const NAME: &str = "tmpexec";
const DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
const MAX_DEPTH: usize = 8;
const MAX_ENTRIES: usize = 200_000;

pub fn is_elf(head: &[u8]) -> bool {
    head.starts_with(b"\x7fELF")
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in DIRS {
        let dir = Path::new(d);
        let mut hits = Vec::new();
        let stats = ctx.fs.walk(dir, MAX_DEPTH, MAX_ENTRIES, &mut |p, md, depth| {
            if md.is_file() {
                let exec = md.permissions().mode() & 0o111 != 0;
                let head = ctx.fs.read_capped(p, 4).unwrap_or_default();
                let elf = is_elf(&head);
                if elf || exec {
                    hits.push((p.to_path_buf(), elf, exec, depth, md.len()));
                }
            }
            true
        });
        for (p, e) in stats.errors {
            ctx.note_err(&p, &e);
        }
        if stats.truncated {
            ctx.note(format!("{}: stopped after {MAX_ENTRIES} entries; temp dir not fully scanned", ctx.disp(dir)));
        }
        for (p, elf, exec, depth, size) in hits {
            let hidden = p.iter().any(|c| c.to_string_lossy().starts_with('.'));
            let sev = match (elf, *d == "/dev/shm" || depth <= 2 || hidden) {
                (true, true) => Severity::High,
                (true, false) => Severity::Med,
                (false, _) if hidden => Severity::Med,
                _ => Severity::Low,
            };
            let what = match (elf, exec) {
                (true, true) => "executable ELF binary",
                (true, false) => "ELF binary (not marked executable)",
                _ => "executable file",
            };
            let key = Ctx::key(NAME, &p);
            ctx.record_file(&key, &p, false);
            let q = ctx.q(&p);
            out.push(Finding::new(
                NAME,
                sev,
                ctx.disp(&p),
                key,
                format!("{what} in {d}{} ({size} bytes)", if hidden { ", hidden path" } else { "" }),
                format!("Do not run it. Check what uses it: sudo fuser -v {q}; ls -l {q}; sha256sum {q} (look the hash up offline/in your threat intel)\nIf malicious: preserve a copy for analysis, then sudo rm -i {q}"),
            ));
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
    fn finds_elf_and_exec() {
        let r = FakeRoot::new("tmpexec");
        r.write("/tmp/.x/payload", "\x7fELF....");
        r.write("/var/tmp/a/b/c/script.sh", "#!/bin/sh\n");
        r.chmod("/var/tmp/a/b/c/script.sh", 0o755);
        r.write("/tmp/notes.txt", "hello");
        let (_, v) = run_check(&r, run);
        assert_eq!(find(&v, "payload").unwrap().severity, Severity::High);
        assert_eq!(find(&v, "script.sh").unwrap().severity, Severity::Low);
        assert!(find(&v, "notes.txt").is_none());
    }
}
