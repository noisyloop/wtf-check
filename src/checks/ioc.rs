//! IOC sweep: directories named `atomic-lockfile`.

use std::path::{Path, PathBuf};

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};

const NAME: &str = "ioc";
const IOC_DIR: &str = "atomic-lockfile";

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut roots: Vec<(PathBuf, usize)> = vec![(PathBuf::from("/tmp"), 4)];
    for h in &ctx.homes {
        for d in [".npm", ".cache", ".local"] {
            roots.push((h.path.join(d), 6));
        }
    }
    let mut out = Vec::new();
    for (root, depth) in roots {
        let mut hits = Vec::new();
        let stats = ctx.fs.walk(&root, depth, 300_000, &mut |p, md, _| {
            if md.is_dir() && p.file_name().is_some_and(|n| n == IOC_DIR) {
                hits.push(p.to_path_buf());
                return false;
            }
            // Don't descend into huge, irrelevant trees.
            !p.ends_with(Path::new(".local/share/Steam"))
        });
        for (p, e) in stats.errors {
            ctx.note_err(&p, &e);
        }
        if stats.truncated {
            ctx.note(format!("IOC sweep of {} truncated (too many entries)", ctx.disp(&root)));
        }
        for p in hits {
            let key = Ctx::key(NAME, &p);
            ctx.record(key.clone(), "present".into(), false);
            let q = ctx.q(&p);
            out.push(Finding::new(
                NAME,
                Severity::High,
                ctx.disp(&p),
                key,
                format!("directory named `{IOC_DIR}` matches a known malware indicator"),
                format!("Do not run anything inside it. Inspect: ls -laR {q}\nPreserve a copy (tar) for analysis, then remove it, audit recently installed npm/AUR packages, and rotate npm/GitHub/SSH credentials."),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::run_check;
    use crate::util::fs::testutil::FakeRoot;

    #[test]
    fn finds_ioc_dirs() {
        let r = FakeRoot::new("ioc");
        r.write("/etc/passwd", "u:x:1000:1000::/home/u:/bin/sh\n");
        r.mkdir("/home/u/.npm/_cacache/x/atomic-lockfile");
        r.mkdir("/tmp/atomic-lockfile");
        r.mkdir("/home/u/.cache/normal");
        let (_, v) = run_check(&r, run);
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().all(|f| f.severity == Severity::High));
    }
}
