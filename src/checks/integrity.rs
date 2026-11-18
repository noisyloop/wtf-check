//! Package file integrity: compare files on disk with the package manager's
//! own checksums (pacman mtree SHA-256, dpkg md5sums). No subprocess.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};
use crate::pkg::FileRecord;

const NAME: &str = "integrity";
const MAX_FINDINGS: usize = 150;
const LIB_DIRS: &[&str] = &[
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    "/usr/lib/aarch64-linux-gnu/",
    "/lib/aarch64-linux-gnu/",
];

/// Files an attacker most likely trojans: executables, shared libraries,
/// PAM modules, systemd and ssh helpers.
pub fn critical(path: &str) -> bool {
    for d in ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"] {
        if path.strip_prefix(d).is_some_and(|r| !r.contains('/')) {
            return true;
        }
    }
    if (path.starts_with("/usr/lib") || path.starts_with("/lib")) && path.contains("/security/") && path.ends_with(".so") {
        return true; // PAM modules
    }
    for d in LIB_DIRS {
        if path.strip_prefix(d).is_some_and(|r| !r.contains('/') && r.contains(".so")) {
            return true;
        }
    }
    ["/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/usr/lib/ssh/", "/usr/lib/openssh/", "/usr/libexec/openssh/"].iter().any(|p| path.starts_with(p))
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let Some(records) = ctx.pkg.records() else {
        let hint = match ctx.pkg.name() {
            "rpm" => "run `sudo rpm -Va` to verify rpm packages",
            _ => "no supported package database found",
        };
        ctx.note(format!("integrity check skipped: {hint}"));
        return Vec::new();
    };
    let selected: Vec<&FileRecord> = records.iter().filter(|r| !r.path.starts_with("/etc/") && (ctx.deep || critical(&r.path))).collect();
    let mut out = Vec::new();
    let mut missing: BTreeMap<&str, usize> = BTreeMap::new();
    let mut checked = 0usize;
    let mut truncated = 0usize;
    for r in selected {
        let p = Path::new(&r.path);
        // Cheap size check first (pacman records sizes).
        let meta = match ctx.fs.stat(p) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                *missing.entry(r.pkg.as_str()).or_default() += 1;
                continue;
            }
            Err(e) => {
                ctx.note_err(p, &e);
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        checked += 1;
        let altered = if r.size.is_some_and(|s| s != meta.len()) {
            Some(format!("size {} differs from the package record ({})", meta.len(), r.size.unwrap_or(0)))
        } else {
            match ctx.fs.digest_full(p, r.md5) {
                Ok((h, _)) if h.eq_ignore_ascii_case(&r.digest) => None,
                Ok((h, _)) => Some(format!("{} {h} differs from the package record {}", if r.md5 { "md5" } else { "sha256" }, r.digest)),
                Err(e) => {
                    ctx.note_err(p, &e);
                    None
                }
            }
        };
        let Some(why) = altered else { continue };
        if out.len() >= MAX_FINDINGS {
            truncated += 1;
            continue;
        }
        let sev = if critical(&r.path) { Severity::High } else { Severity::Med };
        let key = Ctx::key(NAME, p);
        ctx.record(key.clone(), format!("altered:{}", r.digest), false);
        out.push(Finding::new(
            NAME,
            sev,
            ctx.disp(p),
            key,
            format!("file from package {} was modified: {why}", r.pkg),
            format!(
                "Don't run it. Preserve a copy for analysis: sudo cp -a {q} /root/\nConfirm: {}\nRestore from a trusted mirror: {}",
                ctx.pkg.verify_cmd(&r.pkg),
                ctx.pkg.reinstall_cmd(&r.pkg),
                q = ctx.q(p)
            ),
        ));
    }
    if truncated > 0 {
        ctx.note(format!("integrity: {truncated} more modified files not listed (showing the first {MAX_FINDINGS}); the system may be heavily tampered with"));
    }
    if !missing.is_empty() {
        let total: usize = missing.values().sum();
        let pkgs: Vec<String> = missing.iter().take(10).map(|(p, n)| format!("{p} ({n})")).collect();
        out.push(Finding::new(
            NAME,
            Severity::Low,
            "package files",
            "integrity:missing",
            format!("{total} package files are missing from disk: {}{}", pkgs.join(", "), if missing.len() > 10 { ", …" } else { "" }),
            "Usually harmless (NoExtract, manual cleanup). Check with: pacman -Qkk <package> / dpkg --verify <package>",
        ));
    }
    ctx.note(format!("integrity: verified {checked} package files{}", if ctx.deep { " (--deep)" } else { " (security-critical set; use --deep for all)" }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{find, run_check};
    use crate::util::fs::testutil::FakeRoot;

    #[test]
    fn critical_paths() {
        assert!(critical("/usr/bin/sshd"));
        assert!(critical("/usr/lib/libc.so.6"));
        assert!(critical("/usr/lib/security/pam_unix.so"));
        assert!(critical("/lib/x86_64-linux-gnu/security/pam_unix.so"));
        assert!(critical("/usr/lib/x86_64-linux-gnu/libpam.so.0.85.1"));
        assert!(!critical("/usr/share/doc/x"));
        assert!(!critical("/usr/lib/python3/x.so"));
    }

    #[test]
    fn detects_modified_binary_dpkg() {
        let r = FakeRoot::new("integrity");
        r.write("/var/lib/dpkg/status", "");
        r.write("/usr/bin/good", "abc");
        r.write("/usr/bin/evil", "trojaned");
        // md5("abc") = 900150983cd24fb0d6963f7d28e17f72
        r.write(
            "/var/lib/dpkg/info/coreutils.md5sums",
            "900150983cd24fb0d6963f7d28e17f72  usr/bin/good\n900150983cd24fb0d6963f7d28e17f72  usr/bin/evil\n900150983cd24fb0d6963f7d28e17f72  usr/bin/gone\n",
        );
        let (_, v) = run_check(&r, run);
        let evil = find(&v, "/usr/bin/evil").unwrap();
        assert_eq!(evil.severity, Severity::High);
        assert!(evil.fix.contains("apt install --reinstall coreutils"));
        assert!(find(&v, "/usr/bin/good").is_none());
        assert!(v.iter().any(|f| f.reason.contains("1 package files are missing")));
    }
}
