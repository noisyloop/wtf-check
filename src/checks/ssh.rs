//! SSH authorized_keys and permissions.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{logical_lines, snip};
use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};
use crate::util::{base64, sha256, shell_quote};

const NAME: &str = "ssh";

#[derive(Debug, PartialEq, Eq)]
pub struct AuthKey {
    pub options: Vec<String>,
    pub key_type: String,
    pub blob: String,
    pub comment: String,
}

fn is_key_type(s: &str) -> bool {
    s.starts_with("ssh-") || s.starts_with("ecdsa-sha2-") || s.starts_with("sk-ssh-") || s.starts_with("sk-ecdsa-")
}

/// Split an options field on commas outside double quotes.
fn split_options(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            cur.push(c);
            esc = true;
        } else if c == '"' {
            quoted = !quoted;
            cur.push(c);
        } else if c == ',' && !quoted {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn parse_line(line: &str) -> Option<AuthKey> {
    let line = line.trim();
    let first = line.split_whitespace().next()?;
    let (options, rest) = if is_key_type(first) {
        (Vec::new(), line)
    } else {
        // Options run until the first whitespace outside quotes.
        let mut quoted = false;
        let mut esc = false;
        let mut end = line.len();
        for (i, c) in line.char_indices() {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                quoted = !quoted;
            } else if c.is_whitespace() && !quoted {
                end = i;
                break;
            }
        }
        (split_options(&line[..end]), line[end..].trim_start())
    };
    let mut it = rest.splitn(3, char::is_whitespace);
    let key_type = it.next()?.to_string();
    if !is_key_type(&key_type) {
        return None;
    }
    let blob = it.next()?.to_string();
    let comment = it.next().unwrap_or("").trim().to_string();
    Some(AuthKey { options, key_type, blob, comment })
}

/// OpenSSH-style SHA256 fingerprint of a base64 key blob.
pub fn fingerprint(blob: &str) -> Option<String> {
    let raw = base64::decode(blob)?;
    Some(format!("SHA256:{}", base64::encode(&sha256::digest(&raw), false)))
}

fn perm_findings(ctx: &Ctx, p: &Path, what: &str, out: &mut Vec<Finding>) {
    let Ok(md) = ctx.fs.lstat(p) else { return };
    let mode = md.permissions().mode();
    let q = ctx.q(p);
    if md.file_type().is_symlink() {
        out.push(Finding::new(NAME, Severity::Med, ctx.disp(p), Ctx::key("ssh-perm", p), format!("{what} is a symlink"), format!("Review: ls -l {q}")));
    } else if mode & 0o002 != 0 {
        out.push(Finding::new(NAME, Severity::High, ctx.disp(p), Ctx::key("ssh-perm", p), format!("{what} is world-writable (mode {:o})", mode & 0o7777), format!("chmod o-w {q}  (and review its contents)")));
    } else if mode & 0o020 != 0 {
        out.push(Finding::new(NAME, Severity::Med, ctx.disp(p), Ctx::key("ssh-perm", p), format!("{what} is group-writable (mode {:o})", mode & 0o7777), format!("chmod g-w {q}")));
    }
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    for h in &ctx.homes {
        let ssh = h.path.join(".ssh");
        perm_findings(ctx, &h.path, "home directory", &mut out);
        perm_findings(ctx, &ssh, "~/.ssh", &mut out);
        for (fname, legacy) in [("authorized_keys", false), ("authorized_keys2", true)] {
            let p = ssh.join(fname);
            let Some(text) = ctx.read_text(&p) else { continue };
            ctx.record_file(&Ctx::key(NAME, &p), &p, false);
            perm_findings(ctx, &p, fname, &mut out);
            if legacy {
                out.push(Finding::new(NAME, Severity::Low, ctx.disp(&p), Ctx::key("ssh-legacy", &p), "authorized_keys2 is deprecated and rarely used legitimately — a common hiding spot", format!("Review: less {}", ctx.q(&p))));
            }
            for (ln, line) in logical_lines(&text, &['#']) {
                let loc = format!("{}:{ln}", ctx.disp(&p));
                let Some(k) = parse_line(&line) else {
                    out.push(Finding::new(NAME, Severity::Low, loc, Ctx::key(NAME, &p), format!("unparseable authorized_keys line: {}", snip(&line)), format!("Review: less {}", ctx.q(&p))));
                    continue;
                };
                let fp = fingerprint(&k.blob).unwrap_or_else(|| "invalid-base64".into());
                let mut sev = Severity::Info;
                let mut why = format!("user {}: {} {} {}", h.user, k.key_type, fp, if k.comment.is_empty() { "(no comment)" } else { &k.comment });
                let risky: Vec<&String> = k.options.iter().filter(|o| {
                    let l = o.to_ascii_lowercase();
                    l.starts_with("command=") || l.starts_with("environment=")
                }).collect();
                if !risky.is_empty() {
                    sev = Severity::Med;
                    why.push_str(&format!("; forced options: {}", snip(&risky.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","))));
                }
                if h.user == "root" && sev == Severity::Info {
                    why.push_str("; grants root login");
                }
                let fix = format!(
                    "Confirm you recognise this key ({fp}). To remove it, edit {q} and delete line {ln}, e.g.: ${{EDITOR:-nano}} {q}",
                    q = ctx.q(&p)
                );
                out.push(Finding::new(NAME, sev, loc, Ctx::key(NAME, &p), why, fix));
            }
        }
    }
    // sshd configuration that changes where keys come from.
    let mut confs = vec![std::path::PathBuf::from("/etc/ssh/sshd_config")];
    confs.extend(ctx.list(Path::new("/etc/ssh/sshd_config.d")));
    for c in confs {
        let Some(text) = ctx.read_text(&c) else { continue };
        ctx.record_file(&Ctx::key(NAME, &c), &c, false);
        for (ln, line) in logical_lines(&text, &['#']) {
            let mut it = line.split_whitespace();
            let key = it.next().unwrap_or("").to_ascii_lowercase();
            let val: Vec<&str> = it.collect();
            let val = val.join(" ");
            if key == "authorizedkeyscommand" && !val.eq_ignore_ascii_case("none") {
                out.push(Finding::new(NAME, Severity::Med, format!("{}:{ln}", ctx.disp(&c)), Ctx::key(NAME, &c), format!("AuthorizedKeysCommand runs a program to supply login keys: {}", snip(&val)), format!("Review: sudo less {}", shell_quote(&ctx.disp(&c)))));
            } else if key == "authorizedkeysfile" && val.split_whitespace().any(|v| !v.contains(".ssh/authorized_keys")) {
                out.push(Finding::new(NAME, Severity::Low, format!("{}:{ln}", ctx.disp(&c)), Ctx::key(NAME, &c), format!("non-default AuthorizedKeysFile (keys in these files are not audited): {}", snip(&val)), format!("Review: sudo less {}", shell_quote(&ctx.disp(&c)))));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::run_check;
    use crate::util::fs::testutil::FakeRoot;

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    #[test]
    fn parse_and_fingerprint() {
        let k = parse_line(&format!("ssh-ed25519 {BLOB} alice@laptop")).unwrap();
        assert_eq!(k.comment, "alice@laptop");
        assert!(k.options.is_empty());
        assert_eq!(fingerprint(&k.blob).unwrap(), "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA");
        let k = parse_line(&format!("command=\"/bin/sh -c 'x, y'\",no-pty,environment=\"A=b\" ssh-ed25519 {BLOB}")).unwrap();
        assert_eq!(k.options, vec!["command=\"/bin/sh -c 'x, y'\"", "no-pty", "environment=\"A=b\""]);
        assert_eq!(k.key_type, "ssh-ed25519");
        assert!(parse_line("garbage").is_none());
    }

    #[test]
    fn flags_options_and_perms() {
        let r = FakeRoot::new("ssh");
        r.write("/etc/passwd", "eve:x:1001:1001::/home/eve:/bin/bash\n");
        r.write("/home/eve/.ssh/authorized_keys", &format!("ssh-ed25519 {BLOB} ok\ncommand=\"curl x|sh\" ssh-ed25519 {BLOB} bad\n"));
        r.chmod("/home/eve/.ssh", 0o777);
        let (_, v) = run_check(&r, run);
        assert!(v.iter().any(|f| f.severity == Severity::High && f.reason.contains("world-writable")));
        assert!(v.iter().any(|f| f.severity == Severity::Med && f.reason.contains("forced options")));
        assert!(v.iter().any(|f| f.severity == Severity::Info && f.reason.contains("SHA256:ZkAs")));
    }
}
