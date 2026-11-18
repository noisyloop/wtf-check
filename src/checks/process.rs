//! Running processes via /proc.

use std::io::ErrorKind;
use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};
use crate::patterns::base;
use crate::util::fs::in_temp;
use crate::util::proc::{self, ProcInfo};

const NAME: &str = "process";

const KTHREAD_PREFIXES: &[&str] = &["kworker", "kthreadd", "ksoftirqd", "migration/", "rcu_", "kswapd", "watchdog/", "irq/", "jbd2/", "kcompactd", "khugepaged", "kblockd", "kdevtmpfs", "cpuhp/", "oom_reaper", "writeback", "kauditd"];
/// Programs known to rename their comm (threads/processes) legitimately.
const RENAMERS: &[&str] = &[
    "firefox", "firefox-bin", "librewolf", "thunderbird", "chrome", "chromium", "electron", "code", "codium", "brave", "vivaldi-bin", "opera",
    "systemd", "sshd", "sshd-session", "Xorg", "Xwayland", "steam", "java", "wine64-preloader", "wine-preloader", "dbus-daemon", "gnome-shell",
    "plasmashell", "kwin_wayland", "postgres", "nginx", "php-fpm", "sddm-helper", "gdm-session-worker",
];

fn is_interp(b: &str) -> bool {
    b.starts_with("python") || b.starts_with("perl") || b.starts_with("ruby") || b.starts_with("node") || ["bash", "sh", "dash", "zsh", "fish", "busybox", "lua", "php"].contains(&b)
}

/// Judge one process. Returns (severity, reason) items.
pub fn judge(p: &ProcInfo, path_exists: &dyn Fn(&str) -> bool) -> Vec<(Severity, String)> {
    let mut out = Vec::new();
    let Ok(exe) = &p.exe else { return out };
    let deleted = exe.ends_with(" (deleted)");
    let path = exe.trim_end_matches(" (deleted)");
    if path.starts_with("/memfd:") {
        out.push((Severity::High, format!("running from an anonymous memfd ({exe}) — fileless execution")));
        return out;
    }
    if in_temp(path) {
        out.push((Severity::High, format!("executable lives in a temp dir: {exe}")));
    }
    if deleted && !in_temp(path) {
        if path_exists(path) {
            out.push((Severity::Low, format!("running binary was replaced on disk (likely a package upgrade; restart it): {path}")));
        } else {
            out.push((Severity::Med, format!("running binary was deleted from disk: {path}")));
        }
    }
    let exe_base = base(path);
    let looks_kthread = p.comm.starts_with('[') || p.argv0.starts_with('[') || KTHREAD_PREFIXES.iter().any(|k| p.comm.starts_with(k));
    if looks_kthread {
        out.push((Severity::High, format!("userspace process disguised as a kernel thread (comm {:?}, argv0 {:?}, exe {exe})", p.comm, p.argv0)));
    } else if !p.comm.is_empty() && !exe_base.is_empty() {
        let c = p.comm.as_str();
        let exe15: String = exe_base.chars().take(15).collect();
        let matches = exe_base.starts_with(c) || c.starts_with(exe15.as_str());
        if !matches && !is_interp(exe_base) && !RENAMERS.contains(&exe_base) {
            out.push((Severity::Low, format!("process name {c:?} does not match its executable {path}")));
        }
    }
    out
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let proc_dir = ctx.fs.raw(Path::new("/proc"));
    let pids = match proc::list_pids(&proc_dir) {
        Ok(p) if !p.is_empty() => p,
        _ => {
            ctx.note(format!("process check skipped: no procfs at {}", proc_dir.display()));
            return Vec::new();
        }
    };
    let me = std::process::id();
    let mut denied = 0;
    let mut out = Vec::new();
    for pid in pids {
        if pid == me {
            continue;
        }
        let p = proc::read_proc(&proc_dir, pid);
        if p.exe == Err(ErrorKind::PermissionDenied) {
            denied += 1;
            continue;
        }
        let exists = |s: &str| ctx.fs.exists(Path::new(s));
        for (sev, why) in judge(&p, &exists) {
            out.push(Finding::new(
                NAME,
                sev,
                format!("/proc/{pid}"),
                format!("proc:{pid}"),
                format!("pid {pid} ({}): {why}", p.comm),
                format!("Inspect (read-only): ls -l /proc/{pid}/exe; cat /proc/{pid}/cmdline | tr '\\0' ' '; sudo ls -l /proc/{pid}/fd\nPreserve evidence before killing: sudo cp /proc/{pid}/exe /root/pid{pid}.bin\nThen, if malicious: sudo kill -STOP {pid} (and find what started it)"),
            ));
        }
    }
    if denied > 0 {
        let hint = if ctx.euid == 0 { "permission denied even as root (hidepid, container or LSM restrictions)" } else { "owned by other users; run as root" };
        ctx.note(format!("{denied} processes could not be inspected ({hint})"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(comm: &str, exe: &str, argv0: &str) -> ProcInfo {
        ProcInfo { comm: comm.into(), exe: Ok(exe.into()), argv0: argv0.into() }
    }

    fn worst(pi: &ProcInfo, exists: bool) -> Option<Severity> {
        judge(pi, &|_| exists).into_iter().map(|x| x.0).max()
    }

    #[test]
    fn judgements() {
        assert_eq!(worst(&p("bash", "/usr/bin/bash", "-bash"), true), None);
        assert_eq!(worst(&p("x", "/memfd: (deleted)", "x"), false), Some(Severity::High));
        assert_eq!(worst(&p("run", "/tmp/.x/run", "run"), true), Some(Severity::High));
        assert_eq!(worst(&p("sshd", "/usr/bin/sshd (deleted)", "sshd"), true), Some(Severity::Low));
        assert_eq!(worst(&p("evil", "/opt/evil (deleted)", "evil"), false), Some(Severity::Med));
        assert_eq!(worst(&p("kworker/0:1", "/usr/local/bin/miner", "[kworker/0:1]"), true), Some(Severity::High));
        assert_eq!(worst(&p("python3", "/usr/bin/python3.12", "python3"), true), None);
        assert_eq!(worst(&p("Isolated Web Co", "/usr/lib/firefox/firefox", "/usr/lib/firefox/firefox"), true), None);
        assert_eq!(worst(&p("dbus", "/usr/bin/xmrig", "dbus"), true), Some(Severity::Low));
        assert_eq!(worst(&p("systemd-journal", "/usr/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-journald"), true), None);
    }
}
