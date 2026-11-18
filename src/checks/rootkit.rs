//! Rootkit indicators:
//! 1. A small, curated set of on-disk IOCs from public analyses of Linux
//!    rootkits and malware families (works offline with --root).
//! 2. Hidden processes: PIDs that exist (stat /proc/N succeeds) but are
//!    missing from the /proc directory listing, which is what getdents-hooking
//!    rootkits such as Diamorphine do (live only; the `unhide` brute technique).
//! 3. Hidden kernel modules: present in /sys/module as loadable modules but
//!    missing from /proc/modules (live only).
//!
//! The IOC list is deliberately small and high-confidence. For broad
//! signature coverage, also run rkhunter or chkrootkit (see README).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};
use crate::pkg::Ownership;
use crate::util::proc;

const NAME: &str = "rootkit";

pub struct Ioc {
    pub path: &'static str,
    pub family: &'static str,
    pub source: &'static str,
    /// Only flag if no package owns the path (the name can be legitimate).
    pub unowned_only: bool,
}

const fn ioc(path: &'static str, family: &'static str, source: &'static str) -> Ioc {
    Ioc { path, family, source, unowned_only: false }
}
const fn ioc_unowned(path: &'static str, family: &'static str, source: &'static str) -> Ioc {
    Ioc { path, family, source, unowned_only: true }
}

pub const IOCS: &[Ioc] = &[
    ioc("/usr/local/lib/libprocesshider.so", "libprocesshider (LD_PRELOAD process hider)", "https://github.com/gianlucaborello/libprocesshider"),
    ioc("/XxJynx", "Jynx2 LD_PRELOAD rootkit", "rkhunter signature set"),
    ioc("/reptile", "Reptile LKM rootkit (default install dir)", "https://github.com/f0rb1dd3n/Reptile"),
    ioc("/tmp/kdevtmpfsi", "Kinsing cryptominer", "Aqua Security Kinsing analysis (2020)"),
    ioc("/var/tmp/kinsing", "Kinsing cryptominer", "Aqua Security Kinsing analysis (2020)"),
    ioc("/tmp/kinsing", "Kinsing cryptominer", "Aqua Security Kinsing analysis (2020)"),
    ioc("/dev/shm/kdmtmpflush", "BPFDoor backdoor", "Sandfly Security / Elastic BPFDoor analyses (2022)"),
    ioc("/var/run/haldrund.pid", "BPFDoor backdoor", "Sandfly Security / Elastic BPFDoor analyses (2022)"),
    ioc("/etc/cron.hourly/gcc.sh", "XorDDoS botnet", "Microsoft Security XorDDoS analysis (2022)"),
    ioc_unowned("/lib/libudev.so", "XorDDoS botnet (copy of itself)", "Microsoft Security XorDDoS analysis (2022)"),
    ioc("/root/.config/cron/perfcc", "perfctl cryptominer/rootkit", "Aqua Nautilus perfctl analysis (2024)"),
    ioc_unowned("/usr/bin/perfcc", "perfctl cryptominer/rootkit", "Aqua Nautilus perfctl analysis (2024)"),
    ioc_unowned("/usr/lib/libpprocps.so", "perfctl rootkit library", "Aqua Nautilus perfctl analysis (2024)"),
    ioc_unowned("/usr/lib/libfsnkdev.so", "perfctl rootkit library", "Aqua Nautilus perfctl analysis (2024)"),
    ioc("/lib/libntpVnQE6mk", "OrBit LD_PRELOAD rootkit", "Intezer OrBit analysis (2022)"),
    ioc("/dev/shm/ldx", "OrBit LD_PRELOAD rootkit", "Intezer OrBit analysis (2022)"),
];

/// Kernel module names of public LKM rootkits.
pub const ROOTKIT_MODULES: &[(&str, &str)] = &[
    ("diamorphine", "https://github.com/m0nad/Diamorphine"),
    ("reptile", "https://github.com/f0rb1dd3n/Reptile"),
    ("reptile_module", "https://github.com/f0rb1dd3n/Reptile"),
    ("suterusu", "https://github.com/mncoppola/suterusu"),
];

fn ioc_findings(ctx: &Ctx, out: &mut Vec<Finding>) {
    for i in IOCS {
        let p = Path::new(i.path);
        if ctx.fs.lstat(p).is_err() {
            continue;
        }
        if i.unowned_only && !matches!(ctx.owner(p), Ownership::Unowned) {
            continue;
        }
        let key = Ctx::key(NAME, p);
        ctx.record(key.clone(), "present".into(), false);
        out.push(Finding::new(
            NAME,
            Severity::High,
            ctx.disp(p),
            key,
            format!("matches a known indicator of {} (source: {})", i.family, i.source),
            format!(
                "Don't run or open it. Preserve it for analysis: sudo cp -a {q} /root/evidence/\nTreat the system as compromised: scan from a live USB (--root), rotate credentials from a trusted device, and plan a reinstall.",
                q = ctx.q(p)
            ),
        ));
    }
}

/// PIDs that stat() can see but the directory listing hides. `exists` and
/// `tgid_of` are injected for testing.
pub fn hidden_pids(listed: &HashSet<u32>, pid_max: u32, exists: &dyn Fn(u32) -> bool, tgid_of: &dyn Fn(u32) -> Option<u32>) -> Vec<u32> {
    (1..=pid_max).filter(|p| !listed.contains(p) && exists(*p) && tgid_of(*p) == Some(*p)).collect()
}

fn tgid(proc_dir: &Path, pid: u32) -> Option<u32> {
    let t = fs::read_to_string(proc_dir.join(pid.to_string()).join("status")).ok()?;
    t.lines().find_map(|l| l.strip_prefix("Tgid:")).and_then(|v| v.trim().parse().ok())
}

fn live_checks(ctx: &Ctx, out: &mut Vec<Finding>) {
    let proc_dir = Path::new("/proc");
    let Ok(first) = proc::list_pids(proc_dir) else { return };
    let pid_max: u32 = fs::read_to_string("/proc/sys/kernel/pid_max").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(32768).min(4_194_304);
    let listed: HashSet<u32> = first.into_iter().collect();
    let exists = |p: u32| fs::symlink_metadata(proc_dir.join(p.to_string())).is_ok();
    let tg = |p: u32| tgid(proc_dir, p);
    let candidates = hidden_pids(&listed, pid_max, &exists, &tg);
    ctx.note(format!("rootkit: probed all {pid_max} possible PIDs for processes hidden from the /proc listing"));
    if !candidates.is_empty() {
        // Re-list to rule out processes that started during the scan.
        let again: HashSet<u32> = proc::list_pids(proc_dir).unwrap_or_default().into_iter().collect();
        for pid in candidates.into_iter().filter(|p| !again.contains(p) && exists(*p)) {
            let info = proc::read_proc(proc_dir, pid);
            out.push(Finding::new(
                NAME,
                Severity::High,
                format!("/proc/{pid}"),
                format!("rootkit:hidden-pid:{pid}"),
                format!(
                    "process {pid} ({}, exe {}) exists but is hidden from the /proc listing — a classic kernel rootkit technique",
                    info.comm,
                    info.exe.as_deref().unwrap_or("unreadable")
                ),
                format!("Inspect: cat /proc/{pid}/status; ls -l /proc/{pid}/exe\nAssume a kernel-level compromise: power off, scan from a live USB with --root, and plan a reinstall."),
            ));
        }
    }

    // Loadable modules visible in sysfs but not in /proc/modules.
    let listed_mods: HashSet<String> = fs::read_to_string("/proc/modules").unwrap_or_default().lines().filter_map(|l| l.split_whitespace().next()).map(|s| s.to_string()).collect();
    let mut all_mods = listed_mods.clone();
    if let Ok(rd) = fs::read_dir("/sys/module") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            all_mods.insert(name.clone());
            // Only loadable modules have `initstate`; built-ins don't.
            if e.path().join("initstate").exists() && !listed_mods.contains(&name) {
                out.push(Finding::new(
                    NAME,
                    Severity::High,
                    format!("/sys/module/{name}"),
                    format!("rootkit:hidden-module:{name}"),
                    format!("kernel module {name:?} is loaded (in /sys/module) but hidden from /proc/modules"),
                    "Assume a kernel-level compromise: power off, scan from a live USB with --root, and plan a reinstall.",
                ));
            }
        }
    }
    for (m, src) in ROOTKIT_MODULES {
        if all_mods.contains(*m) {
            out.push(Finding::new(
                NAME,
                Severity::High,
                format!("kernel module {m}"),
                format!("rootkit:module:{m}"),
                format!("a kernel module named like a public LKM rootkit is loaded: {m} ({src})"),
                "Assume a kernel-level compromise: power off, scan from a live USB with --root, and plan a reinstall.",
            ));
        }
    }
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    ioc_findings(ctx, &mut out);
    if ctx.live {
        live_checks(ctx, &mut out);
    } else {
        ctx.note("rootkit: hidden process/module detection needs the live system; offline scan checked on-disk indicators only".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{find, run_check};
    use crate::util::fs::testutil::FakeRoot;

    #[test]
    fn hidden_pid_logic() {
        let listed: HashSet<u32> = [1, 2, 100].into_iter().collect();
        // 50 is a hidden process; 101 is a thread of 100 (tgid 100); 7 doesn't exist.
        let exists = |p: u32| [1, 2, 50, 100, 101].contains(&p);
        let tgid = |p: u32| Some(if p == 101 { 100 } else { p });
        assert_eq!(hidden_pids(&listed, 200, &exists, &tgid), vec![50]);
    }

    #[test]
    fn iocs_offline() {
        let r = FakeRoot::new("rootkit");
        r.write("/usr/local/lib/libprocesshider.so", "x");
        r.mkdir("/dev/shm/ldx");
        // Package-owned libudev.so (Arch) must not be flagged.
        r.write("/var/lib/pacman/local/systemd-libs-1-1/desc", "%NAME%\nsystemd-libs\n");
        r.write("/var/lib/pacman/local/systemd-libs-1-1/files", "%FILES%\nusr/lib/libudev.so\n");
        r.write("/usr/lib/libudev.so", "x");
        r.symlink("usr/lib", "/lib");
        let (_, v) = run_check(&r, run);
        assert!(find(&v, "libprocesshider.so").is_some());
        assert!(find(&v, "/dev/shm/ldx").is_some());
        assert!(find(&v, "libudev.so").is_none(), "{v:?}");
    }
}
