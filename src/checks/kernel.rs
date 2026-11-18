//! Kernel taint, loaded modules not in the module tree, and eBPF programs.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};

const NAME: &str = "kernel";
const BPFTOOL: &[&str] = &["/usr/bin/bpftool", "/usr/sbin/bpftool", "/sbin/bpftool"];

/// (bit, letter, meaning, severity)
const TAINT: &[(u32, char, &str, Severity)] = &[
    (0, 'P', "proprietary module loaded", Severity::Info),
    (1, 'F', "module was force-loaded", Severity::Med),
    (2, 'S', "SMP with CPUs not designed for SMP", Severity::Info),
    (3, 'R', "module was force-unloaded", Severity::Med),
    (4, 'M', "machine check exception", Severity::Info),
    (5, 'B', "bad page referenced", Severity::Info),
    (6, 'U', "taint requested by userspace", Severity::Low),
    (7, 'D', "kernel died recently (OOPS/BUG)", Severity::Low),
    (8, 'A', "ACPI table overridden", Severity::Low),
    (9, 'W', "kernel issued a warning", Severity::Info),
    (10, 'C', "staging driver loaded", Severity::Info),
    (11, 'I', "platform firmware bug workaround", Severity::Info),
    (12, 'O', "out-of-tree module loaded", Severity::Low),
    (13, 'E', "unsigned module loaded", Severity::Med),
    (14, 'L', "soft lockup occurred", Severity::Info),
    (15, 'K', "kernel live-patched", Severity::Low),
    (16, 'X', "auxiliary taint (distro-defined)", Severity::Info),
    (17, 'T', "built with struct randomization plugin", Severity::Info),
    (18, 'N', "in-kernel test module loaded", Severity::Info),
];

pub fn decode_taint(v: u64) -> Vec<(char, &'static str, Severity)> {
    let mut out: Vec<_> = TAINT.iter().filter(|(b, ..)| v & (1u64 << b) != 0).map(|&(_, l, m, s)| (l, m, s)).collect();
    let known: u64 = TAINT.iter().map(|(b, ..)| 1u64 << b).sum();
    if v & !known != 0 {
        out.push(('?', "unknown taint bits set", Severity::Low));
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct BpfProg {
    pub id: u64,
    pub kind: String,
    pub name: String,
    pub tag: String,
}

/// Parse `bpftool prog show` plain-text output.
pub fn parse_bpftool(text: &str) -> Vec<BpfProg> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((id, rest)) = line.split_once(':') else { continue };
        let Ok(id) = id.trim().parse::<u64>() else { continue };
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let after = |k: &str| toks.iter().position(|t| *t == k).and_then(|i| toks.get(i + 1)).map(|s| s.to_string()).unwrap_or_default();
        out.push(BpfProg { id, kind: toks.first().map(|s| s.to_string()).unwrap_or_default(), name: after("name"), tag: after("tag") });
    }
    out
}

/// Module names from modules.dep / modules.builtin (`kernel/x/foo-bar.ko.zst:` → `foo_bar`).
pub fn module_names(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|l| {
            let path = l.split(':').next()?.trim();
            let file = path.rsplit('/').next()?;
            let name = file.split(".ko").next()?;
            (!name.is_empty()).then(|| name.replace('-', "_"))
        })
        .collect()
}

fn run_bpftool(bin: &str) -> Option<String> {
    let mut child = Command::new(bin).args(["prog", "show"]).env_clear().env("LC_ALL", "C").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > Duration::from_secs(15) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
    let mut s = String::new();
    child.stdout.take()?.read_to_string(&mut s).ok()?;
    Some(s)
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    let tpath = ctx.fs.raw(Path::new("/proc/sys/kernel/tainted"));
    match std::fs::read_to_string(&tpath) {
        Ok(t) => {
            let v: u64 = t.trim().parse().unwrap_or(0);
            ctx.record("kernel:tainted".into(), v.to_string(), false);
            if v != 0 {
                let flags = decode_taint(v);
                let sev = flags.iter().map(|f| f.2).max().unwrap_or(Severity::Info);
                let desc: Vec<String> = flags.iter().map(|(l, m, _)| format!("{l}: {m}")).collect();
                out.push(Finding::new(
                    NAME,
                    sev,
                    tpath.display().to_string(),
                    "kernel:tainted",
                    format!("kernel is tainted ({v}): {}", desc.join("; ")),
                    "List out-of-tree/unsigned modules: grep -E '\\((O|E|OE|P|PO|POE)\\)' /proc/modules\nCheck each with: modinfo <name>",
                ));
            }
        }
        Err(_) => ctx.note("kernel taint not checked: /proc/sys/kernel/tainted not readable under this root".into()),
    }

    // Loaded modules vs. the module tree of the running kernel.
    let modules = std::fs::read_to_string(ctx.fs.raw(Path::new("/proc/modules"))).unwrap_or_default();
    let release = std::fs::read_to_string(ctx.fs.raw(Path::new("/proc/sys/kernel/osrelease"))).unwrap_or_default();
    let release = release.trim();
    if !modules.is_empty() && !release.is_empty() {
        let mut known = HashSet::new();
        let mut found_tree = false;
        for base in ["/usr/lib/modules", "/lib/modules"] {
            for f in ["modules.dep", "modules.builtin"] {
                if let Ok(t) = ctx.fs.read_text(Path::new(&format!("{base}/{release}/{f}"))) {
                    found_tree = true;
                    known.extend(module_names(&t));
                }
            }
        }
        if found_tree {
            for line in modules.lines() {
                let name = line.split_whitespace().next().unwrap_or("").replace('-', "_");
                if !name.is_empty() && !known.contains(&name) {
                    out.push(Finding::new(
                        NAME,
                        Severity::Med,
                        format!("/proc/modules ({name})"),
                        format!("kernel:module:{name}"),
                        format!("loaded module {name:?} is not in the module tree for kernel {release} (manually insmod'ed or removed after loading)"),
                        format!("Inspect: modinfo {q}; cat /sys/module/{q}/taint 2>/dev/null\nIf unknown, reboot from trusted media and investigate.", q = crate::util::shell_quote(&name)),
                    ));
                }
            }
        }
    }

    // eBPF programs (live system, root only; host's bpftool only).
    if ctx.live && ctx.euid == 0 {
        match BPFTOOL.iter().find(|b| Path::new(b).is_file()) {
            Some(bin) => match run_bpftool(bin) {
                Some(text) => {
                    for p in parse_bpftool(&text) {
                        let key = format!("ebpf:{}:{}:{}", p.kind, p.name, p.tag);
                        ctx.record(key.clone(), p.tag.clone(), false);
                        out.push(Finding::new(
                            NAME,
                            Severity::Info,
                            format!("bpf prog {}", p.id),
                            key,
                            format!("loaded eBPF program: type {} name {} tag {}", p.kind, if p.name.is_empty() { "(none)" } else { &p.name }, p.tag),
                            format!("Inspect: sudo {bin} prog show id {}; sudo {bin} link show", p.id),
                        ));
                    }
                }
                None => ctx.note(format!("{bin} prog show failed or timed out")),
            },
            None => ctx.note("bpftool not installed: eBPF programs not listed".into()),
        }
    } else if ctx.live {
        ctx.note("eBPF programs not listed (needs root)".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_decode() {
        assert!(decode_taint(0).is_empty());
        let d = decode_taint(4096 + 8192);
        assert_eq!(d.iter().map(|x| x.0).collect::<String>(), "OE");
        assert_eq!(d.iter().map(|x| x.2).max(), Some(Severity::Med));
        assert_eq!(decode_taint(1 << 40).last().unwrap().0, '?');
    }

    #[test]
    fn bpftool_parsing() {
        let t = "3: cgroup_device  tag 03b4eaae2f14641a  gpl\n\tloaded_at 2026-01-01T00:00:00+0000  uid 0\n\txlated 296B  jited 192B  memlock 4096B\n45: tracing  name hid_tail_call  tag 7cc47bbf07148bfe  gpl\n";
        let p = parse_bpftool(t);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], BpfProg { id: 3, kind: "cgroup_device".into(), name: "".into(), tag: "03b4eaae2f14641a".into() });
        assert_eq!(p[1].name, "hid_tail_call");
    }

    #[test]
    fn modules_dep() {
        let n = module_names("kernel/drivers/net/foo-bar.ko.zst: kernel/x.ko\nupdates/dkms/nvidia.ko:\n");
        assert!(n.contains("foo_bar") && n.contains("nvidia"));
    }
}
