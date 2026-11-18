//! /proc helpers (procfs is read directly; nothing is executed).

use std::fs;
use std::io;
use std::path::Path;

/// (real, effective) uid from a /proc/<pid>/status text.
pub fn parse_status_uid(text: &str) -> Option<(u32, u32)> {
    let line = text.lines().find(|l| l.starts_with("Uid:"))?;
    let mut it = line[4..].split_whitespace();
    let real = it.next()?.parse().ok()?;
    let eff = it.next()?.parse().ok()?;
    Some((real, eff))
}

/// Effective uid of this process (always from the host's /proc).
pub fn euid() -> Option<u32> {
    parse_status_uid(&fs::read_to_string("/proc/self/status").ok()?).map(|(_, e)| e)
}

pub fn list_pids(proc_dir: &Path) -> io::Result<Vec<u32>> {
    let mut pids: Vec<u32> = fs::read_dir(proc_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
        .collect();
    pids.sort_unstable();
    Ok(pids)
}

pub struct ProcInfo {
    pub comm: String,
    /// readlink of /proc/<pid>/exe.
    pub exe: Result<String, io::ErrorKind>,
    pub argv0: String,
}

pub fn read_proc(proc_dir: &Path, pid: u32) -> ProcInfo {
    let base = proc_dir.join(pid.to_string());
    let comm = fs::read_to_string(base.join("comm")).unwrap_or_default().trim_end_matches('\n').to_string();
    let exe = fs::read_link(base.join("exe")).map(|p| p.to_string_lossy().into_owned()).map_err(|e| e.kind());
    let cmdline = fs::read(base.join("cmdline")).unwrap_or_default();
    let argv0 = String::from_utf8_lossy(cmdline.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
    ProcInfo { comm, exe, argv0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_uid() {
        let t = "Name:\tbash\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_uid(t), Some((1000, 0)));
        assert_eq!(parse_status_uid("Name: x\n"), None);
    }
}
