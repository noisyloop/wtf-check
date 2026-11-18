//! dpkg: parse /var/lib/dpkg/info/*.list directly.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::path::Path;

use crate::util::fs::Fs;

pub const INFO_DIR: &str = "/var/lib/dpkg/info";

pub struct Dpkg {
    fs: Fs,
    files: OnceCell<HashMap<String, String>>,
}

/// `libc6:amd64.list` → `libc6`.
pub fn package_from_list_name(file: &str) -> Option<&str> {
    let stem = file.strip_suffix(".list")?;
    Some(stem.split(':').next().unwrap_or(stem))
}

/// Parse a dpkg `*.md5sums` file: `md5hex  relative/path`.
pub fn parse_md5sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let (h, p) = l.split_once(char::is_whitespace)?;
            let p = p.trim_start();
            (h.len() == 32 && !p.is_empty()).then(|| (format!("/{}", p.trim_start_matches('/')), h.to_ascii_lowercase()))
        })
        .collect()
}

/// Parse /var/lib/dpkg/diversions (triplets: original, diverted-to, package)
/// into original → diverted-to.
pub fn parse_diversions(text: &str) -> HashMap<String, String> {
    let lines: Vec<&str> = text.lines().collect();
    lines.chunks_exact(3).map(|c| (c[0].to_string(), c[1].to_string())).collect()
}

impl Dpkg {
    pub fn detect(fs: &Fs) -> Option<Dpkg> {
        (fs.is_dir(Path::new(INFO_DIR)) && fs.exists(Path::new("/var/lib/dpkg/status"))).then(|| Dpkg { fs: fs.clone(), files: OnceCell::new() })
    }

    pub fn records(&self) -> Vec<super::FileRecord> {
        // A diverted file's packaged version lives at the diverted-to path.
        let diversions = self.fs.read_text(Path::new("/var/lib/dpkg/diversions")).map(|t| parse_diversions(&t)).unwrap_or_default();
        let mut out = Vec::new();
        for f in self.fs.list_dir(Path::new(INFO_DIR)).unwrap_or_default() {
            let fname = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let Some(stem) = fname.strip_suffix(".md5sums") else { continue };
            let pkg = stem.split(':').next().unwrap_or(stem).to_string();
            if let Ok(t) = self.fs.read_text(&f) {
                for (path, digest) in parse_md5sums(&t) {
                    let path = diversions.get(&path).cloned().unwrap_or(path);
                    out.push(super::FileRecord { path, pkg: pkg.clone(), size: None, digest, md5: true });
                }
            }
        }
        out
    }

    pub fn owner(&self, path: &str) -> Option<String> {
        let map = self.files.get_or_init(|| {
            let mut m = HashMap::new();
            for list in self.fs.list_dir(Path::new(INFO_DIR)).unwrap_or_default() {
                let fname = list.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let Some(pkg) = package_from_list_name(&fname) else { continue };
                if let Ok(t) = self.fs.read_text(&list) {
                    for line in t.lines().filter(|l| l.starts_with('/')) {
                        m.insert(line.to_string(), pkg.to_string());
                    }
                }
            }
            m
        });
        map.get(path).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::fs::testutil::FakeRoot;

    #[test]
    fn list_parsing() {
        assert_eq!(package_from_list_name("libc6:amd64.list"), Some("libc6"));
        assert_eq!(package_from_list_name("cron.list"), Some("cron"));
        assert_eq!(package_from_list_name("cron.md5sums"), None);
        let r = FakeRoot::new("dpkg");
        r.write("/var/lib/dpkg/status", "");
        r.write("/var/lib/dpkg/info/cron.list", "/.\n/etc\n/etc/crontab\n/lib/systemd/system/cron.service\n");
        let d = Dpkg::detect(&Fs::new(r.0.clone())).unwrap();
        assert_eq!(d.owner("/etc/crontab").as_deref(), Some("cron"));
        assert_eq!(d.owner("/etc/passwd"), None);
        let d = parse_diversions("/usr/bin/a\n/usr/bin/a.distrib\nfoo\n/x\n/y\n:\n");
        assert_eq!(d.get("/usr/bin/a").map(String::as_str), Some("/usr/bin/a.distrib"));
        assert_eq!(d.len(), 2);
        assert_eq!(parse_md5sums("d41d8cd98f00b204e9800998ecf8427e  usr/bin/x\nbad\n"), vec![("/usr/bin/x".to_string(), "d41d8cd98f00b204e9800998ecf8427e".to_string())]);
    }
}
