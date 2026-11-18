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

impl Dpkg {
    pub fn detect(fs: &Fs) -> Option<Dpkg> {
        (fs.is_dir(Path::new(INFO_DIR)) && fs.exists(Path::new("/var/lib/dpkg/status"))).then(|| Dpkg { fs: fs.clone(), files: OnceCell::new() })
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
    }
}
