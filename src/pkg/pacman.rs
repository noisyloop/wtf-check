//! pacman: parse /var/lib/pacman/local/*/{desc,files} directly (no subprocess).

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::util::fs::Fs;
use crate::util::inflate;

pub const LOCAL_DB: &str = "/var/lib/pacman/local";
pub const SYNC_DB: &str = "/var/lib/pacman/sync";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalPkg {
    pub name: String,
    pub version: String,
    pub install_date: Option<i64>,
    pub build_date: Option<i64>,
    pub packager: String,
    pub validation: String,
}

pub struct Pacman {
    fs: Fs,
    files: OnceCell<HashMap<String, String>>,
    pkgs: OnceCell<Vec<LocalPkg>>,
}

/// Parse a pacman `desc`/`files` file into `%SECTION%` → lines.
pub fn sections(text: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        let l = line.trim_end();
        if l.len() > 2 && l.starts_with('%') && l.ends_with('%') {
            cur = Some(l.trim_matches('%').to_string());
            out.entry(l.trim_matches('%').to_string()).or_default();
        } else if l.is_empty() {
            cur = None;
        } else if let Some(c) = &cur {
            out.entry(c.clone()).or_default().push(l.to_string());
        }
    }
    out
}

pub fn parse_desc(text: &str) -> LocalPkg {
    let s = sections(text);
    let first = |k: &str| s.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
    LocalPkg {
        name: first("NAME"),
        version: first("VERSION"),
        install_date: first("INSTALLDATE").parse().ok(),
        build_date: first("BUILDDATE").parse().ok(),
        packager: first("PACKAGER"),
        validation: s.get("VALIDATION").map(|v| v.join(",")).unwrap_or_default(),
    }
}

/// File paths (absolute, no directories) from a pacman `files` file.
pub fn parse_files(text: &str) -> Vec<String> {
    sections(text)
        .remove("FILES")
        .unwrap_or_default()
        .into_iter()
        .filter(|p| !p.ends_with('/'))
        .map(|p| format!("/{p}"))
        .collect()
}

/// `name-pkgver-pkgrel` → `name`.
pub fn strip_version(dir: &str) -> &str {
    let mut it = dir.rsplitn(3, '-');
    it.next();
    it.next();
    it.next().unwrap_or(dir)
}

impl Pacman {
    pub fn detect(fs: &Fs) -> Option<Pacman> {
        let has_any = fs.list_dir(Path::new(LOCAL_DB)).map(|v| !v.is_empty()).unwrap_or(false);
        has_any.then(|| Pacman { fs: fs.clone(), files: OnceCell::new(), pkgs: OnceCell::new() })
    }

    fn entries(&self) -> Vec<PathBuf> {
        self.fs.list_dir(Path::new(LOCAL_DB)).unwrap_or_default().into_iter().filter(|p| self.fs.is_dir(p)).collect()
    }

    pub fn owner(&self, path: &str) -> Option<String> {
        let map = self.files.get_or_init(|| {
            let mut m = HashMap::new();
            for dir in self.entries() {
                let name = dir.file_name().map(|n| strip_version(&n.to_string_lossy()).to_string()).unwrap_or_default();
                if let Ok(t) = self.fs.read_text(&dir.join("files")) {
                    for f in parse_files(&t) {
                        m.insert(f, name.clone());
                    }
                }
            }
            m
        });
        map.get(path).cloned()
    }

    pub fn packages(&self) -> &[LocalPkg] {
        self.pkgs.get_or_init(|| {
            self.entries().iter().filter_map(|d| self.fs.read_text(&d.join("desc")).ok()).map(|t| parse_desc(&t)).filter(|p| !p.name.is_empty()).collect()
        })
    }

    /// Package names from the sync databases. None if any db can't be read
    /// (e.g. zstd-compressed), so callers fall back to a heuristic.
    fn sync_names(&self) -> Option<HashSet<String>> {
        let dbs: Vec<PathBuf> = self.fs.list_dir(Path::new(SYNC_DB)).ok()?.into_iter().filter(|p| p.extension().is_some_and(|e| e == "db")).collect();
        if dbs.is_empty() {
            return None;
        }
        let mut names = HashSet::new();
        for db in dbs {
            let data = self.fs.read_capped(&db, 512 * 1024 * 1024).ok()?;
            let tar = if inflate::is_gzip(&data) {
                inflate::gunzip(&data, 1024 * 1024 * 1024).ok()?
            } else if data.len() >= 262 && &data[257..262] == b"ustar" {
                data
            } else {
                return None;
            };
            for n in inflate::tar_names(&tar) {
                if let Some(top) = n.split('/').next() {
                    names.insert(strip_version(top).to_string());
                }
            }
        }
        Some(names)
    }

    /// `pacman -Qm` equivalent. Returns (packages, method description).
    pub fn foreign(&self) -> (Vec<LocalPkg>, &'static str) {
        let pkgs = self.packages();
        match self.sync_names() {
            Some(sync) => (pkgs.iter().filter(|p| !sync.contains(&p.name)).cloned().collect(), "not present in any sync database"),
            None => (
                pkgs.iter().filter(|p| !p.packager.contains("@archlinux.org")).cloned().collect(),
                "heuristic: packager is not an @archlinux.org address (sync dbs unreadable)",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::fs::testutil::FakeRoot;

    const DESC: &str = "%NAME%\nyay-bin\n\n%VERSION%\n12.4.2-1\n\n%BUILDDATE%\n1781000000\n\n%INSTALLDATE%\n1781100000\n\n%PACKAGER%\nUnknown Packager\n\n%VALIDATION%\nnone\n\n";

    #[test]
    fn desc_and_files() {
        let p = parse_desc(DESC);
        assert_eq!(p.name, "yay-bin");
        assert_eq!(p.version, "12.4.2-1");
        assert_eq!(p.install_date, Some(1781100000));
        assert_eq!(p.packager, "Unknown Packager");
        let f = parse_files("%FILES%\nusr/\nusr/bin/\nusr/bin/yay\n\n%BACKUP%\netc/x\tabc\n");
        assert_eq!(f, vec!["/usr/bin/yay"]);
        assert_eq!(strip_version("lib32-glibc-2.40+r16-1"), "lib32-glibc");
        assert_eq!(strip_version("foo-1:2.0-3"), "foo");
    }

    #[test]
    fn owner_and_foreign_from_fake_root() {
        let r = FakeRoot::new("pacman");
        r.write("/var/lib/pacman/local/yay-bin-12.4.2-1/desc", DESC);
        r.write("/var/lib/pacman/local/yay-bin-12.4.2-1/files", "%FILES%\nusr/bin/yay\n");
        r.write(
            "/var/lib/pacman/local/bash-5.2-1/desc",
            "%NAME%\nbash\n\n%VERSION%\n5.2-1\n\n%PACKAGER%\nArch Dev <dev@archlinux.org>\n",
        );
        r.write("/var/lib/pacman/local/bash-5.2-1/files", "%FILES%\netc/bash.bashrc\nusr/bin/bash\n");
        r.write("/var/lib/pacman/local/ALPM_DB_VERSION", "9\n");
        let pm = Pacman::detect(&Fs::new(r.0.clone())).unwrap();
        assert_eq!(pm.owner("/usr/bin/bash").as_deref(), Some("bash"));
        assert_eq!(pm.owner("/usr/bin/evil"), None);
        let (f, method) = pm.foreign();
        assert!(method.starts_with("heuristic"));
        assert_eq!(f.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["yay-bin"]);
    }
}
