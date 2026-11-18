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

/// Decode mtree/vis octal escapes such as `\\040` (space).
fn unvis(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push(((b[i + 1] - b'0') << 6) | ((b[i + 2] - b'0') << 3) | (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a (decompressed) pacman `.MTREE`: regular files with size + sha256.
pub fn parse_mtree(text: &str) -> Vec<(String, Option<u64>, String)> {
    let mut defaults: HashMap<String, String> = HashMap::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut toks = line.split_whitespace();
        let first = toks.next().unwrap_or("");
        if first == "/set" {
            for kv in toks {
                if let Some((k, v)) = kv.split_once('=') {
                    defaults.insert(k.into(), v.into());
                }
            }
            continue;
        }
        if first == "/unset" {
            for k in toks {
                defaults.remove(k);
            }
            continue;
        }
        let mut kv = defaults.clone();
        for t in toks {
            if let Some((k, v)) = t.split_once('=') {
                kv.insert(k.into(), v.into());
            }
        }
        let path = unvis(first.trim_start_matches('.'));
        if !path.starts_with('/') || (path.starts_with("/.") && !path[2..].contains('/')) {
            continue; // ./.PKGINFO, ./.BUILDINFO, ./.MTREE, ./.INSTALL
        }
        if kv.get("type").map(String::as_str) != Some("file") {
            continue;
        }
        if let Some(d) = kv.get("sha256digest") {
            out.push((path, kv.get("size").and_then(|s| s.parse().ok()), d.clone()));
        }
    }
    out
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

    /// Checksum records from every package's mtree, minus %BACKUP% (config) files.
    pub fn records(&self) -> Vec<super::FileRecord> {
        let mut out = Vec::new();
        for dir in self.entries() {
            let name = dir.file_name().map(|n| strip_version(&n.to_string_lossy()).to_string()).unwrap_or_default();
            let backup: HashSet<String> = self
                .fs
                .read_text(&dir.join("files"))
                .map(|t| sections(&t).remove("BACKUP").unwrap_or_default().iter().filter_map(|l| l.split('\t').next()).map(|p| format!("/{p}")).collect())
                .unwrap_or_default();
            let Ok(raw) = self.fs.read_capped(&dir.join("mtree"), 64 * 1024 * 1024) else { continue };
            let text = if inflate::is_gzip(&raw) {
                match inflate::gunzip(&raw, 256 * 1024 * 1024) {
                    Ok(t) => t,
                    Err(_) => continue,
                }
            } else {
                raw
            };
            for (path, size, digest) in parse_mtree(&String::from_utf8_lossy(&text)) {
                if !backup.contains(&path) {
                    out.push(super::FileRecord { path, pkg: name.clone(), size, digest, md5: false });
                }
            }
        }
        out
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

    /// Wrap bytes in a gzip stream using one stored (uncompressed) block.
    pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        g.push(1);
        let len = data.len() as u16;
        g.extend(len.to_le_bytes());
        g.extend((!len).to_le_bytes());
        g.extend(data);
        g.extend([0u8; 8]);
        g
    }

    #[test]
    fn mtree_parsing() {
        let t = "#mtree\n/set type=file uid=0 gid=0 mode=644\n./.PKGINFO time=1 size=10 sha256digest=aa\n./usr time=1 mode=755 type=dir\n./usr/bin/bash time=1 mode=755 size=5 sha256digest=bb\n./usr/bin/sh time=1 type=link link=bash\n./usr/share/my\\040file size=1 sha256digest=cc\n";
        let m = parse_mtree(t);
        assert_eq!(m, vec![("/usr/bin/bash".into(), Some(5), "bb".into()), ("/usr/share/my file".into(), Some(1), "cc".into())]);
        let r = FakeRoot::new("mtree");
        r.write("/var/lib/pacman/local/bash-5.2-1/desc", "%NAME%\nbash\n");
        r.write("/var/lib/pacman/local/bash-5.2-1/files", "%FILES%\netc/bash.bashrc\nusr/bin/bash\n\n%BACKUP%\netc/bash.bashrc\tabc\n");
        let mt = "/set type=file\n./etc/bash.bashrc size=1 sha256digest=dd\n./usr/bin/bash size=5 sha256digest=bb\n";
        std::fs::write(r.0.join("var/lib/pacman/local/bash-5.2-1/mtree"), gzip_stored(mt.as_bytes())).unwrap();
        let pm = Pacman::detect(&Fs::new(r.0.clone())).unwrap();
        let recs = pm.records();
        assert_eq!(recs.len(), 1, "backup files are skipped");
        assert_eq!(recs[0].path, "/usr/bin/bash");
        assert_eq!(recs[0].pkg, "bash");
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
