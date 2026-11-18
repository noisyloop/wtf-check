//! Shared scan context: root, users' homes, package DB, notes and inventory.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use crate::pkg::{Backend, Ownership};
use crate::util::fs::Fs;
use crate::util::{proc, shell_quote};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    pub user: String,
    /// Logical path.
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub home: String,
}

pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(PasswdEntry { name: f[0].to_string(), uid: f[2].parse().ok()?, home: f[5].to_string() })
        })
        .collect()
}

pub struct Ctx {
    pub fs: Fs,
    /// Scanning the running system (root is `/`).
    pub live: bool,
    pub euid: u32,
    pub homes: Vec<Home>,
    pub pkg: Backend,
    pub distro: String,
    /// `--deep`: verify every package file, not just security-critical ones.
    pub deep: bool,
    notes: RefCell<BTreeSet<String>>,
    inventory: RefCell<BTreeMap<String, String>>,
    /// Inventory keys whose changes alone are expected (package-owned files).
    quiet: RefCell<BTreeSet<String>>,
}

impl Ctx {
    pub fn new(root: PathBuf) -> Ctx {
        let fs = Fs::new(root);
        let live = fs.is_host_root();
        let euid = proc::euid().unwrap_or(u32::MAX);
        let pkg = Backend::detect(&fs);
        let distro = fs
            .read_text(Path::new("/etc/os-release"))
            .ok()
            .and_then(|t| t.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string())))
            .unwrap_or_else(|| "unknown".into());
        let mut ctx = Ctx {
            fs,
            live,
            euid,
            homes: Vec::new(),
            pkg,
            distro,
            deep: false,
            notes: RefCell::new(BTreeSet::new()),
            inventory: RefCell::new(BTreeMap::new()),
            quiet: RefCell::new(BTreeSet::new()),
        };
        ctx.homes = ctx.discover_homes();
        ctx
    }

    pub fn all_users_mode(&self) -> bool {
        self.euid == 0 || !self.live
    }

    fn discover_homes(&self) -> Vec<Home> {
        let passwd = self.fs.read_text(Path::new("/etc/passwd")).map(|t| parse_passwd(&t)).unwrap_or_default();
        let mut homes: Vec<Home> = Vec::new();
        let mut push = |user: String, path: PathBuf| {
            if path != Path::new("/") && !homes.iter().any(|h| h.path == path) {
                homes.push(Home { user, path });
            }
        };
        if self.all_users_mode() {
            for e in &passwd {
                if (e.uid == 0 || (1000..60000).contains(&e.uid)) && e.home.starts_with('/') && self.fs.is_dir(Path::new(&e.home)) {
                    push(e.name.clone(), PathBuf::from(&e.home));
                }
            }
            if self.fs.is_dir(Path::new("/root")) {
                push("root".into(), PathBuf::from("/root"));
            }
            for d in self.fs.list_dir(Path::new("/home")).unwrap_or_default() {
                if self.fs.is_dir(&d) {
                    let name = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    let user = passwd.iter().find(|e| Path::new(&e.home) == d).map(|e| e.name.clone()).unwrap_or(name);
                    push(user, d);
                }
            }
        } else {
            let me = passwd.iter().find(|e| e.uid == self.euid);
            let home = me.map(|e| e.home.clone()).or_else(|| std::env::var("HOME").ok());
            if let Some(h) = home {
                push(me.map(|e| e.name.clone()).unwrap_or_else(|| "me".into()), PathBuf::from(h));
            }
            self.note("running as a normal user: only your own home was scanned, and root-only files are skipped (run with sudo for a full audit)".into());
        }
        homes
    }

    pub fn note(&self, s: String) {
        self.notes.borrow_mut().insert(s);
    }

    pub fn note_err(&self, logical: &Path, e: &io::Error) {
        match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::InvalidInput => {}
            io::ErrorKind::PermissionDenied => self.note(format!("unreadable (permission denied): {}", self.disp(logical))),
            _ => self.note(format!("error reading {}: {e}", self.disp(logical))),
        }
    }

    pub fn notes(&self) -> Vec<String> {
        self.notes.borrow().iter().cloned().collect()
    }

    pub fn disp(&self, logical: &Path) -> String {
        self.fs.display(logical)
    }

    /// Display path, shell-quoted for fix commands.
    pub fn q(&self, logical: &Path) -> String {
        shell_quote(&self.disp(logical))
    }

    pub fn read_text(&self, logical: &Path) -> Option<String> {
        match self.fs.read_text(logical) {
            Ok(t) => Some(t),
            Err(e) => {
                self.note_err(logical, &e);
                None
            }
        }
    }

    pub fn list(&self, logical: &Path) -> Vec<PathBuf> {
        match self.fs.list_dir(logical) {
            Ok(v) => v,
            Err(e) => {
                self.note_err(logical, &e);
                Vec::new()
            }
        }
    }

    pub fn key(check: &str, logical: &Path) -> String {
        format!("{check}:{}", logical.display())
    }

    pub fn record(&self, key: String, value: String, quiet: bool) {
        if quiet {
            self.quiet.borrow_mut().insert(key.clone());
        }
        self.inventory.borrow_mut().insert(key, value);
    }

    /// Hash a checked file into the inventory under `key`.
    pub fn record_file(&self, key: &str, logical: &Path, quiet: bool) {
        let v = self.fs.sha256(logical).unwrap_or_else(|e| format!("unreadable:{:?}", e.kind()));
        self.record(key.to_string(), v, quiet);
    }

    pub fn inventory(&self) -> BTreeMap<String, String> {
        self.inventory.borrow().clone()
    }

    pub fn is_quiet(&self, key: &str) -> bool {
        self.quiet.borrow().contains(key)
    }

    pub fn home_of(&self, logical: &Path) -> Option<&Home> {
        self.homes.iter().find(|h| logical.starts_with(&h.path))
    }

    pub fn owner(&self, logical: &Path) -> Ownership {
        self.pkg.owner(&logical.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_parsing() {
        let t = "root:x:0:0:root:/root:/bin/bash\n# c\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\nbad line\nnobody:x:65534:65534::/:/usr/bin/nologin\n";
        let p = parse_passwd(t);
        assert_eq!(p.len(), 3);
        assert_eq!(p[1], PasswdEntry { name: "alice".into(), uid: 1000, home: "/home/alice".into() });
    }
}
