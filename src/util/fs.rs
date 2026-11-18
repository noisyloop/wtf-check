//! Read-only filesystem access confined to a scan root.
//!
//! All paths handled by checks are *logical* (absolute, as seen by the scanned
//! system, e.g. `/etc/crontab`). `Fs` maps them under `--root`, and resolves
//! symlinks itself so that an absolute link target on a mounted disk is
//! re-anchored to the root instead of escaping to the host.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
const O_NONBLOCK: i32 = 0x80;
#[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
const O_NONBLOCK: i32 = 0x4000;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64", target_arch = "sparc", target_arch = "sparc64")))]
const O_NONBLOCK: i32 = 0o4000;

pub const MAX_TEXT: u64 = 8 * 1024 * 1024;
const MAX_LINK_HOPS: usize = 40;

#[derive(Clone, Debug)]
pub struct Fs {
    root: PathBuf,
}

pub struct WalkStats {
    pub truncated: bool,
    pub errors: Vec<(PathBuf, io::Error)>,
}

impl Fs {
    pub fn new(root: PathBuf) -> Fs {
        Fs { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_host_root(&self) -> bool {
        self.root == Path::new("/")
    }

    /// Map a logical path under the root without resolving anything.
    pub fn raw(&self, logical: &Path) -> PathBuf {
        let rel = logical.strip_prefix("/").unwrap_or(logical);
        if rel.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    /// The real on-disk path, for display and for fix commands.
    pub fn display(&self, logical: &Path) -> String {
        self.raw(logical).to_string_lossy().into_owned()
    }

    /// Resolve symlinks within the root, returning a canonical *logical* path.
    /// Missing components are kept as-is (callers then get NotFound).
    pub fn resolve(&self, logical: &Path, follow_last: bool) -> io::Result<PathBuf> {
        let mut pending: VecDeque<OsString> = VecDeque::new();
        push_components(&mut pending, logical, false);
        let mut out = PathBuf::from("/");
        let mut hops = 0;
        while let Some(c) = pending.pop_front() {
            if c == ".." {
                out.pop();
                continue;
            }
            let cand = out.join(&c);
            if pending.is_empty() && !follow_last {
                return Ok(cand);
            }
            match fs::symlink_metadata(self.raw(&cand)) {
                Ok(m) if m.file_type().is_symlink() => {
                    hops += 1;
                    if hops > MAX_LINK_HOPS {
                        return Err(io::Error::other("too many levels of symbolic links"));
                    }
                    let target = fs::read_link(self.raw(&cand))?;
                    if target.is_absolute() {
                        out = PathBuf::from("/");
                    }
                    push_components(&mut pending, &target, true);
                }
                Ok(_) => out = cand,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    out = cand;
                    for rest in pending.drain(..) {
                        if rest == ".." {
                            out.pop();
                        } else {
                            out.push(rest);
                        }
                    }
                    return Ok(out);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn lstat(&self, logical: &Path) -> io::Result<Metadata> {
        fs::symlink_metadata(self.raw(&self.resolve(logical, false)?))
    }

    pub fn stat(&self, logical: &Path) -> io::Result<Metadata> {
        fs::symlink_metadata(self.raw(&self.resolve(logical, true)?))
    }

    pub fn exists(&self, logical: &Path) -> bool {
        self.stat(logical).is_ok()
    }

    pub fn is_dir(&self, logical: &Path) -> bool {
        self.stat(logical).map(|m| m.is_dir()).unwrap_or(false)
    }

    /// Sorted logical children of a directory (directory symlinks followed).
    pub fn list_dir(&self, logical: &Path) -> io::Result<Vec<PathBuf>> {
        let dir = self.resolve(logical, true)?;
        let mut out = Vec::new();
        for ent in fs::read_dir(self.raw(&dir))? {
            out.push(dir.join(ent?.file_name()));
        }
        out.sort();
        Ok(out)
    }

    fn open_regular(&self, logical: &Path) -> io::Result<(File, Metadata)> {
        let real = self.raw(&self.resolve(logical, true)?);
        let m = fs::symlink_metadata(&real)?;
        if !m.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        // O_NONBLOCK: never hang if the file is swapped for a FIFO in between.
        let f = fs::OpenOptions::new().read(true).custom_flags(O_NONBLOCK).open(&real)?;
        Ok((f, m))
    }

    /// Read at most `cap` bytes of a regular file.
    pub fn read_capped(&self, logical: &Path, cap: u64) -> io::Result<Vec<u8>> {
        let (f, _) = self.open_regular(logical)?;
        let mut buf = Vec::new();
        f.take(cap).read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn read_text(&self, logical: &Path) -> io::Result<String> {
        Ok(String::from_utf8_lossy(&self.read_capped(logical, MAX_TEXT)?).into_owned())
    }

    /// SHA-256 of a regular file (streamed; huge files hash their first 256 MiB).
    pub fn sha256(&self, logical: &Path) -> io::Result<String> {
        let (f, _) = self.open_regular(logical)?;
        super::sha256::hash_reader(f.take(256 * 1024 * 1024))
    }

    /// Full SHA-256 or MD5 of a regular file plus its size (no size cap).
    pub fn digest_full(&self, logical: &Path, md5: bool) -> io::Result<(String, u64)> {
        let (f, m) = self.open_regular(logical)?;
        let h = if md5 { super::md5::hash_reader(f)? } else { super::sha256::hash_reader(f)? };
        Ok((h, m.len()))
    }

    /// Depth-limited walk that never follows symlinks. `f` receives the
    /// logical path, its lstat metadata and depth (1 = direct child), and
    /// returns whether to descend into it (only meaningful for directories).
    pub fn walk(
        &self,
        logical: &Path,
        max_depth: usize,
        max_entries: usize,
        f: &mut dyn FnMut(&Path, &Metadata, usize) -> bool,
    ) -> WalkStats {
        let mut stats = WalkStats { truncated: false, errors: Vec::new() };
        let start = match self.resolve(logical, true) {
            Ok(p) => p,
            Err(e) => {
                stats.errors.push((logical.to_path_buf(), e));
                return stats;
            }
        };
        let mut stack = vec![(start, 0usize)];
        let mut seen = 0usize;
        while let Some((dir, depth)) = stack.pop() {
            let rd = match fs::read_dir(self.raw(&dir)) {
                Ok(rd) => rd,
                Err(e) => {
                    if e.kind() != io::ErrorKind::NotFound {
                        stats.errors.push((dir, e));
                    }
                    continue;
                }
            };
            let mut children: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
            children.sort();
            for name in children {
                seen += 1;
                if seen > max_entries {
                    stats.truncated = true;
                    return stats;
                }
                let child = dir.join(name);
                let md = match fs::symlink_metadata(self.raw(&child)) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let descend = f(&child, &md, depth + 1);
                if descend && md.is_dir() && depth + 1 < max_depth {
                    stack.push((child, depth + 1));
                }
            }
        }
        stats
    }
}

fn push_components(q: &mut VecDeque<OsString>, p: &Path, front: bool) {
    let comps: Vec<OsString> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect();
    if front {
        for c in comps.into_iter().rev() {
            q.push_front(c);
        }
    } else {
        q.extend(comps);
    }
}

/// True if a logical path lies in a world-writable temp location.
pub fn in_temp(p: &str) -> bool {
    ["/tmp", "/var/tmp", "/dev/shm"].iter().any(|t| p == *t || (p.starts_with(t) && p.as_bytes().get(t.len()) == Some(&b'/')))
}

#[cfg(test)]
pub mod testutil {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A temporary fake root, removed on drop.
    pub struct FakeRoot(pub PathBuf);

    impl FakeRoot {
        pub fn new(tag: &str) -> FakeRoot {
            static N: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "wtf-check-test-{}-{}-{}",
                std::process::id(),
                tag,
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            FakeRoot(p)
        }

        pub fn write(&self, logical: &str, content: &str) -> PathBuf {
            let p = self.0.join(logical.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, content).unwrap();
            p
        }

        pub fn mkdir(&self, logical: &str) {
            std::fs::create_dir_all(self.0.join(logical.trim_start_matches('/'))).unwrap();
        }

        pub fn symlink(&self, target: &str, logical: &str) {
            let p = self.0.join(logical.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(Path::new(target), p).unwrap();
        }

        pub fn chmod(&self, logical: &str, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            let p = self.0.join(logical.trim_start_matches('/'));
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    impl Drop for FakeRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::FakeRoot;
    use super::*;

    #[test]
    fn absolute_symlinks_stay_inside_root() {
        let r = FakeRoot::new("fs");
        r.write("/etc/real.conf", "inside");
        r.symlink("/etc/real.conf", "/etc/link.conf");
        r.symlink("../../../../../../etc/real.conf", "/a/b/rel.conf");
        let fs = Fs::new(r.0.clone());
        assert_eq!(fs.resolve(Path::new("/etc/link.conf"), true).unwrap(), Path::new("/etc/real.conf"));
        assert_eq!(fs.read_text(Path::new("/etc/link.conf")).unwrap(), "inside");
        assert_eq!(fs.read_text(Path::new("/a/b/rel.conf")).unwrap(), "inside");
        assert_eq!(fs.resolve(Path::new("/etc/link.conf"), false).unwrap(), Path::new("/etc/link.conf"));
    }

    #[test]
    fn symlink_loops_error() {
        let r = FakeRoot::new("loop");
        r.symlink("/x", "/y");
        r.symlink("/y", "/x");
        let fs = Fs::new(r.0.clone());
        assert!(fs.read_text(Path::new("/x")).is_err());
    }

    #[test]
    fn temp_detection() {
        assert!(in_temp("/tmp/x"));
        assert!(in_temp("/dev/shm/.a/b"));
        assert!(!in_temp("/tmpfoo/x"));
        assert!(!in_temp("/usr/tmp"));
    }

    #[test]
    fn walk_depth_limited() {
        let r = FakeRoot::new("walk");
        r.write("/t/a/b/c/d.txt", "x");
        let fs = Fs::new(r.0.clone());
        let mut seen = Vec::new();
        fs.walk(Path::new("/t"), 2, 1000, &mut |p, _, _| {
            seen.push(p.to_path_buf());
            true
        });
        assert!(seen.contains(&PathBuf::from("/t/a/b")));
        assert!(!seen.contains(&PathBuf::from("/t/a/b/c")));
    }
}
