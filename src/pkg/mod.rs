//! Package-ownership lookups (auto-detected backend).

pub mod dpkg;
pub mod pacman;
pub mod rpm;

use crate::util::fs::Fs;

pub enum Backend {
    Pacman(pacman::Pacman),
    Dpkg(dpkg::Dpkg),
    Rpm(rpm::Rpm),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    Owned(String),
    Unowned,
    /// No package manager detected; ownership can't be judged.
    Unknown,
}

impl Ownership {
    pub fn package(&self) -> Option<&str> {
        match self {
            Ownership::Owned(p) => Some(p),
            _ => None,
        }
    }
}

/// usrmerge aliases: a file may be recorded under /lib but live in /usr/lib, etc.
pub fn alternates(path: &str) -> Vec<String> {
    let mut v = vec![path.to_string()];
    for (a, b) in [("/usr/lib/", "/lib/"), ("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/sbin/", "/usr/bin/"), ("/usr/lib64/", "/lib64/")] {
        if let Some(rest) = path.strip_prefix(a) {
            v.push(format!("{b}{rest}"));
        } else if let Some(rest) = path.strip_prefix(b) {
            v.push(format!("{a}{rest}"));
        }
    }
    v
}

impl Backend {
    pub fn detect(fs: &Fs) -> Backend {
        if let Some(p) = pacman::Pacman::detect(fs) {
            Backend::Pacman(p)
        } else if let Some(d) = dpkg::Dpkg::detect(fs) {
            Backend::Dpkg(d)
        } else if let Some(r) = rpm::Rpm::detect(fs) {
            Backend::Rpm(r)
        } else {
            Backend::None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Backend::Pacman(_) => "pacman",
            Backend::Dpkg(_) => "dpkg",
            Backend::Rpm(_) => "rpm",
            Backend::None => "none",
        }
    }

    pub fn owner(&self, path: &str) -> Ownership {
        let lookup = |p: &str| match self {
            Backend::Pacman(b) => b.owner(p),
            Backend::Dpkg(b) => b.owner(p),
            Backend::Rpm(b) => b.owner(p),
            Backend::None => None,
        };
        if matches!(self, Backend::None) {
            return Ownership::Unknown;
        }
        for alt in alternates(path) {
            if let Some(pkg) = lookup(&alt) {
                return Ownership::Owned(pkg);
            }
        }
        Ownership::Unowned
    }

    /// A command the user can run to verify a package's files.
    pub fn verify_cmd(&self, pkg: &str) -> String {
        let q = crate::util::shell_quote(pkg);
        match self {
            Backend::Pacman(_) => format!("pacman -Qkk {q}"),
            Backend::Dpkg(_) => format!("dpkg --verify {q}"),
            Backend::Rpm(_) => format!("rpm -V {q}"),
            Backend::None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usrmerge_alternates() {
        let a = alternates("/lib/systemd/system/x.service");
        assert!(a.contains(&"/usr/lib/systemd/system/x.service".to_string()));
        let b = alternates("/usr/sbin/sshd");
        assert!(b.contains(&"/sbin/sshd".to_string()) && b.contains(&"/usr/bin/sshd".to_string()));
    }
}
