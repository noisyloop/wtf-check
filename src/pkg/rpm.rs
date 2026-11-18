//! rpm: `rpm -qf` per path (absolute binary path, no shell, cached).
//! Always the *host's* /usr/bin/rpm — never a binary from a mounted --root.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::util::fs::Fs;

const RPM_BIN: &str = "/usr/bin/rpm";

pub struct Rpm {
    root: PathBuf,
    cache: RefCell<HashMap<String, Option<String>>>,
}

impl Rpm {
    pub fn detect(fs: &Fs) -> Option<Rpm> {
        let has_db = fs.is_dir(Path::new("/var/lib/rpm")) || fs.is_dir(Path::new("/usr/lib/sysimage/rpm"));
        (has_db && Path::new(RPM_BIN).is_file()).then(|| Rpm { root: fs.root().to_path_buf(), cache: RefCell::new(HashMap::new()) })
    }

    pub fn owner(&self, path: &str) -> Option<String> {
        if let Some(v) = self.cache.borrow().get(path) {
            return v.clone();
        }
        let mut cmd = Command::new(RPM_BIN);
        cmd.env_clear().env("LC_ALL", "C").stdin(Stdio::null()).stderr(Stdio::null());
        if self.root != Path::new("/") {
            cmd.arg("--root").arg(&self.root);
        }
        cmd.args(["-qf", "--qf", "%{NAME}\\n", "--"]).arg(path);
        let res = cmd.output().ok().filter(|o| o.status.success()).and_then(|o| {
            String::from_utf8_lossy(&o.stdout).lines().next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        });
        self.cache.borrow_mut().insert(path.to_string(), res.clone());
        res
    }
}
