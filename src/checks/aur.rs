//! Arch only: foreign (AUR / locally built) packages.

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};
use crate::pkg::Backend;
use crate::util::shell_quote;
use crate::util::time::{epoch_of, fmt_date};

const NAME: &str = "aur";

/// Known AUR malware waves: installs/updates in this window get a MED.
pub fn window() -> (i64, i64) {
    (epoch_of(2026, 6, 9), epoch_of(2026, 8, 16)) // [2026-06-09, 2026-08-15] inclusive
}

pub fn in_window(t: Option<i64>) -> bool {
    let (a, b) = window();
    t.is_some_and(|t| t >= a && t < b)
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    let Backend::Pacman(pm) = &ctx.pkg else {
        return Vec::new();
    };
    let (foreign, method) = pm.foreign();
    ctx.note(format!("foreign packages determined by: {method}"));
    let mut out = Vec::new();
    for p in foreign {
        let installed = p.install_date.map(fmt_date).unwrap_or_else(|| "unknown".into());
        let built = p.build_date.map(fmt_date).unwrap_or_else(|| "unknown".into());
        let key = format!("aur:{}", p.name);
        ctx.record(key.clone(), format!("{} {}", p.version, p.install_date.unwrap_or(0)), false);
        let n = shell_quote(&p.name);
        let path = format!("/var/lib/pacman/local/{}-{}", p.name, p.version);
        let (sev, reason, fix) = if in_window(p.install_date) || in_window(p.build_date) {
            (
                Severity::Med,
                format!("foreign package {} {} installed/updated {installed} (built {built}) — inside the 2026-06-09..2026-08-15 AUR malware window", p.name, p.version),
                format!(
                    "Review the PKGBUILD history for that period: https://aur.archlinux.org/cgit/aur.git/log/?h={n}\nList and verify its files: pacman -Ql {n}; pacman -Qkk {n}\nIf anything is suspicious: remove it (sudo pacman -Rns {n}) and rotate credentials (SSH keys, tokens, browser sessions, password-manager master password)."
                ),
            )
        } else {
            (
                Severity::Info,
                format!("foreign package {} {} installed {installed} (built {built}, packager {})", p.name, p.version, if p.packager.is_empty() { "unknown" } else { &p.packager }),
                format!("Review: pacman -Qi {n}; check its PKGBUILD on the AUR before updating"),
            )
        };
        out.push(Finding::new(NAME, sev, ctx.disp(std::path::Path::new(&path)), key, reason, fix));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds() {
        assert!(!in_window(Some(epoch_of(2026, 6, 8) + 86399)));
        assert!(in_window(Some(epoch_of(2026, 6, 9))));
        assert!(in_window(Some(epoch_of(2026, 8, 15) + 86399)));
        assert!(!in_window(Some(epoch_of(2026, 8, 16))));
        assert!(!in_window(None));
    }
}
