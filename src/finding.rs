use std::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Med,
    High,
}

impl Severity {
    pub const ALL_DESC: [Severity; 4] = [Severity::High, Severity::Med, Severity::Low, Severity::Info];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Med => "MED",
            Severity::High => "HIGH",
        }
    }

    /// One level more severe (used when a file in a system path is unowned).
    pub fn bump(self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Med,
            _ => Severity::High,
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "med" | "medium" => Some(Severity::Med),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub check: &'static str,
    pub severity: Severity,
    /// Real on-disk path (or pseudo path such as `/proc/123`).
    pub path: String,
    /// Baseline identity (`check:logical-path` or similar).
    pub subject: String,
    pub reason: String,
    /// Suggested commands for the user to run themselves (may be empty).
    pub fix: String,
}

impl Finding {
    pub fn new(
        check: &'static str,
        severity: Severity,
        path: impl Into<String>,
        subject: impl Into<String>,
        reason: impl Into<String>,
        fix: impl Into<String>,
    ) -> Finding {
        Finding { check, severity, path: path.into(), subject: subject.into(), reason: reason.into(), fix: fix.into() }
    }
}

/// Collects reasons for one file and tracks the worst severity.
#[derive(Default)]
pub struct Acc {
    pub sev: Option<Severity>,
    pub reasons: Vec<String>,
}

impl Acc {
    pub fn add(&mut self, s: Severity, r: impl Into<String>) {
        let r = r.into();
        if self.reasons.contains(&r) {
            return;
        }
        self.sev = Some(self.sev.map_or(s, |c| c.max(s)));
        self.reasons.push(r);
    }

    pub fn is_empty(&self) -> bool {
        self.sev.is_none()
    }

    /// Apply the "unowned file in a system path" rule: bump existing hits one
    /// level, prepend the reason, and ensure at least `base` severity.
    pub fn unowned(&mut self, base: Severity) {
        self.sev = Some(self.sev.map_or(base, |s| s.bump().max(base)));
        self.reasons.insert(0, "not owned by any package".into());
    }

    pub fn reason(&self) -> String {
        const MAX: usize = 8;
        let mut r = self.reasons.iter().take(MAX).cloned().collect::<Vec<_>>().join("; ");
        if self.reasons.len() > MAX {
            r.push_str(&format!("; (+{} more)", self.reasons.len() - MAX));
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_and_bump() {
        assert!(Severity::High > Severity::Med && Severity::Med > Severity::Low && Severity::Low > Severity::Info);
        assert_eq!(Severity::Med.bump(), Severity::High);
        assert_eq!(Severity::High.bump(), Severity::High);
        assert_eq!(Severity::parse("Medium"), Some(Severity::Med));
    }

    #[test]
    fn acc_unowned() {
        let mut a = Acc::default();
        a.unowned(Severity::Low);
        assert_eq!(a.sev, Some(Severity::Low));
        let mut a = Acc::default();
        a.add(Severity::Med, "curl");
        a.unowned(Severity::Low);
        assert_eq!(a.sev, Some(Severity::High));
        assert!(a.reason().starts_with("not owned"));
    }
}
