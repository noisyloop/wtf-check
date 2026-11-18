//! wtf-check: a read-only Linux persistence auditor (std only).

mod baseline;
mod checks;
mod ctx;
mod finding;
mod patterns;
mod pkg;
mod report;
mod util;

use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::ExitCode;

use ctx::Ctx;
use finding::{Finding, Severity};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, PartialEq)]
struct Opts {
    json: bool,
    no_color: bool,
    root: PathBuf,
    only: Option<Vec<String>>,
    skip: Vec<String>,
    save_baseline: Option<PathBuf>,
    baseline: Option<PathBuf>,
    min_severity: Option<Severity>,
}

#[derive(Debug, PartialEq)]
enum Action {
    Scan(Opts),
    Help,
    Version,
    ListChecks,
}

fn usage() -> String {
    format!(
        "wtf-check {VERSION} — read-only Linux persistence auditor

USAGE:
    wtf-check [scan] [OPTIONS]
    wtf-check list-checks

OPTIONS:
    --json                  Machine-readable JSON output
    --no-color              Disable colors (NO_COLOR is also honoured)
    --root PATH             Scan a mounted system (e.g. /mnt from a live USB) [default: /]
    --only LIST             Run only these checks (comma-separated)
    --skip LIST             Skip these checks (comma-separated)
    --save-baseline FILE    Write hashes of every checked item to FILE
    --baseline FILE         Report only items new/changed since FILE
    --min-severity LEVEL    Hide findings below LEVEL (info|low|med|high)
    -h, --help              Show this help
    -V, --version           Show version

CHECKS:
{}

EXIT CODES:
    0 clean (nothing above LOW)   1 MED findings   2 HIGH findings   3 error

wtf-check never modifies, deletes or executes anything it finds. Fix commands
are printed for you to review and run yourself.",
        checks::CHECKS.iter().map(|c| format!("    {:<10} {}", c.name, c.about)).collect::<Vec<_>>().join("\n")
    )
}

fn parse_list(v: &str) -> Result<Vec<String>, String> {
    let names = checks::names();
    let list: Vec<String> = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for n in &list {
        if !names.contains(&n.as_str()) {
            return Err(format!("unknown check '{n}' (available: {})", names.join(",")));
        }
    }
    Ok(list)
}

fn parse_args(args: Vec<String>) -> Result<Action, String> {
    let mut o = Opts { root: PathBuf::from("/"), ..Default::default() };
    let mut it = args.into_iter().peekable();
    if let Some(first) = it.peek() {
        match first.as_str() {
            "scan" => {
                it.next();
            }
            "list-checks" => return Ok(Action::ListChecks),
            "help" => return Ok(Action::Help),
            _ => {}
        }
    }
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> { inline.clone().or_else(|| it.next()).ok_or_else(|| format!("{name} needs a value")) };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Action::Help),
            "-V" | "--version" => return Ok(Action::Version),
            "--json" => o.json = true,
            "--no-color" | "--no-colour" => o.no_color = true,
            "--root" => o.root = PathBuf::from(value("--root")?),
            "--only" => o.only = Some(parse_list(&value("--only")?)?),
            "--skip" => o.skip.extend(parse_list(&value("--skip")?)?),
            "--save-baseline" => o.save_baseline = Some(PathBuf::from(value("--save-baseline")?)),
            "--baseline" => o.baseline = Some(PathBuf::from(value("--baseline")?)),
            "--min-severity" => {
                let v = value("--min-severity")?;
                o.min_severity = Some(Severity::parse(&v).ok_or_else(|| format!("bad severity '{v}'"))?);
            }
            _ => return Err(format!("unknown argument '{a}'")),
        }
    }
    Ok(Action::Scan(o))
}

fn run(o: Opts) -> Result<u8, String> {
    let root = std::fs::canonicalize(&o.root).map_err(|e| format!("--root {}: {e}", o.root.display()))?;
    if !root.is_dir() {
        return Err(format!("--root {} is not a directory", root.display()));
    }
    // Load the baseline first so a bad file fails fast.
    let base = o.baseline.as_deref().map(baseline::load).transpose()?;

    let ctx = Ctx::new(root);
    let selected: Vec<&checks::Check> = checks::CHECKS
        .iter()
        .filter(|c| o.only.as_ref().is_none_or(|l| l.iter().any(|n| n == c.name)))
        .filter(|c| !o.skip.iter().any(|n| n == c.name))
        .collect();

    let mut findings: Vec<Finding> = Vec::new();
    let mut crashed = false;
    for c in &selected {
        match panic::catch_unwind(AssertUnwindSafe(|| (c.run)(&ctx))) {
            Ok(v) => findings.extend(v),
            Err(_) => {
                crashed = true;
                ctx.note(format!("check '{}' crashed; its results are incomplete", c.name));
            }
        }
    }

    let inventory = ctx.inventory();
    let names: HashSet<&str> = selected.iter().map(|c| c.name).collect();
    if let Some(b) = &base {
        findings = baseline::diff(&ctx, findings, &inventory, b, &names);
    }
    if let Some(p) = &o.save_baseline {
        baseline::save(p, &inventory).map_err(|e| format!("cannot write baseline {}: {e}", p.display()))?;
        ctx.note(format!("baseline with {} items saved to {}", inventory.len(), p.display()));
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.check.cmp(b.check)).then_with(|| a.path.cmp(&b.path)));
    let worst = findings.iter().map(|f| f.severity).max();
    let shown: Vec<Finding> = match o.min_severity {
        Some(m) => findings.into_iter().filter(|f| f.severity >= m).collect(),
        None => findings,
    };

    let meta = report::Meta {
        version: VERSION,
        root: ctx.fs.root().display().to_string(),
        distro: ctx.distro.clone(),
        package_manager: ctx.pkg.name(),
        user_mode: if ctx.euid == 0 { "root (all users)".into() } else if ctx.all_users_mode() { "offline root (all users)".into() } else { "normal user (own home)".into() },
        homes: ctx.homes.iter().map(|h| ctx.disp(&h.path)).collect(),
        checks: selected.iter().map(|c| c.name).collect(),
        baseline: o.baseline.as_ref().map(|p| p.display().to_string()),
        notes: ctx.notes(),
    };
    let out = if o.json {
        report::to_json(&meta, &shown)
    } else {
        let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let color = !o.no_color && !no_color_env && std::io::stdout().is_terminal();
        report::to_human(&meta, &shown, color)
    };
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(out.as_bytes());
    let _ = stdout.flush();

    if crashed {
        return Ok(3);
    }
    Ok(match worst {
        Some(Severity::High) => 2,
        Some(Severity::Med) => 1,
        _ => 0,
    })
}

fn main() -> ExitCode {
    let mut args = Vec::new();
    for a in std::env::args_os().skip(1) {
        match a.into_string() {
            Ok(s) => args.push(s),
            Err(a) => {
                eprintln!("wtf-check: argument is not valid UTF-8: {a:?}");
                return ExitCode::from(3);
            }
        }
    }
    match parse_args(args) {
        Err(e) => {
            eprintln!("wtf-check: {e}\nTry 'wtf-check --help'.");
            ExitCode::from(3)
        }
        Ok(Action::Help) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Action::Version) => {
            println!("wtf-check {VERSION}");
            ExitCode::SUCCESS
        }
        Ok(Action::ListChecks) => {
            for c in checks::CHECKS {
                println!("{:<10} {}", c.name, c.about);
            }
            ExitCode::SUCCESS
        }
        Ok(Action::Scan(o)) => match run(o) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("wtf-check: {e}");
                ExitCode::from(3)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Result<Action, String> {
        parse_args(v.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn arg_parsing() {
        let Action::Scan(o) = a(&["scan", "--json", "--root", "/mnt", "--only=systemd,cron", "--skip", "cron"]).unwrap() else { panic!() };
        assert!(o.json);
        assert_eq!(o.root, PathBuf::from("/mnt"));
        assert_eq!(o.only, Some(vec!["systemd".into(), "cron".into()]));
        assert_eq!(o.skip, vec!["cron".to_string()]);
        assert_eq!(a(&[]).unwrap(), Action::Scan(Opts { root: PathBuf::from("/"), ..Default::default() }));
        assert_eq!(a(&["--help"]).unwrap(), Action::Help);
        assert!(a(&["--only", "nope"]).is_err());
        assert!(a(&["--root"]).is_err());
        assert!(a(&["--bogus"]).is_err());
        assert!(a(&["--min-severity", "x"]).is_err());
    }

    #[test]
    fn end_to_end_fake_root_with_baseline() {
        use util::fs::testutil::FakeRoot;
        let r = FakeRoot::new("e2e");
        r.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\n");
        r.mkdir("/root");
        r.write("/etc/systemd/system/a.service", "[Service]\nExecStart=/usr/bin/true\n");
        let bl = r.0.join("base.txt");
        let opts = |base: Option<PathBuf>, save: Option<PathBuf>| Opts { root: r.0.clone(), json: true, baseline: base, save_baseline: save, ..Default::default() };
        assert_eq!(run(opts(None, Some(bl.clone()))).unwrap(), 0);
        let saved = std::fs::read_to_string(&bl).unwrap();
        assert!(saved.contains("systemd:/etc/systemd/system/a.service\t"));
        // Same state → nothing new; then add a malicious unit.
        let ctx = Ctx::new(r.0.clone());
        let inv_before = { checks::systemd::run(&ctx); ctx.inventory() };
        r.write("/etc/systemd/system/b.service", "[Service]\nExecStart=/dev/shm/x\n");
        let ctx2 = Ctx::new(r.0.clone());
        let f = checks::systemd::run(&ctx2);
        let names: HashSet<&str> = ["systemd"].into_iter().collect();
        let d = baseline::diff(&ctx2, f, &ctx2.inventory(), &inv_before, &names);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].path.ends_with("b.service") && d[0].severity == Severity::High && d[0].reason.contains("new since baseline"));
        assert_eq!(run(opts(Some(bl), None)).unwrap(), 2);
    }
}
