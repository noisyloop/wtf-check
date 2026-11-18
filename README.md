# wtf-check

A **read-only Linux persistence auditor**. It looks at the places where malware
(or a sloppy install script) makes itself survive reboots and logins — systemd
units, cron, shell startup files, `ld.so.preload`, autostart entries, udev
rules, SSH keys, temp-dir binaries, running processes, the kernel — and tells
you what looks wrong and how you could fix it.

Arch-aware first (pacman DB, AUR/foreign packages), but works on any distro
(dpkg and rpm ownership lookups, or none at all).

**Design guarantees**

- **Zero external crates**, no `build.rs`. Pure `std` — including SHA-256,
  base64, a DEFLATE/gzip decoder (for pacman sync DBs) and the JSON writer.
- **Read-only.** Never modifies, deletes or executes anything it finds. No
  network access, no listening sockets, no daemon. The only file it ever writes
  is the baseline you explicitly ask for with `--save-baseline`.
- **Prints fix commands; never runs them.** File names in fix commands are
  shell-quoted, and all output is stripped of terminal control characters, so a
  malicious file name can't inject commands or rewrite your terminal.
- **Subprocesses only** for rpm ownership lookups (`/usr/bin/rpm -qf`) and the
  optional `bpftool` — always absolute paths, no shell, empty environment, and
  always the *host's* binaries (never one from a scanned `--root`).
- FIFOs and device files are never opened; symlinks are resolved *inside* the
  scan root, so a mounted disk can't redirect reads to the host.

## Install

```sh
cargo build --release
sudo install -m 0755 target/release/wtf-check /usr/local/bin/
```

For a fully static binary (runs on any Linux, ideal for live USBs, and
unaffected by `LD_PRELOAD`/`ld.so.preload` on the host):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/wtf-check
```

Tests and lints:

```sh
cargo test
cargo clippy -- -D warnings
```

## Usage

```sh
wtf-check                       # same as `wtf-check scan`
sudo wtf-check scan             # full audit: /root and every /home/*
wtf-check scan --json | jq .    # machine-readable
wtf-check --only systemd,cron   # just some checks
wtf-check --skip process,aur
wtf-check --min-severity med    # hide LOW/INFO
wtf-check list-checks

# Baselines: hash every checked file + unit list + eBPF list + foreign pkgs
sudo wtf-check --save-baseline /root/wtf.baseline
sudo wtf-check --baseline /root/wtf.baseline     # report only new/changed items

# Offline scan of a mounted system from a live USB (see docs/LIVE-USB.md)
sudo mount /dev/nvme0n1p2 /mnt
sudo wtf-check --root /mnt
```

| Option | Meaning |
| --- | --- |
| `--json` | JSON output (`summary`, `findings[]` with `check`, `severity`, `path`, `reason`, `fix`, plus `notes[]`). |
| `--no-color` | Disable colour. `NO_COLOR` is honoured too; colour is off when stdout isn't a TTY. |
| `--root PATH` | Treat `PATH` as `/`. All homes in the scanned system's `/etc/passwd` and `/home` are audited. Process/kernel/eBPF checks are skipped (there is no live `/proc`). |
| `--only LIST` / `--skip LIST` | Comma-separated check names. |
| `--save-baseline FILE` | Write `key<TAB>sha256` lines for everything checked. |
| `--baseline FILE` | Show only findings about items that are new or changed versus `FILE`, plus new/changed/removed items no check flagged. Live process findings are always shown. |
| `--min-severity LEVEL` | `info`, `low`, `med`, `high`. Display filter only — the exit code still reflects everything found. |

**Exit codes:** `0` nothing above LOW · `1` MED findings · `2` HIGH findings ·
`3` error (bad arguments, unreadable baseline, or a check crashed).

**Running as a normal user** scans only your own home plus whatever system files
are world-readable; unreadable paths are listed under `notes` rather than
aborting. Run as root for a complete audit.

## What each check means

Every finding has a severity, a path, a reason and a suggested fix. Files in
system paths that **no package owns** get one severity level added (and on
their own are LOW, or MED under `/usr/lib`, where everything should be
package-owned). Package ownership is detected automatically:

- **pacman:** `/var/lib/pacman/local/*/{desc,files}` parsed directly.
- **dpkg:** `/var/lib/dpkg/info/*.list` parsed directly.
- **rpm:** `rpm -qf` per path (cached), with `--root` for offline scans.

Owned files that look suspicious keep their severity — AUR malware is
package-owned too — and get a verify command (`pacman -Qkk`, `dpkg --verify`,
`rpm -V`).

Suspicious command patterns (shared by all checks): `curl`/`wget` piped or
substituted into a shell or interpreter (HIGH), `/dev/tcp` redirections (HIGH),
`nc`/`socat` with `-e`/`exec:` (HIGH), base64 decoding (MED, HIGH if piped into
a shell), `python -c`/`perl -e` (MED), plain `curl`/`wget` (MED), paths in
`/tmp`, `/var/tmp`, `/dev/shm` (MED; HIGH when that's the binary being run),
`LD_PRELOAD` (HIGH), `sh -c`/`bash -c` (LOW), `mkfifo`, `chattr +i`.

| Check | Looks at | Flags |
| --- | --- | --- |
| `systemd` | `/etc/systemd/{system,user}`, `/usr/lib/systemd/{system,user}`, `/lib/…`, `/usr/local/lib/…`, `~/.config/systemd/user`, `~/.local/share/systemd/user`, incl. `*.wants/` links and `*.d/*.conf` drop-ins | Unowned units; `Exec*=` running from temp or hidden dirs; suspicious patterns; `Environment=LD_PRELOAD`; enablement symlinks pointing outside the unit dirs; every user unit (LOW). Masked units (→ `/dev/null`) are skipped. |
| `cron` | `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly,yearly}`, `/var/spool/cron/**` (cronie, Debian, SUSE, fcron), `/etc/anacrontab` | `@reboot` (MED), every user crontab job (LOW), suspicious patterns, unowned system cron files. |
| `shell` | `~/.bashrc .bash_profile .bash_login .profile .zshrc .zprofile .zshenv .zlogin .xprofile .xinitrc`, fish `config.fish`/`conf.d`, `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, zsh/fish system files | Suspicious patterns; `LD_PRELOAD`; `PATH` containing temp dirs (HIGH) or `.`/empty entries (MED); redefining `sudo`/`su`/`doas`/`passwd` via alias or function (HIGH — classic password capture); DEBUG traps. |
| `preload` | `/etc/ld.so.preload`, `/etc/environment`, `environment.d`, `~/.pam_environment`, `/etc/ld.so.conf(.d)` | Non-empty `ld.so.preload` (HIGH); `LD_PRELOAD`/`LD_AUDIT` in environment files (HIGH); library paths in temp or home dirs (HIGH). |
| `autostart` | `~/.config/autostart`, `/etc/xdg/autostart` | Every user autostart entry (LOW); unowned system entries (MED); hidden-dir/temp executables; patterns. Disabled entries (`Hidden=true`) are skipped. |
| `udev` | `/etc/udev/rules.d`, `/run/udev/rules.d`, `/usr/lib/udev/rules.d` | `RUN+=`, `PROGRAM=`, `IMPORT{program}=` in `/etc` (LOW), unowned rules that run programs (MED), patterns. |
| `ssh` | `~/.ssh/authorized_keys{,2}` for every user, `sshd_config(.d)` | Each key with its SHA256 fingerprint (INFO, so you can recognise them); `command=`/`environment=` options (MED); world-/group-writable home or `~/.ssh` or key file (HIGH/MED); `authorized_keys2` (LOW); `AuthorizedKeysCommand` (MED). |
| `tmpexec` | `/tmp`, `/var/tmp`, `/dev/shm` (depth ≤ 8) | ELF files (magic bytes) — HIGH in `/dev/shm`, hidden paths or near the top; executables (LOW, MED if hidden). |
| `process` | `/proc/*/exe`, `comm`, `cmdline` | Running from a memfd (HIGH, fileless); exe in temp dirs (HIGH); deleted exe (MED, LOW if a replacement exists — usually an upgrade); userspace process named like a kernel thread (HIGH); comm/exe name mismatch (LOW). |
| `kernel` | `/proc/sys/kernel/tainted`, `/proc/modules`, `modules.dep`, `bpftool prog show` | Decoded taint flags (unsigned/forced modules MED); loaded modules missing from the module tree (MED); each eBPF program (INFO; **HIGH** when new versus `--baseline`). |
| `aur` | pacman local DB vs. sync DBs (`pacman -Qm` equivalent, computed without pacman) | Every foreign package with install/build dates (INFO); installed or updated **2026-06-09 – 2026-08-15** (the AUR malware waves): MED, with advice to review the PKGBUILD history and rotate credentials. If a sync DB can't be decoded, falls back to "packager isn't `@archlinux.org`" (noted in the output). |
| `ioc` | `~/.npm`, `~/.cache`, `~/.local`, `/tmp` (depth-limited) | Directories named `atomic-lockfile` (HIGH). |

## Limitations — read this

**An in-kernel rootkit can hide from any in-host tool**, this one included. A
malicious kernel module or eBPF program can filter what `readdir`, `/proc` and
`read` return, so a compromised system can look clean from the inside. A
`LD_PRELOAD` rootkit can do the same for every dynamically linked program,
including the default wtf-check build (use the static musl build to avoid that).

For real assurance, **boot a trusted live USB**, mount the disk read-only and
scan it from outside:

```sh
sudo mount -o ro /dev/nvme0n1p2 /mnt   # plus /mnt/home etc. if separate
sudo wtf-check --root /mnt
```

**New to this? Follow the step-by-step [live USB guide](docs/LIVE-USB.md)**:
making the stick, booting it, unlocking encrypted disks, mounting ext4/btrfs/XFS
read-only, running the scan and reading the results.

Also: wtf-check finds *persistence*, not every compromise. It doesn't verify
package file integrity (use `pacman -Qkk`, `debsums`, `rpm -Va`), inspect
browser extensions, or analyse binaries.

## False positives

Expect some, and read the reason before acting:

- **Unowned files in `/etc`** are normal when created by an admin, an installer
  script (`curl … | sh` tools often drop `/etc/profile.d/*.sh`), or
  config management. They're LOW unless something else matched.
- **User units, autostart entries and crontab jobs** are listed as LOW so you
  can confirm you know each one; that's an inventory, not an accusation.
- **`sh -c`, `curl`, `base64`** appear in legitimate units and scripts. Owned
  files that match keep their severity because AUR malware is package-owned —
  check the PKGBUILD.
- **Deleted executables** after a system upgrade are expected until you restart
  the service; these are LOW when a replacement binary exists.
- **comm/exe mismatches**: browsers, Electron apps and daemons rename their
  processes. Known renamers are skipped; others show as LOW.
- **Tainted kernel `O`/`P`** is normal with NVIDIA, VirtualBox, ZFS or other
  DKMS modules.
- **Temp-dir executables** are common during builds (`/tmp/cargo-install*`,
  AppImages). ELF files in `/dev/shm` or hidden temp dirs remain worth a look.
- **AUR window**: a package being updated in that window doesn't mean it was
  malicious — it means you should check its PKGBUILD history for that period.

Use `--save-baseline` once you've reviewed a clean system, then `--baseline`
afterwards: unchanged known-good items stop showing up.

## Project layout

```
src/main.rs            argument parsing (by hand), orchestration, exit codes
src/ctx.rs             scan context: root, homes, package DB, notes, inventory
src/finding.rs         Severity, Finding
src/report.rs          human (coloured) + JSON output (hand-written escaping)
src/baseline.rs        baseline save/load/diff
src/patterns.rs        shared suspicious-command heuristics
src/pkg/{mod,pacman,dpkg,rpm}.rs
src/checks/<one file per check>.rs
src/util/{sha256,fs,proc,base64,inflate,time}.rs
```

## License

MIT — see [LICENSE](LICENSE).
