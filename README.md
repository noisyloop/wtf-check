# wtf-check

A **read-only Linux persistence and rootkit auditor**. It looks at the places
where malware (or a sloppy install script) makes itself survive reboots and
logins, and tells you what looks wrong and how you could fix it. Those places
include:

- systemd units, cron, shell startup files, `ld.so.preload`, autostart entries, udev rules and SSH keys
- package files that no longer match their checksums
- hidden processes and kernel modules
- raw-socket backdoors, running processes and temp-dir binaries

Arch-aware first (pacman database, mtree checksums, AUR/foreign packages), but
works on any distro (dpkg and rpm too, or no package manager at all). It can
scan the running system, a disk mounted from a live USB, or boot **straight
from a Flipper Zero** into a guided offline scan.

**Design guarantees**

- **Zero external crates**, no `build.rs`. Pure `std`, including the SHA-256, MD5,
  base64, DEFLATE/gzip decoder and JSON writer.
- **Read-only.** Never modifies, deletes or executes anything it finds. No
  network access, no sockets opened, no daemon. The only file it ever writes is
  the baseline you explicitly ask for with `--save-baseline`.
- **Prints fix commands; never runs them.** File names in fix commands are
  shell-quoted, and all output is stripped of terminal control characters, so a
  malicious file name can't inject commands or rewrite your terminal.
- **Subprocesses only** for rpm ownership lookups (`/usr/bin/rpm -qf`) and the
  optional `bpftool`: always absolute paths, no shell, an empty environment, and
  always the *host's* binaries (never one from a scanned `--root`).
- FIFOs and device files are never opened; symlinks are resolved *inside* the
  scan root, so a mounted disk can't redirect reads to the host.

## Install

Pick one:

| Method | Command |
| --- | --- |
| **Arch Linux** (builds from source as a package) | `git clone https://github.com/noisyloop/wtf-check.git && cd wtf-check/packaging/arch && makepkg -si` |
| **Any distro with Rust** | `cargo install --locked --git https://github.com/noisyloop/wtf-check`, then run `sudo ~/.cargo/bin/wtf-check` |
| **Prebuilt static binary** (once a release is tagged) | Download `wtf-check-x86_64` (or `-aarch64`) and `SHA256SUMS` from the [Releases page](https://github.com/noisyloop/wtf-check/releases), then `sha256sum -c --ignore-missing SHA256SUMS && chmod +x wtf-check-x86_64` |
| **Flipper Zero boot image** | See [Flipper Zero](#flipper-zero-scan-without-booting-your-system) below |

On Arch, Rust comes from the official repos: `sudo pacman -S --needed rust`.
Elsewhere use your distro's `cargo` or [rustup](https://rustup.rs).

The static (musl) build runs on any Linux, which makes it ideal for live USBs.
It is also unaffected by `LD_PRELOAD`/`ld.so.preload` on the host:

```sh
rustup target add x86_64-unknown-linux-musl      # Arch: sudo pacman -S rust-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Development: `cargo test` and `cargo clippy -- -D warnings`. CI runs both on
every push (`.github/workflows/ci.yml`). Pushing a `v*` tag publishes static
binaries, the Flipper image and checksums (`release.yml`).

## Usage

```sh
sudo wtf-check                  # full audit: system + /root + every /home/*
wtf-check                       # as a normal user: your own home + readable system files
wtf-check --json | jq .         # machine-readable
wtf-check --only systemd,cron   # just some checks
wtf-check --skip process,aur
wtf-check --min-severity med    # hide LOW/INFO
sudo wtf-check --deep           # integrity: verify every package file, not just binaries/libs
wtf-check list-checks

# Baselines: hashes of every checked file + units, eBPF programs, packages, listeners
sudo wtf-check --save-baseline /root/wtf.baseline
sudo wtf-check --baseline /root/wtf.baseline     # report only new/changed items

# Suppress findings you've reviewed
sudo wtf-check --allow /root/wtf.allow

# Offline scan of a mounted system from a live USB (see docs/LIVE-USB.md)
sudo wtf-check --root /mnt
```

| Option | Meaning |
| --- | --- |
| `--json` | JSON output (`summary`, `findings[]` with `check`, `severity`, `path`, `reason`, `fix`, plus `notes[]`). |
| `--no-color` | Disable colour. `NO_COLOR` is honoured too; colour is off when stdout isn't a TTY. |
| `--root PATH` | Treat `PATH` as `/`. All homes in the scanned system's `/etc/passwd` and `/home` are audited. Live-only checks (processes, network, hidden PIDs/modules, eBPF) are skipped. |
| `--only LIST` / `--skip LIST` | Comma-separated check names. |
| `--deep` | `integrity` verifies every package file instead of the security-critical set. |
| `--allow FILE` | Suppress reviewed findings. One pattern per line, matched against the finding's path or subject; a trailing `*` matches any suffix; `check:pattern` limits a pattern to one check; `#` starts a comment. Example below. |
| `--save-baseline FILE` | Write `key<TAB>hash` lines for everything checked. |
| `--baseline FILE` | Show only findings about items that are new or changed versus `FILE`, plus new/changed/removed items no check flagged. Live process findings are always shown. |
| `--min-severity LEVEL` | `info`, `low`, `med`, `high`. Display filter only; the exit code still reflects everything found. |

```text
# /root/wtf.allow, reviewed 2026-11-18
/etc/profile.d/nvm.sh              # installed by me
shell:/home/alice/.zshrc           # only for the shell check
network:tcp 127.0.0.1:631*         # CUPS
```

**Exit codes:** `0` nothing above LOW · `1` MED findings · `2` HIGH findings ·
`3` error (bad arguments, unreadable baseline/allowlist, or a check crashed).

**Running as a normal user** scans only your own home plus whatever system files
are world-readable; unreadable paths are listed under `notes` rather than
aborting. Run as root for a complete audit.

## What each check means

Every finding has a severity, a path, a reason and a suggested fix. Files in
system paths that **no package owns** get one severity level added (and on
their own are LOW, or MED under `/usr/lib`, where everything should be
package-owned). Package ownership is detected automatically:

- **pacman:** `/var/lib/pacman/local/*/{desc,files,mtree}` parsed directly.
- **dpkg:** `/var/lib/dpkg/info/*.{list,md5sums}` and `diversions` parsed directly.
- **rpm:** `rpm -qf` per path (cached), with `--root` for offline scans.

Owned files that look suspicious keep their severity (AUR malware is
package-owned too) and get a verify command.

Suspicious command patterns, shared by all checks:

| Pattern | Severity |
| --- | --- |
| `curl`/`wget` piped or substituted into a shell or interpreter | HIGH |
| `/dev/tcp` redirections | HIGH |
| `nc`/`socat` with `-e`/`exec:` | HIGH |
| `LD_PRELOAD` | HIGH |
| base64 decoding | MED (HIGH if piped into a shell) |
| `python -c`/`perl -e` | MED |
| plain `curl`/`wget` | MED |
| paths in `/tmp`, `/var/tmp`, `/dev/shm` | MED (HIGH when that's the binary being run) |
| `sh -c`/`bash -c` | LOW |
| `mkfifo`, `chattr +i` | also flagged |

The last column of the checks table maps each check to [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0003/)
techniques, useful when comparing with other tools or writing detections.

| Check | Looks at | Flags | ATT&CK |
| --- | --- | --- | --- |
| `systemd` | `/etc/systemd/{system,user}`, `/usr/lib/systemd/{system,user}`, `/lib/…`, `/usr/local/lib/…`, `~/.config/systemd/user`, `~/.local/share/systemd/user`, incl. `*.wants/` links and `*.d/*.conf` drop-ins | Unowned units; `Exec*=` from temp or hidden dirs; patterns; `Environment=LD_PRELOAD`; enablement symlinks pointing outside the unit dirs; every user unit (LOW). Masked units are skipped. | T1543.002, T1053.006 |
| `cron` | `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,…}`, `/var/spool/cron/**`, `/etc/anacrontab` | `@reboot` (MED), every user crontab job (LOW), patterns, unowned system cron files. | T1053.003 |
| `shell` | bash/zsh/fish/X startup files in every home, `/etc/profile(.d)`, `/etc/bash.bashrc`, zsh/fish system files | Patterns; `LD_PRELOAD`; `PATH` with temp dirs (HIGH) or `.`/empty entries (MED); redefining `sudo`/`su`/`doas`/`passwd` (HIGH, password capture); DEBUG traps. | T1546.004 |
| `preload` | `/etc/ld.so.preload`, `/etc/environment`, `environment.d`, `~/.pam_environment`, `/etc/ld.so.conf(.d)` | Non-empty `ld.so.preload` (HIGH); `LD_PRELOAD`/`LD_AUDIT` in environment files (HIGH); library paths in temp or home dirs (HIGH). | T1574.006 |
| `autostart` | `~/.config/autostart`, `/etc/xdg/autostart` | Every user entry (LOW); unowned system entries (MED); hidden/temp executables; patterns. | T1547.013 |
| `udev` | `/etc/udev/rules.d`, `/run/udev/rules.d`, `/usr/lib/udev/rules.d` | `RUN+=`/`PROGRAM=`/`IMPORT{program}=` in `/etc` (LOW), unowned rules that run programs (MED), patterns. | T1546.017 |
| `ssh` | `~/.ssh/authorized_keys{,2}` for every user, `sshd_config(.d)` | Each key with its SHA256 fingerprint (INFO); `command=`/`environment=` options (MED); writable home/`~/.ssh`/key file (HIGH/MED); `authorized_keys2` (LOW); `AuthorizedKeysCommand` (MED). | T1098.004 |
| `tmpexec` | `/tmp`, `/var/tmp`, `/dev/shm` (depth ≤ 8) | ELF files by magic bytes (HIGH in `/dev/shm`, hidden or shallow paths); executables (LOW, MED if hidden). | T1036 |
| `process` | `/proc/*/exe`, `comm`, `cmdline` | memfd (fileless) execution (HIGH); exe in temp dirs (HIGH); deleted exe (MED, LOW if replaced by an upgrade); process named like a kernel thread (HIGH); comm/exe mismatch (LOW). | T1620, T1036.004 |
| `network` | `/proc/net/{tcp,udp,raw,packet}[6]`, mapped to processes via `/proc/*/fd` | Every listener (INFO inventory; new ones MED with `--baseline`); sockets owned by deleted/temp/memfd binaries (HIGH); raw/AF_PACKET sockets held by unexpected programs (MED, the BPFDoor technique); sockets with no visible owner (LOW). | T1205.002, T1571 |
| `kernel` | `/proc/sys/kernel/tainted`, `/proc/modules`, `modules.dep`, `bpftool prog show` | Decoded taint flags; loaded modules missing from the module tree (MED); each eBPF program (INFO; **HIGH** when new versus `--baseline`). | T1547.006 |
| `rootkit` | Curated on-disk IOCs; `/proc` brute force; `/sys/module` | Files/dirs of known families (libprocesshider, Jynx2, Reptile, Kinsing, BPFDoor, XorDDoS, perfctl, OrBit); **PIDs that exist but are hidden from the `/proc` listing**; modules in `/sys/module` but hidden from `/proc/modules`; known LKM rootkit module names. All HIGH. | T1014 |
| `integrity` | Package files vs. pacman mtree SHA-256 / dpkg md5sums | Modified binaries, shared libraries, PAM modules, systemd/ssh helpers (HIGH); with `--deep`, any modified package file (MED). Config/backup files and dpkg diversions are handled. rpm: run `rpm -Va`. | T1554 |
| `aur` | pacman local DB vs. sync DBs (`pacman -Qm` equivalent, computed without pacman) | Every foreign package with dates (INFO); installed or updated **2026-06-09 – 2026-08-15** (AUR malware waves): MED, with PKGBUILD-review and credential-rotation advice. | T1195.002 |
| `ioc` | `~/.npm`, `~/.cache`, `~/.local`, `/tmp` (depth-limited) | Directories named `atomic-lockfile` (HIGH). | — |

## Flipper Zero: scan without booting your system

`flipper/build-flipper-image.sh` builds a small disk image for the Flipper
Zero's **Mass Storage** app. The image boots straight into a guided,
read-only scan of the computer's installed system:

1. It lists the disks and suggests the likely system partition.
2. It unlocks LUKS read-only, activates LVM, and finds archinstall's btrfs subvolumes.
3. It marks the device read-only at the block layer and mounts it read-only.
4. It runs every offline check and saves the reports back onto the Flipper.

No second USB stick and no Ventoy needed:

```sh
sudo pacman -S --needed git linux mkinitcpio cryptsetup lvm2 dosfstools mtools rust rust-musl
git clone https://github.com/noisyloop/wtf-check.git && cd wtf-check
./flipper/build-flipper-image.sh          # → wtf-check-flipper.img
```

Step-by-step instructions, including copying it to the Flipper, booting and
reading the reports, are in **[docs/FLIPPER.md](docs/FLIPPER.md)**. The boot
flow is tested end-to-end in QEMU/UEFI against ext4, LUKS and btrfs-subvolume
disks (`flipper/test/qemu-smoke.py`).

## Limitations: read this

**An in-kernel rootkit can hide from any in-host tool**, this one included. A
malicious kernel module or eBPF program can filter what `readdir`, `/proc` and
`read` return. The `rootkit` check catches the common getdents-hooking trick
(hidden PIDs that still answer `stat`), but a careful rootkit hides from that
too. An `LD_PRELOAD` rootkit can fool every dynamically linked program,
including the default wtf-check build; the static musl build is immune.

For real assurance, **scan from outside**:

- **Flipper Zero:** [docs/FLIPPER.md](docs/FLIPPER.md) boots a guided scan in one step.
- **Live USB:** [docs/LIVE-USB.md](docs/LIVE-USB.md) walks through making
  the stick, booting the Arch ISO, unlocking encrypted disks, mounting ext4,
  btrfs or XFS read-only, and reading the results.

Also:

- wtf-check finds *persistence and tampering*, not every compromise. It
  doesn't inspect browser extensions, analyse binaries or scan memory.
- The `rootkit` IOC list is small and high-confidence by design. For broad
  signature coverage, also run rkhunter or chkrootkit (see below).
- `integrity` trusts the package database on the same disk. An attacker with
  root could edit both a binary and its mtree/md5sums entry. Compare against
  packages from a trusted mirror (`pacman -S <pkg>`) when it matters.
- It's young software: test it on your systems with the projects listed under
  *Testing your detection* before relying on it.

## False positives

Expect some, and read the reason before acting:

- **Unowned files in `/etc`** are normal when created by an admin, an installer
  script (`curl … | sh` tools often drop `/etc/profile.d/*.sh`), or config
  management. They're LOW unless something else matched.
- **User units, autostart entries, crontab jobs, SSH keys and listeners** are
  listed so you can confirm you know each one; that's an inventory, not an
  accusation.
- **`sh -c`, `curl`, `base64`** appear in legitimate units and scripts. Owned
  files that match keep their severity because AUR malware is package-owned,
  so check the PKGBUILD.
- **Deleted executables** after an upgrade are expected until you restart the
  service; these are LOW when a replacement binary exists.
- **comm/exe mismatches**: browsers, Electron apps and daemons rename their
  processes. Known renamers are skipped; others show as LOW.
- **Raw/packet sockets**: DHCP clients, NetworkManager, wpa_supplicant and
  capture tools are expected; others are MED so you look.
- **Integrity**: files changed by the image builder, `dpkg-divert` (handled),
  or manual hotfixes show up. That's the point, but check the context.
- **Tainted kernel `O`/`P`** is normal with NVIDIA, VirtualBox, ZFS or other
  DKMS modules.
- **Temp-dir executables** are common during builds and AppImages.
- **AUR window**: an update in that window means "check its PKGBUILD history",
  not "malicious".

Once you've reviewed a clean system, use `--save-baseline` and later
`--baseline` (only changes are shown), or `--allow` for individual findings.

## How it compares

wtf-check overlaps with established tools. Its focus is modern Linux
persistence, Arch awareness, and offline scanning with no dependencies.

| Project | What it is | How wtf-check differs |
| --- | --- | --- |
| [rkhunter](https://rkhunter.sourceforge.net/) | Shell-script rootkit hunter: known-rootkit file signatures, binary property checks | rkhunter runs the system's own tools (`ps`, `netstat`, `strings`), which a compromised host can subvert, and its signatures mostly cover older rootkits. wtf-check reads files and `/proc` directly, covers systemd/XDG/udev/`environment.d` persistence, and is built for `--root` scans. Use both for broader coverage. |
| [chkrootkit](https://www.chkrootkit.org/) | Classic signature scanner for infected binaries and known rootkits | Same trade-off as rkhunter: wide legacy signature set, but it calls system binaries and has little coverage of modern persistence locations. |
| [Lynis](https://github.com/CISOfy/lynis) | Security auditing and hardening for Unix systems | A broad configuration/compliance audit. wtf-check is narrower: "what will run on boot or login, and was it tampered with". |
| [AIDE](https://github.com/aide/aide) / [Tripwire](https://github.com/Tripwire/tripwire-open-source) | File integrity monitoring against your own database | Better general FIM. wtf-check's `integrity` uses the package manager's checksums (no setup), and its baseline explains *why* a change matters. |
| [unhide](https://github.com/YJesus/Unhide) | Finds hidden processes and ports by brute force | wtf-check's `rootkit` check uses the same `/proc` brute-force idea (without signals or sockets); unhide has more techniques. |
| [osquery](https://github.com/osquery/osquery) / [Velociraptor](https://github.com/Velocidex/velociraptor) | Endpoint visibility and DFIR platforms (SQL / VQL queries, fleets) | Far more powerful and fleet-scale, but agents with large dependency trees. wtf-check is one std-only binary with opinionated checks and fix advice. |
| `pacman -Qkk`, [debsums](https://packages.debian.org/stable/debsums), `rpm -Va` | Package file verification | `integrity` does the same verification for pacman and dpkg (honouring dpkg diversions), restricted by default to the files attackers trojan most. |

### Testing your detection

- [PANIX](https://github.com/Aegrah/PANIX): a Linux persistence framework that
  plants many of the techniques above. Run it in a VM and check what
  wtf-check reports.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team): small,
  ATT&CK-mapped tests, including Linux persistence techniques.
- Public rootkit source for lab use: [Diamorphine](https://github.com/m0nad/Diamorphine)
  (LKM, hides PIDs/modules), [Reptile](https://github.com/f0rb1dd3n/Reptile),
  [libprocesshider](https://github.com/gianlucaborello/libprocesshider)
  (LD_PRELOAD). **Only in a throwaway VM.**

### Further reading

- [MITRE ATT&CK, Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/)
  and [Rootkit (T1014)](https://attack.mitre.org/techniques/T1014/).
- Arch Wiki: [Security](https://wiki.archlinux.org/title/Security),
  [Arch User Repository](https://wiki.archlinux.org/title/Arch_User_Repository)
  (why PKGBUILDs must be reviewed), [mkinitcpio](https://wiki.archlinux.org/title/Mkinitcpio),
  [Unified kernel image](https://wiki.archlinux.org/title/Unified_kernel_image),
  [Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot),
  [dm-crypt](https://wiki.archlinux.org/title/Dm-crypt).
- [Elastic Security Labs](https://www.elastic.co/security-labs) and
  [Sandfly Security's blog](https://sandflysecurity.com/blog/): in-depth Linux
  persistence and malware write-ups (BPFDoor, perfctl, many others).
- Flipper Zero: [documentation](https://docs.flipper.net/),
  [qFlipper](https://github.com/flipperdevices/qFlipper), and the
  [official apps catalog sources](https://github.com/flipperdevices/flipperzero-good-faps)
  (Mass Storage app).

## Project layout

```
src/main.rs            argument parsing (by hand), orchestration, exit codes
src/ctx.rs             scan context: root, homes, package DB, notes, inventory
src/finding.rs         Severity, Finding
src/report.rs          human (coloured) + JSON output (hand-written escaping)
src/baseline.rs        baseline save/load/diff
src/allow.rs           --allow pattern file
src/patterns.rs        shared suspicious-command heuristics
src/pkg/{mod,pacman,dpkg,rpm}.rs
src/checks/<one file per check>.rs
src/util/{sha256,md5,fs,proc,base64,inflate,time}.rs
flipper/               Flipper Zero boot image: build script, mkinitcpio hooks,
                       guided scan (wtf-scan), QEMU end-to-end test
packaging/arch/        PKGBUILD
docs/                  LIVE-USB.md, FLIPPER.md
```

## License

MIT, see [LICENSE](LICENSE).
