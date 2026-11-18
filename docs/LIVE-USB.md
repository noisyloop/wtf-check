# Scanning Arch Linux from a live USB: a step-by-step guide

This guide is for people who have never booted their Arch machine from a USB
stick. It uses the official **Arch Linux ISO** and **one USB stick**, and takes
about 30–45 minutes the first time.

The Arch ISO boots to a text console where you're already **root**, so the
commands below have no `sudo`. Every command is typed or pasted at that prompt.

## Why bother?

When you run wtf-check on your normal, running system, you are asking that
system to report on itself. If it has been seriously compromised (a *rootkit*
in the kernel, a library injected into every program via `/etc/ld.so.preload`,
or a malicious AUR package that did either), the malware can hide its files
and processes from **any** program running on it, wtf-check included.

Booting the Arch ISO means your installed system is **not running at all**.
Its disk is just data, and nothing on it gets a chance to lie. wtf-check reads
it from the outside with `--root`.

## What you need

- **One USB stick**, 8 GB or larger. **It will be erased**, so copy off
  anything you want to keep. It holds the Arch ISO, wtf-check and your report.
- **A second, trusted computer** to prepare the stick. If you suspect your
  computer is compromised, don't prepare it there.
- Your **disk encryption password**, if your install uses LUKS.

> **Safety first:** this guide only **reads** your disk. Every mount command
> below is read-only. Don't remove the `ro` options.

---

## Step 1: Make the stick bootable with Ventoy

[Ventoy](https://www.ventoy.net) turns a stick into a boot menu for ISO files
while the rest of it stays normal storage, so one stick can hold the Arch ISO,
wtf-check and your report.

1. On the trusted computer, download Ventoy from its official release page,
   <https://github.com/ventoy/Ventoy/releases> (or <https://www.ventoy.net>),
   and check the file against the `sha256` listed there. Use the official
   download rather than an AUR package for this.
2. Install it to the stick. This **erases** the stick.
   - **Linux:** unpack the `linux.tar.gz`, `cd` into it, then:
     ```sh
     lsblk                              # find the stick, e.g. /dev/sdb (whole disk, not sdb1)
     sudo sh Ventoy2Disk.sh -i /dev/sdX
     ```
     Double-check `sdX`. Installing to the wrong disk erases it.
   - **Windows:** unzip, run `Ventoy2Disk.exe`, pick the stick, click *Install*.
3. Afterwards the stick appears as a normal drive labelled **Ventoy**. Create a
   folder named `ventoy` on it, and inside that a file named `ventoy.json`
   containing exactly:
   ```json
   { "control": [ { "VTOY_LINUX_REMOUNT": "1" } ] }
   ```
   **Don't skip this.** While the live system runs, Linux keeps Ventoy's
   partition busy. This setting lets you mount it in step 4 to reach
   wtf-check and save your report.

## Step 2: Copy the Arch ISO and wtf-check onto the stick

**Arch ISO.**

1. Download the latest ISO and its `.sig` file from
   <https://archlinux.org/download/> (pick a mirror near you).
2. Verify it.
   - On an Arch machine:
     ```sh
     pacman-key -v archlinux-*-x86_64.iso.sig
     ```
     It must report a good signature from an Arch Linux developer.
   - Anywhere else: compare `sha256sum archlinux-*-x86_64.iso` against the
     SHA256 shown on the download page.
3. Copy the `.iso` onto the Ventoy drive like any other file. Don't unpack it.

**wtf-check.** Use the **static (musl) build**. It runs on the live ISO no
matter which glibc it ships, and it ignores `LD_PRELOAD`/`ld.so.preload`.

On an Arch machine, the musl target comes from the official repos:

```sh
sudo pacman -S --needed git rust rust-musl
git clone https://github.com/noisyloop/wtf-check.git && cd wtf-check
cargo build --release --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/wtf-check
```

(With rustup instead: `rustup target add x86_64-unknown-linux-musl`, then the
same `cargo build`. For ARM, use `aarch64-unknown-linux-musl`.)

Copy `target/x86_64-unknown-linux-musl/release/wtf-check` onto the Ventoy
drive, next to the ISO, and **write down the `sha256sum` output**.

Optional: if you saved a baseline earlier on the healthy system
(`sudo wtf-check --save-baseline wtf.baseline`), copy that onto the stick too.

## Step 3: Boot your Arch machine from the stick

1. Shut down completely, not suspend or hibernate. Dual-boot with Windows?
   Turn off Windows *Fast Startup* first.
2. **Turn off Secure Boot** in the firmware setup (usually F2 or Del at
   power-on). The official Arch ISO doesn't support Secure Boot. If you use
   your own Secure Boot keys (sbctl), note your settings so you can restore
   them afterwards.
3. Plug in the stick, power on, and tap the **boot menu key**:

   | Maker | Boot menu key |
   | --- | --- |
   | Dell | F12 |
   | HP | F9 (or Esc, then F9) |
   | Lenovo | F12 (ThinkPad: Enter, then F12; some IdeaPads: the small *Novo* button) |
   | ASUS | F8 or Esc |
   | Acer | F12 (may need enabling in setup with F2) |
   | MSI | F11 |
   | Gigabyte | F12 |
   | Framework | F12 |

4. Pick the USB entry (often *UEFI: <stick name>*).
5. In the Ventoy menu, select the Arch ISO, then **Boot in normal mode**.
6. In the Arch menu, choose **Arch Linux install medium (x86_64, UEFI)**.
7. You land at a `root@archiso ~ #` prompt. You won't install anything, and
   you don't need a network connection.

Not a US keyboard? Set yours first, e.g. `loadkeys de-latin1` (list them with
`localectl list-keymaps`). Tiny text on a HiDPI screen? Run `setfont ter-132b`.

## Step 4: Mount the stick and get wtf-check

```sh
mkdir -p /run/usb
mount /dev/disk/by-label/Ventoy /run/usb
ls /run/usb                          # you should see the ISO and wtf-check
cp /run/usb/wtf-check /tmp/wtf-check
chmod +x /tmp/wtf-check
sha256sum /tmp/wtf-check             # must match what you wrote down in step 2
```

wtf-check is copied to `/tmp` because programs can't run straight from the
stick's exFAT partition.

If `mount` says **"Device or resource busy"**, the `ventoy.json` from step 1 is
missing or misspelled. Reboot into the trusted computer, fix it, and try again.
Or put wtf-check on a second stick or SD card and mount that instead.

## Step 5: Find your Arch install's disk

```sh
lsblk -f
```

You'll see something like:

```
NAME        FSTYPE      LABEL    SIZE MOUNTPOINTS
loop0       squashfs             800M /run/archiso/airootfs   ← the live system (skip)
sda                               16G                         ← your USB stick
├─sda1      exfat       Ventoy    16G /run/usb
└─sda2      vfat        VTOYEFI   32M                         ← Ventoy's boot files (skip)
nvme0n1                          512G                         ← your internal disk
├─nvme0n1p1 vfat                   1G                         ← EFI / /boot partition (skip)
└─nvme0n1p2 btrfs                511G                         ← your Arch system  ✔
```

Look for the big partition on the internal disk (`nvme0n1…` or `sda…` when the
stick is `sdb`) with type **btrfs**, **ext4**, **xfs** or **crypto_LUKS**
(possibly with **LVM2_member** inside). In the commands below, replace
`/dev/nvme0n1p2` with yours.

(Optional, strongest protection: mark the whole internal disk read-only at the
block level first: `blockdev --setro /dev/nvme0n1`.)

## Step 6: Mount it read-only

Work through the cases in order.

**A. Encrypted (`crypto_LUKS`):** archinstall's "encrypt disk" option, or a
manual dm-crypt setup. Unlock it read-only:

```sh
cryptsetup open --readonly /dev/nvme0n1p2 suspect
lsblk -f /dev/mapper/suspect
```

From here on the device is `/dev/mapper/suspect`. If it shows **LVM2_member**,
continue with B. Otherwise skip to C, D or E.

**B. LVM on LUKS** (the classic manual Arch setup from the wiki):

```sh
vgchange -ay
lsblk -f                             # find the root volume, e.g. /dev/mapper/vg0-root
```

Use that volume as the device in C, D or E. A separate `home` volume gets
mounted at `/mnt/home` the same way.

**C. btrfs** (archinstall's default). The system lives in subvolumes:

```sh
mount -o ro /dev/nvme0n1p2 /mnt
ls /mnt                              # archinstall layout: @  @home  @log  @pkg  @.snapshots
umount /mnt
mount -o ro,rescue=nologreplay,subvol=@     /dev/nvme0n1p2 /mnt
mount -o ro,rescue=nologreplay,subvol=@home /dev/nvme0n1p2 /mnt/home
mount -o ro,rescue=nologreplay,subvol=@log  /dev/nvme0n1p2 /mnt/var/log   # optional
```

If `ls /mnt` showed normal folders (`etc`, `usr`, `home`…) instead of `@` names,
the system isn't in a subvolume and the first `mount` was all you needed. Don't
`umount`.

**D. ext4:**

```sh
mount -o ro,noload /dev/nvme0n1p2 /mnt
```

(`noload` stops the kernel from replaying the journal, so nothing is written.)

**E. XFS:**

```sh
mount -o ro,norecovery /dev/nvme0n1p2 /mnt
```

**Separate /home partition?** If `lsblk -f` showed another large Linux
partition, mount it read-only at `/mnt/home` using the matching command.

**Sanity check:**

```sh
ls /mnt                              # bin boot etc home usr var …
ls /mnt/home                         # your username(s)
ls /mnt/var/lib/pacman/local | head  # your installed packages
```

## Step 7: Run the scan

Save the report onto the stick, never onto the disk you're inspecting:

```sh
/tmp/wtf-check --root /mnt --no-color | tee /run/usb/wtf-report.txt
/tmp/wtf-check --root /mnt --json > /run/usb/wtf-report.json
```

If you brought a baseline from step 2:

```sh
/tmp/wtf-check --root /mnt --baseline /run/usb/wtf.baseline
```

The console only scrolls so far, so page through the saved report with
`less -R /run/usb/wtf-report.txt`.

Two notes always appear in an offline scan. They're expected, because a
powered-off system has no running processes: *"process check skipped: no
procfs"* and *"kernel taint not checked"*. Run wtf-check normally on the
booted system as well to cover those.

### Arch extra: check package integrity while you're here

pacman can verify every installed file against its package records, read-only,
from the live ISO:

```sh
pacman --sysroot /mnt -Qkk 2>&1 | grep -v ' 0 altered files' | tee /run/usb/pacman-Qkk.txt
pacman --sysroot /mnt -Qm | tee /run/usb/foreign-packages.txt
```

The first lists files that differ from what their package installed. Edited
configs in `/etc` (your `pacman.conf`, `fstab`…) are normal. Changed binaries
in `/usr/bin` or `/usr/lib` are not. The second lists foreign (AUR or locally
built) packages, which you can cross-check with wtf-check's `aur` findings.

## Step 8: Read the results

- The report is grouped **HIGH → MED → LOW → INFO**. HIGH first. Each finding
  has a *why* and a suggested *fix*.
- **LOW / INFO** is mostly an inventory: your SSH keys, cron jobs, user units
  and AUR packages. Confirm you recognise each one.
- **`aur` MED findings** mean a foreign package was installed or updated
  between 2026-06-09 and 2026-08-15, the window of the AUR malware waves. That
  doesn't prove it's malicious. Open the package's PKGBUILD history on
  `https://aur.archlinux.org/cgit/aur.git/log/?h=<package>` (from another
  device) and look at what changed in that period.
- Paths in the report include `/mnt`: `/mnt/etc/systemd/system/x.service` is
  `/etc/systemd/system/x.service` on your real system.
- Read the *False positives* section of the [README](../README.md) before
  worrying. Many LOW findings are normal.

**Don't fix things from the live USB yet.** Your disk is mounted read-only on
purpose. If you find something real:

1. Keep the reports, and copy suspicious files to the stick as evidence:
   `cp /mnt/path/to/file /run/usb/`
2. For a HIGH you didn't put there yourself (a non-empty `ld.so.preload`, a
   unit running from `/tmp`, an unknown root SSH key, a suspicious AUR
   package), **reinstalling is the safe choice**. From a different, trusted
   device, change your passwords and replace SSH keys and API tokens.
3. If you clean up instead, boot your normal system and run the suggested fix
   commands one at a time, after reading each one. Then reinstall any package
   `pacman -Qkk` reported as altered: `sudo pacman -S <package>`.

## Step 9: Clean up and reboot

```sh
umount -R /mnt
cryptsetup close suspect             # only if you unlocked LUKS in step 6A
umount /run/usb
reboot
```

Remove the stick when the screen goes dark, and turn Secure Boot back on in the
firmware setup if you turned it off. Your report is on the stick, ready to read
on any computer.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Ventoy menu doesn't list the ISO | The copy didn't finish, or the ISO is in a subfolder. Copy it again to the top level of the Ventoy drive and eject properly. |
| Black screen or "verification failed" when booting Arch | Secure Boot is still on. Turn it off (step 3). |
| `mount: /run/usb: … Device or resource busy` | `ventoy/ventoy.json` is missing or has a typo (step 1). |
| `GLIBC_2.xx not found` | You copied the normal build. Use the static musl build from step 2. |
| `Permission denied` running wtf-check | Run it from `/tmp` after `chmod +x`, not from the stick. |
| `wrong fs type, bad option, bad superblock` | Wrong case in step 6, or the partition is still locked (LUKS) or inside LVM. Re-check `lsblk -f`. |
| `/mnt` only shows `@` folders | btrfs subvolumes. See step 6C. |
| The report lists no homes | `/home` is on a separate partition or the `@home` subvolume, and isn't mounted yet. See step 6. |
| Keys type the wrong letters | Set your keyboard layout with `loadkeys` (step 3). |
| Nothing found | Good news, but not proof: wtf-check covers the common persistence spots, not every possible compromise. |

## Not on Arch?

The same steps work with any distro's live ISO, such as Ubuntu or Fedora
desktop images. Their desktops log you in as a normal user, so put `sudo` in
front of the mount, `cryptsetup` and wtf-check commands. Those ISOs usually
support Secure Boot, so you can leave it on.
