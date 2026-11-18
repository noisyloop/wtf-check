# Scanning from a live USB: a step-by-step guide

This guide is for people who have never booted a computer from a USB stick.
It takes about 30–45 minutes the first time.

## Why bother?

When you run wtf-check on your normal, running system, you are asking that
system to report on itself. If it has been seriously compromised (a *rootkit*
in the kernel, or a library injected into every program via
`/etc/ld.so.preload`), the malware can hide its files and processes from
**any** program running on it, wtf-check included.

Booting from a USB stick means your installed system is **not running at all**.
Its disk is just data, and nothing on it gets a chance to lie. wtf-check reads
it from the outside with `--root`.

## What you need

- **One USB stick**, 8 GB or larger. **It will be erased**, so copy off anything
  you want to keep. It holds the live system, wtf-check and your report.
- **A second, trusted computer** to prepare the stick. If you suspect your
  computer is compromised, don't prepare it there.
- About 30 minutes during which the suspect computer is switched off from its
  normal system.

> **Safety first:** this guide only **reads** your disk. Every mount command
> below is read-only. Don't skip the `ro` options, and don't click your internal
> disk in the live system's file manager: that mounts it read-write.

---

## Step 1: Make the USB stick bootable with Ventoy

[Ventoy](https://www.ventoy.net) turns a stick into a boot menu for ISO files
while the rest of it stays normal storage. That's what lets one stick hold the
live system, wtf-check and your report.

1. On the trusted computer, download Ventoy from
   <https://www.ventoy.net/en/download.html> (or its GitHub releases page).
2. Install it to the stick. This **erases** the stick.
   - **Windows:** unzip, run `Ventoy2Disk.exe`, pick the stick under *Device*,
     click *Install*.
   - **Linux:** unpack, then run `VentoyGUI.x86_64`, or in a terminal:
     ```sh
     lsblk                          # find the stick, e.g. /dev/sdb (whole disk, not sdb1)
     sudo sh Ventoy2Disk.sh -i /dev/sdX
     ```
     Double-check `sdX`. Installing to the wrong disk erases it.

Afterwards the stick shows up as a normal drive called **Ventoy**.

> **Can't use Ventoy?** Write the Ubuntu ISO with [Rufus](https://rufus.ie),
> [balenaEtcher](https://etcher.balena.io) or GNOME Disks (*Restore Disk
> Image…*) instead. Those take over the whole stick, so you'll need a second
> stick for wtf-check and the report. Wherever this guide says
> `/media/ubuntu/Ventoy`, use the second stick's folder.

## Step 2: Copy Ubuntu and wtf-check onto the stick

**Ubuntu.** Use Ubuntu Desktop if you're unsure. It has a normal desktop and
recognises most hardware. (The Arch Linux ISO also works, but it's text-only.)

1. Download the ISO from the official site only:
   <https://ubuntu.com/download/desktop>
2. Verify it. The site publishes a `SHA256SUMS` file. Compare:
   - Linux: `sha256sum ubuntu-*.iso` (macOS: `shasum -a 256 ubuntu-*.iso`)
   - Windows (PowerShell): `Get-FileHash .\ubuntu-*.iso`
3. Copy the `.iso` file onto the Ventoy drive like any other file. Don't unpack it.

**wtf-check.** Use the **static (musl) build**. It runs on any Linux, including
a live system with a different libc version, and it ignores
`LD_PRELOAD`/`ld.so.preload` entirely. With Rust installed from
<https://rustup.rs>:

```sh
git clone https://github.com/noisyloop/wtf-check.git && cd wtf-check
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/wtf-check
```

(For ARM machines, use `aarch64-unknown-linux-musl` instead.)

Copy `target/x86_64-unknown-linux-musl/release/wtf-check` onto the Ventoy
drive, next to the ISO, and write down the `sha256sum` output.

Optional: if you saved a baseline earlier on the healthy system
(`sudo wtf-check --save-baseline wtf.baseline`), copy that onto the stick too.

## Step 3: Boot the suspect computer from the stick

1. Shut the suspect computer down completely (not sleep or hibernate).
   **Windows dual-boot users:** hold Shift while clicking *Shut down*, or disable
   *Fast Startup*, so the Windows partition isn't left in a half-mounted state.
2. Plug in the stick.
3. Power on and immediately tap the **boot menu key**. Common ones:

   | Maker | Boot menu key |
   | --- | --- |
   | Dell | F12 |
   | HP | F9 (or Esc, then F9) |
   | Lenovo | F12 (ThinkPad: Enter, then F12; some IdeaPads: the small *Novo* button) |
   | ASUS | F8 or Esc |
   | Acer | F12 (may need enabling in BIOS with F2) |
   | MSI | F11 |
   | Gigabyte | F12 |
   | Framework | F12 |
   | Apple Intel Mac | hold Option ⌥ |

4. Pick the USB entry (often labelled *UEFI: <stick name>*).
5. The Ventoy menu lists your ISO. Select it, then **Boot in normal mode**.
6. Choose **Try or Install Ubuntu**, then on the welcome screen **Try Ubuntu**.
   **Don't** install.

**Secure Boot screen?** The first time, a computer with Secure Boot on may
show a blue *Verification failed* screen. Press Enter, choose *Enroll key from
disk*, then `VTOYEFI` → `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`, confirm, and
reboot. If that's too fiddly, turn Secure Boot off in firmware setup and back
on afterwards.

If it won't boot at all: enter the firmware setup (usually F2 or Del at
power-on) and check that USB boot is enabled.

## Step 4: Open a terminal and find wtf-check

- Press **Ctrl+Alt+T** (or open *Terminal* from the app grid).
- The stick's storage is at `/media/ubuntu/Ventoy`. If it isn't there, click
  **Ventoy** once in the Files app to mount it. (That's your stick, which is
  fine to click. Your internal disk isn't.)

Copy wtf-check off the stick, since programs can't run straight from it, and verify it:

```sh
ls /media/ubuntu/Ventoy/
cp /media/ubuntu/Ventoy/wtf-check /tmp/wtf-check
chmod +x /tmp/wtf-check
sha256sum /tmp/wtf-check      # must match what you wrote down in step 2
```

## Step 5: Find your installed system's disk

```sh
lsblk -f
```

You'll see something like:

```
NAME        FSTYPE      LABEL   SIZE MOUNTPOINTS
sda                              16G                ← your USB stick
├─sda1      exfat       Ventoy   16G /media/ubuntu/Ventoy   ← wtf-check and the ISO
└─sda2      vfat        VTOYEFI  32M                ← Ventoy's boot files (skip)
nvme0n1                         512G                 ← your internal disk
├─nvme0n1p1 vfat                  1G                 ← EFI partition (skip)
├─nvme0n1p2 ext4                500G                 ← your Linux system  ✔
└─nvme0n1p3 swap                  8G                 ← swap (skip)
```

Look for the big partition on the internal disk (`nvme0n1…` or `sda…`)
with type **ext4**, **btrfs**, **xfs**, **crypto_LUKS** or **LVM2_member**. In
the commands below, replace `/dev/nvme0n1p2` with yours.

(Optional, strongest protection: mark the whole internal disk read-only at the
block level before mounting: `sudo blockdev --setro /dev/nvme0n1`.)

## Step 6: Mount it read-only

Pick the case that matches the **FSTYPE** you saw.

**A. Encrypted (`crypto_LUKS`):** unlock first, read-only:

```sh
sudo cryptsetup open --readonly /dev/nvme0n1p2 suspect
# enter your disk password; the unlocked device is /dev/mapper/suspect
lsblk -f /dev/mapper/suspect     # see what's inside, then continue with B–E below,
                                 # using /dev/mapper/suspect as the device
```

**B. LVM (`LVM2_member`, common on Fedora or encrypted Ubuntu):**

```sh
sudo vgchange -ay
lsblk -f                         # pick the root volume, e.g. /dev/mapper/vgubuntu-root
```

**C. ext4** (most Ubuntu/Debian/Mint/Arch installs):

```sh
sudo mkdir -p /mnt
sudo mount -o ro,noload /dev/nvme0n1p2 /mnt
```

(`noload` stops the kernel from replaying the journal, so nothing at all is written.)

**D. btrfs** (Fedora, openSUSE, many Arch installs). The system usually lives in
a *subvolume*:

```sh
sudo mount -o ro /dev/nvme0n1p2 /mnt
ls /mnt                          # if you see @ and @home (or root and home):
sudo umount /mnt
sudo mount -o ro,rescue=nologreplay,subvol=@ /dev/nvme0n1p2 /mnt
sudo mount -o ro,rescue=nologreplay,subvol=@home /dev/nvme0n1p2 /mnt/home
```

(Fedora names them `root` and `home` instead of `@` and `@home`.)

**E. XFS:**

```sh
sudo mount -o ro,norecovery /dev/nvme0n1p2 /mnt
```

**Separate /home partition?** If `lsblk -f` showed a second large Linux
partition, mount it too, the same way, at `/mnt/home`:

```sh
sudo mount -o ro,noload /dev/nvme0n1p4 /mnt/home    # ext4 example
```

Sanity check. You should see your system's folders and users:

```sh
ls /mnt            # bin  boot  etc  home  usr  var …
ls /mnt/home       # your username(s)
```

## Step 7: Run the scan

Save the report onto **the USB stick**, never onto the disk you're inspecting:

```sh
REPORT=/media/ubuntu/Ventoy
sudo /tmp/wtf-check --root /mnt --no-color | tee "$REPORT/wtf-report.txt"
sudo /tmp/wtf-check --root /mnt --json > "$REPORT/wtf-report.json"
```

If you brought a baseline from step 2:

```sh
sudo /tmp/wtf-check --root /mnt --baseline /media/ubuntu/Ventoy/wtf.baseline
```

Notes you'll always see in offline mode, which are expected and fine:
*"process check skipped: no procfs"* and *"kernel taint not checked"*. There are
no running processes on a powered-off system. Run wtf-check normally on the
booted system as well to cover those.

## Step 8: Read the results

- The report is grouped **HIGH → MED → LOW → INFO**.
- **HIGH:** look at these first. Each one has a *why* and a suggested *fix*.
- **LOW / INFO:** mostly an inventory (your SSH keys, your cron jobs, your AUR
  packages). Ask yourself whether you recognise each one.
- Paths in the report include `/mnt`, e.g. `/mnt/etc/systemd/system/x.service`
  is `/etc/systemd/system/x.service` on your real system.
- See the *False positives* section of the [README](../README.md) before
  panicking. Many LOW findings are normal.

**Don't fix things from the live USB yet.** Your disk is mounted read-only on
purpose. If you find something real:

1. Keep the report and, ideally, a copy of the suspicious files (copy them to
   the stick: `sudo cp /mnt/path/to/file /media/ubuntu/Ventoy/`).
2. Decide whether to clean up or reinstall. For anything HIGH that you didn't
   put there yourself (e.g. a non-empty `ld.so.preload`, a process disguised as
   a kernel thread, an unknown root SSH key), **reinstalling** is the safe
   choice. Also **change passwords and rotate SSH keys/tokens from a different,
   trusted device**.
3. If you do clean up, boot your normal system (or remount read-write) and run
   the suggested fix commands one by one after reading them.

## Step 9: Clean up and reboot

```sh
sudo umount -R /mnt
sudo cryptsetup close suspect      # only if you unlocked LUKS in step 6A
```

Then reboot and remove the stick. Your computer starts normally, and your report
is on the stick, ready to read on any computer.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Ventoy menu doesn't list the ISO | The copy didn't finish, or the file is in a subfolder. Copy it again to the top level of the Ventoy drive and eject the stick properly. |
| `GLIBC_2.xx not found` | You copied the normal build. Use the static musl build from step 2. |
| `Permission denied` running wtf-check | Run it from `/tmp` after `chmod +x` (USB sticks are often `noexec`), and use `sudo`. |
| `wrong fs type, bad option, bad superblock` | Wrong FSTYPE case in step 6, or the partition is still locked (LUKS) or inside LVM. Re-check `lsblk -f`. |
| btrfs: `unrecognized mount option "rescue=nologreplay"` | Older live kernel: use `-o ro,nologreplay,subvol=@` instead. |
| `/mnt` is empty or has only `@` folders | btrfs subvolumes, see step 6D. |
| ntfs / "The disk contains an unclean file system" | That's a Windows partition. wtf-check audits Linux; skip it. |
| The report shows no homes | `/home` is on a separate partition you haven't mounted. See *Separate /home* in step 6. |
| Nothing found | Good news, but not proof: wtf-check covers common persistence spots, not every possible compromise. |
