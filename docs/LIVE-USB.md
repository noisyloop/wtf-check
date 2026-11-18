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

- **Two USB sticks** (or one big one, see the Ventoy tip in step 1):
  - **Stick A**, 4 GB or more, becomes the live system. **It will be erased.**
  - **Stick B**, any size, holds the wtf-check program and your report.
- **A second, trusted computer** to prepare the sticks. If you suspect your
  computer is compromised, don't prepare the sticks on it.
- About 30 minutes during which the suspect computer is switched off from its
  normal system.

> **Safety first:** this guide only **reads** your disk. Every mount command
> below is read-only. Don't skip the `ro` options, and don't click your internal
> disk in the live system's file manager: that mounts it read-write.

---

## Step 1: Make the live USB (Stick A)

Use **Ubuntu Desktop** if you're unsure. It works with Secure Boot, has a
normal desktop, and recognises most hardware. (Arch Linux's ISO works too, but
you must turn off Secure Boot and it's text-only.)

1. On the trusted computer, download the ISO **from the official site only**:
   <https://ubuntu.com/download/desktop>
2. Verify the download. The site publishes a `SHA256SUMS` file. Compare:
   - Linux/macOS: `sha256sum ubuntu-*.iso` (macOS: `shasum -a 256 ubuntu-*.iso`)
   - Windows (PowerShell): `Get-FileHash .\ubuntu-*.iso`

   The long hex string must match the one in `SHA256SUMS` exactly.
3. Write the ISO to Stick A (this **erases** the stick):
   - **Windows:** [Rufus](https://rufus.ie), select the stick, select the ISO, click Start.
   - **macOS / Windows / Linux:** [balenaEtcher](https://etcher.balena.io), then Flash from file, Select target, Flash.
   - **Linux (GNOME):** open *Disks*, select the stick, choose the ⋮ menu, then *Restore Disk Image…*.
   - **Linux (terminal):** find the stick with `lsblk` (e.g. `/dev/sdb`, *not* a
     partition like `/dev/sdb1`), then:
     ```sh
     sudo dd if=ubuntu-*.iso of=/dev/sdX bs=4M status=progress oflag=sync
     ```
     Double-check `sdX`. `dd` to the wrong disk destroys it.

> **Tip, one stick only:** [Ventoy](https://www.ventoy.net) turns a single stick
> into a boot menu for ISO files and leaves the rest of the stick as normal
> storage. Copy the ISO *and* wtf-check onto it and you won't need Stick B.

## Step 2: Put wtf-check on Stick B

Use the **static (musl) build**. It runs on any Linux, including a live system
with a different libc version, and it ignores `LD_PRELOAD`/`ld.so.preload`
entirely.

On the trusted computer (with Rust installed from <https://rustup.rs>):

```sh
git clone <this repository> wtf-check && cd wtf-check
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/wtf-check
```

(For ARM machines, use `aarch64-unknown-linux-musl` instead.)

Copy `target/x86_64-unknown-linux-musl/release/wtf-check` to Stick B and write
down the `sha256sum` output. You'll check it again on the live system.

Optional but useful: if you saved a baseline earlier on the healthy system
(`sudo wtf-check --save-baseline wtf.baseline`), copy that file to Stick B too.
Baselines from a running system can be compared against an offline scan.

## Step 3: Boot the suspect computer from Stick A

1. Shut the suspect computer down completely (not sleep or hibernate).
   **Windows dual-boot users:** hold Shift while clicking *Shut down*, or disable
   *Fast Startup*, so the Windows partition isn't left in a half-mounted state.
2. Plug in Stick A.
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
5. In the Ubuntu menu choose **Try or Install Ubuntu**, then on the welcome
   screen choose **Try Ubuntu**. **Don't** install.

If it refuses to boot: enter the firmware setup (usually F2 or Del at power-on)
and check that USB boot is enabled. Only for the Arch ISO, disable Secure Boot.
Re-enable it afterwards.

## Step 4: Open a terminal and plug in Stick B

- Press **Ctrl+Alt+T** (or open *Terminal* from the app grid).
- Plug in Stick B. Ubuntu mounts it automatically under `/media/ubuntu/<name>`.
  Check with:
  ```sh
  ls /media/ubuntu/*/
  ```

Copy wtf-check off the stick (USB sticks are often mounted `noexec`) and verify it:

```sh
cp /media/ubuntu/*/wtf-check /tmp/wtf-check
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
sda         iso9660     Ubuntu    5G /cdrom          ← Stick A (the live system)
sdb
└─sdb1      vfat        STICKB   16G /media/ubuntu/STICKB   ← Stick B
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

Save the report onto **Stick B**, never onto the disk you're inspecting:

```sh
REPORT=/media/ubuntu/STICKB      # adjust to your stick's name
sudo /tmp/wtf-check --root /mnt --no-color | tee "$REPORT/wtf-report.txt"
sudo /tmp/wtf-check --root /mnt --json > "$REPORT/wtf-report.json"
```

If you brought a baseline from step 2:

```sh
sudo /tmp/wtf-check --root /mnt --baseline /media/ubuntu/STICKB/wtf.baseline
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
   Stick B: `sudo cp /mnt/path/to/file /media/ubuntu/STICKB/evidence/`).
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

Then reboot, remove Stick A, and your computer starts normally.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `GLIBC_2.xx not found` | You copied the normal build. Use the static musl build from step 2. |
| `Permission denied` running wtf-check | Run it from `/tmp` after `chmod +x` (USB sticks are often `noexec`), and use `sudo`. |
| `wrong fs type, bad option, bad superblock` | Wrong FSTYPE case in step 6, or the partition is still locked (LUKS) or inside LVM. Re-check `lsblk -f`. |
| btrfs: `unrecognized mount option "rescue=nologreplay"` | Older live kernel: use `-o ro,nologreplay,subvol=@` instead. |
| `/mnt` is empty or has only `@` folders | btrfs subvolumes, see step 6D. |
| ntfs / "The disk contains an unclean file system" | That's a Windows partition. wtf-check audits Linux; skip it. |
| The report shows no homes | `/home` is on a separate partition you haven't mounted. See *Separate /home* in step 6. |
| Nothing found | Good news, but not proof: wtf-check covers common persistence spots, not every possible compromise. |
