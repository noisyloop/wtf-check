# Scanning from a Flipper Zero

Your Flipper Zero can be the **only** thing you plug in. Its Mass Storage app
shows a disk image on its microSD card to a computer as a USB drive. The
wtf-check image is a tiny bootable system: the computer starts from the
Flipper, your installed Linux never runs, and a guided script scans the
internal disk **read-only** and saves the reports back onto the Flipper.

You don't need a USB stick, Ventoy or an Arch ISO, and nothing needs typing
except answers to a few questions.

> **Status:** the boot flow is tested end-to-end in QEMU with UEFI firmware.
> The tests cover plain ext4, LUKS-encrypted, and archinstall-style btrfs
> subvolume disks, and check that the scanned disks are byte-for-byte unchanged
> afterwards. It has **not yet been tried on a physical Flipper and laptop**,
> so do a test run on a machine you're not worried about first.

## What you need

- A **Flipper Zero** with a microSD card, and a **USB-C data cable** (some
  cables only charge).
- The **Mass Storage** app on the Flipper. Install it from the Flipper app
  catalog (*USB* category) using the Flipper mobile app or
  [qFlipper](https://github.com/flipperdevices/qFlipper).
- An **Arch Linux machine** to build the image, or a downloaded image (see step 1).
- The computer you want to scan: any **UEFI** PC (almost everything since about
  2012). Secure Boot must be off, unless you sign the image with your own keys
  (see *Secure Boot* below).

## Step 1: Get the image

**Download:** when the project publishes a release, `wtf-check-flipper.img` and
`SHA256SUMS` are attached on the
[Releases page](https://github.com/noisyloop/wtf-check/releases). Check it:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

**Or build it yourself on Arch.** This is recommended: your keyboard layout
gets built in, and you know exactly what's inside.

```sh
sudo pacman -S --needed git linux mkinitcpio cryptsetup lvm2 dosfstools mtools rust rust-musl
git clone https://github.com/noisyloop/wtf-check.git
cd wtf-check
./flipper/build-flipper-image.sh
```

The script:

1. Builds the static wtf-check.
2. Uses your system's `mkinitcpio` and `linux` kernel to make one UEFI boot file
   (a [Unified Kernel Image](https://wiki.archlinux.org/title/Unified_kernel_image)).
   It contains drivers for any machine, LUKS/LVM/btrfs/XFS support, wtf-check
   and the guided scan.
3. Wraps it in `wtf-check-flipper.img`, a small GPT disk with one FAT partition
   labelled `WTFCHECK`.

Your own mkinitcpio configuration is not touched. The script prints the image's
size and SHA-256 at the end.

Options: `--sign` (Secure Boot, see below), `--out FILE`, `--size MB`,
`--kernel VERSION`, `--wtf-check PATH` (use an existing static build).

**Keyboard layout:** the image uses the layout from the build machine's
`/etc/vconsole.conf` (`KEYMAP=…`). Prebuilt images use the US layout.

## Step 2: Put the image on the Flipper

The image goes in the Mass Storage app's folder on the microSD card:
`apps_data/mass_storage/`. Create the folder if it doesn't exist.

- **Fastest: card reader.** Turn the Flipper off, take out the microSD card,
  copy `wtf-check-flipper.img` into `apps_data/mass_storage/` on it, eject it
  properly, and put it back.
- **Without a card reader: qFlipper.** Connect the Flipper, open qFlipper's file
  manager, go to *SD Card → apps_data → mass_storage*, and drag the image in.
  This goes over the Flipper's slow serial link, so a 100+ MB file takes a
  while. You only do it once.

## Step 3: Boot the computer from the Flipper

1. Shut the computer down completely (not suspend or hibernate). Dual-boot with
   Windows? Turn off *Fast Startup* first.
2. In the firmware setup (usually F2 or Del at power-on), **turn off Secure
   Boot**, unless you used `--sign`.
3. On the Flipper, open **Apps → USB → Mass Storage** and select
   `wtf-check-flipper.img`. The Flipper shows it's acting as a drive. **Leave
   the app open until the scan says it's done.**
4. Plug the Flipper into the computer and power it on, tapping the **boot menu
   key** (Dell/Lenovo/Acer/Framework F12, HP F9, ASUS F8 or Esc, MSI F11; more
   in the [live USB guide](LIVE-USB.md#step-3-boot-your-arch-machine-from-the-stick)).
5. Pick the USB entry. It may be called *Flipper*, *UEFI: USB* or similar.

Booting takes noticeably longer than from a USB stick, because the Flipper's
USB is slow (12 Mbit/s). Give it a few minutes; the text appears when the boot
file has loaded.

## Step 4: Answer the questions

The scan walks you through everything. A typical session looks like this:

```text
------------------------------------------------------------------
 wtf-check offline scan (read-only)
 Your installed system is NOT running. Nothing on its disk is changed.
------------------------------------------------------------------
Looking for the wtf-check drive (WTFCHECK) to save reports...
  Reports will be saved to the drive (/dev/sda1) in /reports.
------------------------------------------------------------------
Disks and partitions:
  NAME           TYPE         LABEL                SIZE
  nvme0n1        -            -               488386 MiB
  nvme0n1p1      vfat         -                 1024 MiB
  nvme0n1p2      crypto_LUKS  -               487361 MiB
  sda            -            -                  130 MiB
  sda1           vfat         WTFCHECK           128 MiB  <- this wtf-check drive
  Most likely your system: nvme0n1p2
------------------------------------------------------------------
Pick the partition that holds your installed Linux system.
Partition name, e.g. nvme0n1p2 or sda2 (or 'shell' / 'off'): nvme0n1p2
  /dev/nvme0n1p2 is encrypted (LUKS). Unlocking read-only; enter its passphrase.
Enter passphrase for /dev/nvme0n1p2:
  btrfs subvolumes: system=@ home=@home
  Mounted read-only at /mnt:
    Arch Linux
------------------------------------------------------------------
Scanning... (this takes a minute; integrity checks hash system binaries)
...
Result: HIGH findings — read the report carefully.
Report saved as: reports/wtf-report-20261118-093012.txt
View the full report now (q to quit the viewer)? [y/N]
```

What happens behind the scenes:

- **Encrypted disks** are unlocked with `cryptsetup open --readonly`.
- **LVM** volumes are activated and listed so you can pick the root volume.
- **btrfs** subvolumes `@`, `@home` and `@log` (archinstall's layout, or
  Fedora's `root`/`home`) are found and mounted automatically.
- If `/home` is on a **separate partition**, it asks for it.
- Before mounting, the device is set **read-only at the block layer**
  (`blockdev --setro`). Every mount is `ro`, plus `noload` (ext4),
  `norecovery` (XFS) or `rescue=nologreplay` (btrfs), so not even a journal
  replay is written.
- wtf-check runs with every offline check, including `integrity`
  (modified binaries) and `rootkit` (known rootkit files). The text and JSON
  reports go to the Flipper.
- At the end everything is unmounted and synced. Press Enter to power off.

Typing `shell` at the partition prompt gives you a rescue shell (`exit` returns
to the questions); `off` powers off.

## Step 5: Read the reports

The reports are in the `reports` folder of the Flipper image:

- **On any computer:** open the image in the Mass Storage app again and plug
  the Flipper in. It appears as a drive named `WTFCHECK`.
- **From the microSD card on Linux**, without mounting anything:
  `mcopy -s -i wtf-check-flipper.img@@1M ::/reports .`

Each report has HIGH → MED → LOW → INFO sections, a *why* and a suggested
*fix* for each finding. Paths start with `/mnt` (that was your disk). Read
the [README's false-positive notes](../README.md#false-positives) and step 8
of the [live USB guide](LIVE-USB.md#step-8-read-the-results) for what to do
next.

## Secure Boot

The image isn't signed by Microsoft, so with Secure Boot on the firmware
refuses it. Either:

- turn Secure Boot off for the scan and back on afterwards, or
- if you already use your own keys with [sbctl](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot#sbctl),
  build with `./flipper/build-flipper-image.sh --sign`. The boot file is signed
  with your keys and boots with Secure Boot on, on machines that trust them.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| The Flipper isn't in the boot menu | The Mass Storage app isn't running with the image, or the cable only charges. Start the app first, try another cable, and make sure USB boot is enabled in the firmware. |
| "Verification failed" / "Secure Boot violation" | Secure Boot is on. See *Secure Boot* above. |
| Black screen for a long time | Normal at first: the Flipper is slow. If nothing appears after ~10 minutes, try another USB port (USB-A via an adapter often works better on older machines). |
| Keys type the wrong letters | The image uses the build machine's keymap. Rebuild on a machine with your layout, or type carefully: `y`/`z` and symbols move on some layouts. |
| Internal keyboard doesn't respond | Some newer laptops' keyboards need drivers outside the boot image. Use a USB keyboard (with a hub if you're short of ports). |
| "Drive not found or not writable" | The scan still works, but reports stay in memory. Read them on screen when asked, or check the Flipper is still in Mass Storage mode. |
| "Could not mount … read-only" | Wrong partition, or a filesystem that needs journal replay to mount at all. Type `shell` and look with `blkid`. |
| No disks listed | Unusual storage controller (some RAID/Intel VMD setups). Switch the SATA mode to AHCI in the firmware, or use the live USB guide. |

## For developers

| File | Purpose |
| --- | --- |
| `flipper/build-flipper-image.sh` | Arch build: mkinitcpio UKI + disk image |
| `flipper/initcpio/install/wtfcheck`, `hooks/wtfcheck` | mkinitcpio hook: bundles the tools, runs the scan instead of booting |
| `flipper/wtf-scan` | The guided, read-only scan (busybox `ash`) |
| `flipper/make-disk-image.sh` | GPT + FAT32 image assembly with mtools (no root, no loop devices) |
| `flipper/test/qemu-smoke.py` | End-to-end test in QEMU/OVMF (Debian/Ubuntu host) |

Run the end-to-end test:

```sh
sudo apt install qemu-system-x86 ovmf systemd-ukify busybox-static cryptsetup-bin lvm2 \
     btrfs-progs zstd mtools dosfstools fdisk python3-pexpect linux-image-virtual
cargo build --release --target x86_64-unknown-linux-musl
sudo flipper/test/qemu-smoke.py           # KEEP=1 keeps the console transcripts
```

It builds an image equivalent to the Arch one from the host's kernel, boots it
three times from an emulated USB drive, and each time picks the disk by the
type shown in the listing (NVMe names aren't stable between boots). The three
boots cover:

1. plain ext4,
2. LUKS, unlocked read-only,
3. btrfs `@`/`@home`.

For each boot it checks that the expected HIGH findings are in the reports
saved on the USB image, and that the scanned disks didn't change.
