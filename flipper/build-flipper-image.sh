#!/bin/bash
# Build wtf-check's Flipper Zero boot image on Arch Linux.
#
#   ./flipper/build-flipper-image.sh            # builds wtf-check too
#   ./flipper/build-flipper-image.sh --wtf-check PATH --out FILE --size MB
#   ./flipper/build-flipper-image.sh --sign      # sign with your sbctl keys (Secure Boot on)
#
# Result: wtf-check-flipper.img, a small GPT disk image whose EFI partition
# holds one Unified Kernel Image (Arch kernel + initramfs with wtf-check and
# a guided read-only scan). Copy it to the Flipper's microSD under
# apps_data/mass_storage/ and open it with the Mass Storage app.
#
# Needs (all from the official repos):
#   sudo pacman -S --needed linux mkinitcpio systemd cryptsetup lvm2 \
#        util-linux dosfstools mtools rust rust-musl
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
out=$repo/wtf-check-flipper.img
size=auto
sign=0
bin=""
kver=""

while [ $# -gt 0 ]; do
    case $1 in
        --wtf-check) bin=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --size) size=$2; shift 2 ;;
        --kernel) kver=$2; shift 2 ;;
        --sign) sign=1; shift ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

need() { command -v "$1" >/dev/null || { echo "missing: $1 — install it with: sudo pacman -S --needed $2" >&2; exit 1; }; }
need mkinitcpio mkinitcpio
need cryptsetup cryptsetup
need lvm lvm2
need mkfs.fat dosfstools
need mcopy mtools
need sfdisk util-linux

# 1. The static wtf-check binary.
if [ -z "$bin" ]; then
    need cargo "rust rust-musl"
    echo "==> Building static wtf-check"
    (cd "$repo" && cargo build --release --locked --target x86_64-unknown-linux-musl)
    bin=$repo/target/x86_64-unknown-linux-musl/release/wtf-check
fi
[ -x "$bin" ] || { echo "not an executable: $bin" >&2; exit 1; }
if file "$bin" 2>/dev/null | grep -q "dynamically linked"; then
    echo "warning: $bin is dynamically linked; the static musl build is recommended" >&2
fi

# 2. Pick the installed 'linux' kernel.
if [ -z "$kver" ]; then
    for d in /usr/lib/modules/*/; do
        if [ "$(cat "$d/pkgbase" 2>/dev/null)" = linux ] && [ -f "$d/vmlinuz" ]; then kver=$(basename "$d"); fi
    done
fi
[ -n "$kver" ] && [ -f "/usr/lib/modules/$kver/vmlinuz" ] || { echo "no kernel found; install the 'linux' package or pass --kernel VERSION" >&2; exit 1; }
echo "==> Kernel $kver"

# 3. mkinitcpio with a private hook directory (the system's config is untouched).
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -a /usr/lib/initcpio "$work/initcpio"
cp "$here/initcpio/install/wtfcheck" "$work/initcpio/install/wtfcheck"
cp "$here/initcpio/hooks/wtfcheck" "$work/initcpio/hooks/wtfcheck"
cat > "$work/mkinitcpio.conf" <<CONF
MODULES=()
BINARIES=()
FILES=()
# No 'autodetect': include drivers for any machine, not just this one.
HOOKS=(base udev modconf block keyboard keymap consolefont filesystems encrypt wtfcheck)
COMPRESSION="zstd"
CONF
# No root= on purpose: the image never boots an installed system.
echo "quiet loglevel=3 rd.udev.log_level=3" > "$work/cmdline"

export WTF_CHECK_BIN=$bin
export WTF_SCAN_SCRIPT=$here/wtf-scan
echo "==> Building the Unified Kernel Image"
mkinitcpio -c "$work/mkinitcpio.conf" -D "$work/initcpio" -k "/usr/lib/modules/$kver/vmlinuz" \
    --cmdline "$work/cmdline" -U "$work/BOOTX64.EFI"

if [ "$sign" = 1 ]; then
    need sbctl sbctl
    echo "==> Signing with your sbctl Secure Boot keys"
    sbctl sign "$work/BOOTX64.EFI"
fi

# 4. Wrap it in a GPT disk image with a FAT32 EFI partition.
echo "==> Building the disk image"
"$here/make-disk-image.sh" "$work/BOOTX64.EFI" "$out" "$size"
sha256sum "$out"
cat <<DONE

Next steps:
  1. Copy $(basename "$out") to the Flipper's microSD card, folder
     apps_data/mass_storage/ (with qFlipper, or the card in a card reader).
  2. On the Flipper: Apps > USB > Mass Storage, open the image.
  3. Plug the Flipper into the computer to scan, boot from it (Secure Boot
     off), and follow the prompts. Reports land in the image's reports/ folder.
DONE
