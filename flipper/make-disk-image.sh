#!/bin/bash
# make-disk-image.sh EFI_FILE OUT_IMAGE [SIZE_MB|auto] [EXTRA_FILE...]
#
# Builds a GPT disk image with one FAT32 EFI System Partition labelled
# WTFCHECK, containing EFI/BOOT/BOOTX64.EFI and an empty reports/ folder.
# No root needed (uses mtools); the Flipper's Mass Storage app serves the
# image as a USB drive. Needs: mkfs.fat (dosfstools), mtools, sfdisk.
set -euo pipefail

efi=${1:?EFI file}
out=${2:?output image}
size_mb=${3:-auto}
shift 3 2>/dev/null || shift $#

for t in mkfs.fat mmd mcopy sfdisk; do
    command -v "$t" >/dev/null || { echo "missing tool: $t (install dosfstools, mtools, util-linux)" >&2; exit 1; }
done
efi_mb=$(( ( $(stat -c %s "$efi") + 1048575 ) / 1048576 ))
# Room for the boot file plus ~48 MiB for reports; FAT32 needs >= 33 MiB.
if [ "$size_mb" = auto ] || [ "$size_mb" -lt $(( efi_mb + 40 )) ]; then
    size_mb=$(( efi_mb + 48 ))
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
part=$tmp/part.img

# FAT32 partition contents.
mkfs.fat -C -F 32 -n WTFCHECK "$part" $(( size_mb * 1024 )) >/dev/null
mmd -i "$part" ::/EFI ::/EFI/BOOT ::/reports
mcopy -i "$part" "$efi" ::/EFI/BOOT/BOOTX64.EFI
cat > "$tmp/README.txt" <<TXT
wtf-check Flipper boot drive
============================
Boot a computer from this drive (Secure Boot off) to run a read-only
offline scan of its installed Linux system. Reports are saved in the
'reports' folder of this drive.
Project: https://github.com/noisyloop/wtf-check
TXT
mcopy -i "$part" "$tmp/README.txt" ::/README.txt
for f in "$@"; do mcopy -i "$part" "$f" "::/$(basename "$f")"; done

# GPT disk: 1 MiB alignment before, 1 MiB after for the backup table.
rm -f "$out"
truncate -s $(( (size_mb + 2) * 1024 * 1024 )) "$out"
printf 'label: gpt\nstart=2048, size=%d, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="WTFCHECK"\n' $(( size_mb * 2048 )) \
    | sfdisk --quiet "$out"
dd if="$part" of="$out" bs=1M seek=1 conv=notrunc status=none
echo "Disk image: $out ($(( size_mb + 2 )) MiB)"
