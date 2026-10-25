"""Boot a real minimal Linux userspace under QEMU and capture serial evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def marker_seen(serial, nonce):
    expected = b"OMNI_GUEST_USERSPACE_READY_V1 nonce=" + nonce.encode("ascii")
    return any(line.strip() == expected for line in serial.splitlines())


def main():
    kernel = Path("/tmp/omni-guest-boot/vmlinuz")
    busybox = shutil.which("busybox")
    qemu = shutil.which("qemu-system-x86_64")
    cpio = shutil.which("cpio")
    if not all((kernel.is_file(), busybox, qemu, cpio)):
        raise RuntimeError("real kernel, busybox, cpio, and QEMU required")
    nonce = os.urandom(16).hex()
    out = Path("omni-userspace-evidence")
    out.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="omni-userspace-") as tmp:
        root = Path(tmp) / "root"
        (root / "bin").mkdir(parents=True)
        (root / "dev").mkdir()
        (root / "proc").mkdir()
        (root / "sys").mkdir()
        shutil.copy2(busybox, root / "bin/busybox")
        (root / "init").write_text(
            "#!/bin/busybox sh\n"
            "/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true\n"
            "/bin/busybox mount -t proc proc /proc 2>/dev/null || true\n"
            "echo 'OMNI_GUEST_USERSPACE_READY_V1 nonce=" + nonce + "' > /dev/console\n"
            "/bin/busybox poweroff -f\n"
        )
        (root / "init").chmod(0o755)
        initrd = Path(tmp) / "guest.cpio"
        names = ["bin", "bin/busybox", "dev", "proc", "sys", "init"]
        with initrd.open("wb") as f:
            subprocess.run([cpio, "-o", "-H", "newc", "--quiet"], cwd=root,
                           input=("\n".join(names) + "\n").encode(),
                           stdout=f, check=True)
        serial = out / "serial.log"
        errors = out / "qemu-stderr.log"
        cmd = [qemu, "-nodefaults", "-display", "none", "-monitor", "none",
               "-nic", "none", "-no-reboot", "-machine", "q35,accel=tcg",
               "-m", "768", "-smp", "1", "-kernel", str(kernel),
               "-initrd", str(initrd),
               "-append", "console=ttyS0 rdinit=/init panic=-1",
               "-serial", "file:" + str(serial)]
        with errors.open("wb") as err:
            try:
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                        stdin=subprocess.DEVNULL, stderr=err,
                                        timeout=90, check=False)
                exit_code, timeout = result.returncode, False
            except subprocess.TimeoutExpired:
                exit_code, timeout = None, True
        data = serial.read_bytes() if serial.exists() else b""
        observed = marker_seen(data, nonce)
        banner = bool(re.search(rb"Linux version [0-9]", data))
        report = {
            "schema": "omni.real_userspace_probe.v1",
            "status": "GUEST_USERSPACE_MARKER_OBSERVED_UNATTESTED" if observed and banner else "BLOCKED",
            "kernel_sha256": digest(kernel), "busybox_sha256": digest(busybox),
            "initramfs_sha256": digest(initrd), "serial_sha256": hashlib.sha256(data).hexdigest(),
            "serial_bytes": len(data), "nonce": nonce, "kernel_banner_observed": banner,
            "userspace_marker_observed": observed, "qemu_exit_code": exit_code,
            "timed_out": timeout, "guest_attested": False,
            "third_party_app_executed": False, "compatibility_certified": False,
        }
    (out / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    if not (observed and banner):
        raise RuntimeError("actual guest userspace marker not observed")


if __name__ == "__main__":
    main()
