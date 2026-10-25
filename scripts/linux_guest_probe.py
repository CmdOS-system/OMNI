"""Actual Ubuntu kernel/initramfs QEMU boot attempt.

An observed kernel message is evidence of kernel execution, not a complete
userspace boot or application compatibility.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    qemu = shutil.which("qemu-system-x86_64")
    kernel = Path("/tmp/omni-guest-boot/vmlinuz")
    initrd = Path("/tmp/omni-guest-boot/initrd.img")
    if not qemu or not kernel.is_file() or not initrd.is_file():
        raise RuntimeError("real QEMU and staged readable Ubuntu kernel/initramfs required")
    dest = Path("omni-linux-guest-evidence")
    dest.mkdir(exist_ok=False)
    serial = dest / "serial.log"
    stderr = dest / "qemu-stderr.log"
    cmd = [qemu, "-nodefaults", "-display", "none", "-monitor", "none",
           "-nic", "none", "-no-reboot", "-machine", "q35,accel=tcg",
           "-m", "768", "-smp", "1", "-kernel", str(kernel), "-initrd", str(initrd),
           "-append", "console=ttyS0 earlyprintk=serial panic=-1",
           "-serial", "file:" + str(serial)]
    with stderr.open("wb") as errors:
        try:
            subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=errors, timeout=75, check=False)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
    data = serial.read_bytes() if serial.exists() else b""
    # Require recognizable Linux kernel console output, not just QEMU process start.
    observed = bool(re.search(rb"Linux version [0-9]", data))
    report = {
        "schema": "omni.real_linux_guest_probe.v1",
        "qemu_path": qemu, "kernel": str(kernel), "initrd": str(initrd),
        "kernel_sha256": sha256(kernel), "initrd_sha256": sha256(initrd),
        "serial_sha256": hashlib.sha256(data).hexdigest(),
        "serial_bytes": len(data), "kernel_banner_observed": observed,
        "timed_out": timed_out, "guest_userspace_verified": False,
        "guest_boot_attested": False, "third_party_app_executed": False,
        "compatibility_certified": False,
        "status": "KERNEL_BANNER_OBSERVED_UNATTESTED" if observed else "BLOCKED"}
    (dest / "summary.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    if not observed:
        raise RuntimeError("Linux kernel console banner not observed")


if __name__ == "__main__":
    main()
