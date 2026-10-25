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


def evaluate_guest_output(data, nonce, expected_sum, exit_code, timed_out):
    """Fail closed on missing markers, panic, timeout, or abnormal QEMU exit."""
    ready = marker_seen(data, nonce)
    expected = ("OMNI_GUEST_TASK_RESULT_V1 nonce=" + nonce
                + " value=" + str(expected_sum)).encode("ascii")
    task = any(line.strip() == expected for line in data.splitlines())
    banner = bool(re.search(rb"Linux version [0-9]", data))
    panic = bool(re.search(rb"Kernel panic - not syncing", data, re.I))
    passed = ready and task and banner and not panic and not timed_out and exit_code == 0
    return {
        "kernel_banner_observed": banner,
        "kernel_panic_observed": panic,
        "userspace_marker_observed": ready,
        "functional_task_observed": task,
        "status": "GUEST_FUNCTIONAL_TASK_OBSERVED_UNATTESTED" if passed else "BLOCKED",
    }


def main():
    kernel = Path("/tmp/omni-guest-boot/vmlinuz")
    busybox = shutil.which("busybox")
    qemu = shutil.which("qemu-system-x86_64")
    cpio = shutil.which("cpio")
    if not all((kernel.is_file(), busybox, qemu, cpio)):
        raise RuntimeError("real kernel, busybox, cpio, and QEMU required")
    nonce = os.urandom(16).hex()
    left = int.from_bytes(os.urandom(2), "big")
    right = int.from_bytes(os.urandom(2), "big")
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
            "result=$(( " + str(left) + " + " + str(right) + " ))\n"
            "echo OMNI_GUEST_TASK_RESULT_V1 nonce=" + nonce + " value=$result > /dev/console\n"
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
        checks = evaluate_guest_output(data, nonce, left + right, exit_code, timeout)
        report = {
            "schema": "omni.real_userspace_probe.v1",
            "status": checks["status"],
            "kernel_sha256": digest(kernel), "busybox_sha256": digest(busybox),
            "initramfs_sha256": digest(initrd), "serial_sha256": hashlib.sha256(data).hexdigest(),
            "serial_bytes": len(data), "nonce": nonce, **checks,
            "functional_task": "guest_shell_integer_addition", "qemu_exit_code": exit_code,
            "timed_out": timeout, "guest_attested": False,
            "third_party_app_executed": False, "compatibility_certified": False,
        }
    (out / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    if checks["status"] == "BLOCKED":
        raise RuntimeError("actual guest userspace marker not observed")


if __name__ == "__main__":
    main()
