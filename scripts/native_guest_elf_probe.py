"""Compile and execute a freestanding x86_64 ELF in an actual QEMU Linux guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def assess_native_guest(data, nonce, expected_value, qemu_exit_code, timed_out):
    """Classify only a complete, successful guest execution."""
    result = ("OMNI_GUEST_NATIVE_PROGRAM_V1 value=" + str(expected_value)).encode()
    exit_marker = ("OMNI_NATIVE_EXIT_V1 nonce=" + nonce + " code=0").encode()
    lines = {line.strip() for line in data.splitlines()}
    native_ok = result in lines
    exit_ok = exit_marker in lines
    banner = bool(re.search(rb"Linux version [0-9]", data))
    panic = bool(re.search(rb"Kernel panic - not syncing", data, re.I))
    passed = native_ok and exit_ok and banner and not panic and qemu_exit_code == 0 and not timed_out
    return {
        "native_result_observed": native_ok,
        "native_exit_observed": exit_ok,
        "kernel_banner_observed": banner,
        "kernel_panic_observed": panic,
        "status": "NATIVE_ELF_GUEST_EXECUTED_UNATTESTED" if passed else "BLOCKED",
    }


def main():
    kernel = Path("/tmp/omni-guest-boot/vmlinuz")
    busybox = shutil.which("busybox")
    gcc = shutil.which("gcc")
    cpio = shutil.which("cpio")
    qemu = shutil.which("qemu-system-x86_64")
    if not kernel.is_file() or not all((busybox, gcc, cpio, qemu)):
        raise RuntimeError("real kernel, BusyBox, GCC, cpio, QEMU required")
    a = int.from_bytes(os.urandom(2), "big")
    b = int.from_bytes(os.urandom(2), "big")
    nonce = os.urandom(16).hex()
    output = Path("omni-native-guest-evidence")
    output.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "root"
        (root / "bin").mkdir(parents=True)
        (root / "dev").mkdir()
        shutil.copy2(busybox, root / "bin/busybox")
        native = root / "bin/omni-native"
        subprocess.run([gcc, "-nostdlib", "-static", "-no-pie", "-fno-stack-protector",
                        "-DOMNI_LEFT=" + str(a), "-DOMNI_RIGHT=" + str(b),
                        "-o", str(native), "guest/native_task.c"], check=True)
        (root / "init").write_text(
            "#!/bin/busybox sh\n"
            "/bin/omni-native > /dev/console\n"
            "rc=$?\n"
            "echo OMNI_NATIVE_EXIT_V1 nonce=" + nonce + " code=$rc > /dev/console\n"
            "/bin/busybox poweroff -f\n"
        )
        (root / "init").chmod(0o755)
        archive = Path(td) / "guest.cpio"
        with archive.open("wb") as f:
            subprocess.run([cpio, "-o", "-H", "newc", "--quiet"], cwd=root,
                           input=b"bin\nbin/busybox\nbin/omni-native\ndev\ninit\n",
                           stdout=f, check=True)
        serial = output / "serial.log"
        errors = output / "qemu-stderr.log"
        cmd = [qemu, "-nodefaults", "-display", "none", "-monitor", "none",
               "-nic", "none", "-no-reboot", "-machine", "q35,accel=tcg",
               "-m", "768", "-smp", "1", "-kernel", str(kernel),
               "-initrd", str(archive), "-append", "console=ttyS0 rdinit=/init panic=-1",
               "-serial", "file:" + str(serial)]
        with errors.open("wb") as err:
            try:
                process = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=err,
                                         timeout=90, check=False)
                rc, timed_out = process.returncode, False
            except subprocess.TimeoutExpired:
                rc, timed_out = None, True
        data = serial.read_bytes() if serial.exists() else b""
        checks = assess_native_guest(data, nonce, a + b, rc, timed_out)
        success = checks["status"] != "BLOCKED"
        report = {
            "schema": "omni.native_guest_elf.v1",
            "status": checks["status"],
            "source_sha256": sha256("guest/native_task.c"),
            "elf_sha256": sha256(native), "kernel_sha256": sha256(kernel),
            "initramfs_sha256": sha256(archive), "serial_sha256": hashlib.sha256(data).hexdigest(),
            "nonce": nonce, **checks, "qemu_exit_code": rc, "timed_out": timed_out,
            "third_party_app_executed": False, "compatibility_certified": False,
            "guest_attested": False,
        }
    (output / "summary.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    if not success:
        raise RuntimeError("independent native guest ELF execution not proven")

if __name__ == "__main__":
    main()
