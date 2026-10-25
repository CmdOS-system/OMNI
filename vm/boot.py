"""Fail-closed QEMU boot attempt runner.

A launched QEMU process is NOT evidence that a guest OS booted.
No network, passthrough, or host sharing is configured.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def command(qemu, overlay, serial_log, *, memory_mib=512, cpus=1):
    if not (128 <= memory_mib <= 8192 and 1 <= cpus <= 8):
        raise ValueError("resource limits exceeded")
    return [str(qemu), "-nodefaults", "-display", "none", "-monitor", "none",
            "-nic", "none", "-no-reboot", "-machine", "q35,accel=tcg",
            "-m", str(memory_mib), "-smp", str(cpus),
            "-drive", "file=" + str(overlay) + ",if=virtio,format=qcow2,media=disk",
            "-serial", "file:" + str(serial_log)]


def attempt(overlay, expected_sha256, *, allow_boot=False, qemu=None, timeout=20):
    result = {"status": "BLOCKED", "compatibility_verdict": "NOT_CERTIFIED",
              "guest_boot_verified": False, "isolation_verified": False,
              "qemu_started": False, "blockers": [], "exit_code": None,
              "timed_out": False, "serial_sha256": None}
    if not allow_boot:
        result["blockers"].append("explicit_opt_in_required")
        return result
    overlay = Path(overlay)
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_sha256)):
        result["blockers"].append("invalid_overlay_hash")
        return result
    try:
        if not stat.S_ISREG(overlay.lstat().st_mode) or sha256(overlay) != expected_sha256:
            result["blockers"].append("overlay_untrusted_or_modified")
            return result
    except OSError:
        result["blockers"].append("overlay_missing")
        return result
    binary = qemu if qemu is not None else shutil.which("qemu-system-x86_64")
    if not binary or not Path(binary).is_file():
        result["blockers"].append("qemu_missing")
        return result
    if not (1 <= timeout <= 300):
        result["blockers"].append("invalid_timeout")
        return result
    with tempfile.TemporaryDirectory(prefix="omni-boot-") as directory:
        serial = Path(directory) / "serial.log"
        args = command(binary, overlay.resolve(), serial)
        try:
            # No shell. Dedicated process group permits terminating child processes.
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            result["qemu_started"] = True
            try:
                result["exit_code"] = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            result["status"] = "BOOT_ATTEMPTED_UNATTESTED"
            if serial.is_file():
                result["serial_sha256"] = sha256(serial)
        except OSError:
            result["blockers"].append("qemu_launch_failed")
    return result
