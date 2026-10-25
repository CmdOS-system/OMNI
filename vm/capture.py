"""Opt-in QEMU boot attempt with captured, hashed local evidence.

No guest attestation, no application compatibility claim.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile

from vm.boot import command
from vm.evidence import store


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def capture(overlay, expected_sha256, destination, *, allow_boot=False, qemu=None, timeout=20):
    report = {"status": "BLOCKED", "qemu_started": False, "guest_boot_verified": False,
              "isolation_verified": False, "compatibility_verdict": "NOT_CERTIFIED",
              "exit_code": None, "timed_out": False, "blockers": []}
    if not allow_boot:
        report["blockers"].append("explicit_opt_in_required")
        return report
    overlay, destination = Path(overlay), Path(destination)
    if not re.fullmatch("[0-9a-f]{64}", str(expected_sha256)):
        report["blockers"].append("invalid_overlay_hash")
        return report
    try:
        if not stat.S_ISREG(overlay.lstat().st_mode) or sha256(overlay) != expected_sha256:
            report["blockers"].append("overlay_hash_mismatch")
            return report
    except OSError:
        report["blockers"].append("overlay_unreadable")
        return report
    binary = qemu if qemu is not None else shutil.which("qemu-system-x86_64")
    if not binary or not Path(binary).is_file():
        report["blockers"].append("qemu_missing")
        return report
    if not 1 <= timeout <= 300:
        report["blockers"].append("invalid_timeout")
        return report
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        report["blockers"].append("evidence_destination_invalid")
        return report
    with tempfile.TemporaryDirectory(prefix="omni-capture-") as folder:
        serial = Path(folder) / "serial.log"
        stderr = Path(folder) / "qemu-stderr.log"
        try:
            with stderr.open("wb") as error_stream:
                proc = subprocess.Popen(command(binary, overlay.resolve(), serial),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=error_stream, start_new_session=True)
                report["qemu_started"] = True
                try:
                    report["exit_code"] = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    report["timed_out"] = True
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            report["status"] = "BOOT_ATTEMPTED_UNATTESTED"
            report["qemu_stderr_sha256"] = sha256(stderr)
            report["qemu_stderr_bytes"] = stderr.stat().st_size
            store(report, destination, serial_log=serial if serial.is_file() else None)
        except (OSError, ValueError) as exc:
            report["blockers"].append("launch_or_evidence_failed:" + type(exc).__name__)
            report["status"] = "BLOCKED"
    return report
