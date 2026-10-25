"""Disposable QCOW2 overlay lifecycle check. Does NOT boot or isolate a guest."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def lifecycle(base, expected_hash, *, qemu_img=None, timeout=30):
    report = {"status": "BLOCKED", "compatibility_verdict": "NOT_CERTIFIED",
              "guest_booted": False, "isolation_verified": False, "blockers": []}
    base = Path(base)
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_hash)):
        report["blockers"].append("invalid_expected_sha256")
        return report
    try:
        if not stat.S_ISREG(base.lstat().st_mode):
            report["blockers"].append("base_not_regular")
            return report
        original = digest(base)
    except OSError:
        report["blockers"].append("base_unreadable")
        return report
    if original != expected_hash:
        report["blockers"].append("base_hash_mismatch")
        return report
    executable = qemu_img if qemu_img is not None else shutil.which("qemu-img")
    if not executable or not Path(executable).is_file():
        report["blockers"].append("qemu_img_missing")
        return report
    try:
        info = subprocess.run([str(executable), "info", "--output=json", str(base)],
                              capture_output=True, text=True, timeout=timeout, check=True)
        fmt = json.loads(info.stdout).get("format")
        if fmt not in ("raw", "qcow2"):
            report["blockers"].append("unsupported_base_format")
            return report
        with tempfile.TemporaryDirectory(prefix="omni-overlay-") as folder:
            overlay = Path(folder) / "disposable.qcow2"
            subprocess.run([str(executable), "create", "-f", "qcow2", "-F", fmt,
                            "-b", str(base.resolve()), str(overlay)],
                           capture_output=True, text=True, timeout=timeout, check=True)
            overlay_info = subprocess.run([str(executable), "info", "--output=json", str(overlay)],
                                          capture_output=True, text=True, timeout=timeout, check=True)
            meta = json.loads(overlay_info.stdout)
            if meta.get("format") != "qcow2" or meta.get("backing-filename") != str(base.resolve()):
                report["blockers"].append("overlay_backing_mismatch")
                return report
            if not overlay.is_file():
                report["blockers"].append("overlay_missing")
                return report
        if digest(base) != original:
            report["blockers"].append("base_changed")
            return report
        report["status"] = "OVERLAY_LIFECYCLE_ONLY"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        report["blockers"].append("qemu_img_operation_failed")
    return report
