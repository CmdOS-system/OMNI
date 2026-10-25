"""Persist an immutable-style evidence bundle for a QEMU attempt.

Local file hashes establish integrity, not provenance or guest attestation.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def store(report, destination, *, serial_log=None):
    if not isinstance(report, dict) or report.get("status") != "BOOT_ATTEMPTED_UNATTESTED" or not report.get("qemu_started"):
        raise ValueError("only genuine boot-attempt reports accepted")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("destination already exists")
    if not destination.parent.is_dir():
        raise FileNotFoundError("destination parent missing")
    if serial_log is not None:
        serial_log = Path(serial_log)
        if not stat.S_ISREG(serial_log.lstat().st_mode):
            raise ValueError("serial log must be a regular file")
        serial_bytes = serial_log.read_bytes()
        if len(serial_bytes) > 8 * 1024 * 1024:
            raise ValueError("serial log exceeds limit")
    else:
        serial_bytes = None
    safe = dict(report)
    safe["guest_boot_verified"] = False
    safe["isolation_verified"] = False
    safe["compatibility_verdict"] = "NOT_CERTIFIED"
    safe["evidence_level"] = "LOCAL_UNATTESTED"
    safe["serial_sha256"] = digest(serial_bytes) if serial_bytes is not None else None
    payload = (json.dumps(safe, sort_keys=True, indent=2) + "\n").encode()
    manifest = {"schema": "omni.vm.evidence.v1", "report_sha256": digest(payload),
                "serial_sha256": digest(serial_bytes) if serial_bytes is not None else None,
                "guest_attested": False, "compatibility_certified": False}
    try:
        destination.mkdir(mode=0o700)
        (destination / "report.json").write_bytes(payload)
        if serial_bytes is not None:
            (destination / "serial.log").write_bytes(serial_bytes)
        (destination / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    except BaseException:
        # Fail closed: do not leave an apparently complete evidence directory.
        import shutil
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return manifest


def verify(destination):
    destination = Path(destination)
    errors = []
    try:
        manifest = json.loads((destination / "manifest.json").read_text())
        payload = (destination / "report.json").read_bytes()
        report = json.loads(payload)
        if digest(payload) != manifest.get("report_sha256"):
            errors.append("report_hash_mismatch")
        if report.get("evidence_level") != "LOCAL_UNATTESTED" or report.get("guest_boot_verified") is not False:
            errors.append("invalid_attestation_claim")
        serial_hash = manifest.get("serial_sha256")
        if serial_hash is not None:
            if digest((destination / "serial.log").read_bytes()) != serial_hash:
                errors.append("serial_hash_mismatch")
        if manifest.get("guest_attested") is not False or manifest.get("compatibility_certified") is not False:
            errors.append("invalid_manifest_claim")
    except (OSError, ValueError, TypeError):
        errors.append("bundle_unreadable")
    return {"status": "CONSISTENT_UNATTESTED" if not errors else "REJECTED",
            "errors": errors, "compatibility_certified": False}
