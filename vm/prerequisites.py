"""Fail-closed VM prerequisites gate, migrated from OMNI Research Lab v0.12.

Checks only prerequisites; does not boot a VM or attest isolation.
"""
import hashlib
import os
from pathlib import Path
import platform
import shutil
import stat


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def assess(image=None, expected_sha256=None, *, host=None, executable=None, kvm=None):
    system = host if host is not None else platform.system()
    qemu = executable if executable is not None else shutil.which("qemu-system-x86_64")
    if kvm is None:
        kvm = system == "Linux" and os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
    blockers = []
    if system != "Linux":
        blockers.append("backend_linux_kvm_only")
    if not qemu:
        blockers.append("qemu_system_missing")
    elif not Path(qemu).is_file():
        blockers.append("qemu_path_not_file")
    if not kvm:
        blockers.append("kvm_not_accessible")
    image_info = {"provided": bool(image), "sha256": None, "matches_expected": False}
    if not image:
        blockers.append("guest_image_missing")
    else:
        path = Path(image)
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                blockers.append("guest_image_not_regular_file")
            else:
                image_info["sha256"] = sha256(path)
                if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
                    blockers.append("expected_image_sha256_missing_or_invalid")
                else:
                    image_info["matches_expected"] = image_info["sha256"] == expected_sha256
                    if not image_info["matches_expected"]:
                        blockers.append("guest_image_hash_mismatch")
        except OSError:
            blockers.append("guest_image_unreadable")
    return {
        "schema": "omni.vm.prerequisites.v1",
        "host": system,
        "backend": "qemu-kvm-linux",
        "qemu_path": str(qemu) if qemu else None,
        "kvm_accessible": bool(kvm),
        "image": image_info,
        "prerequisites_met": not blockers,
        "blockers": blockers,
        "isolation_verified": False,
        "guest_attested": False,
        "disposable_lifecycle_verified": False,
        "status": "PREREQUISITES_ONLY" if not blockers else "BLOCKED",
        "compatibility_verdict": "NOT_CERTIFIED",
    }
