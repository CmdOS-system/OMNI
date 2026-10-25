"""Real QEMU process smoke test, with blank disk and NO guest OS.

This exercises actual installed QEMU, never certifies a boot or an app.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from vm.capture import capture
from vm.evidence import verify


def main():
    qemu = shutil.which("qemu-system-x86_64")
    qemu_img = shutil.which("qemu-img")
    if not qemu or not qemu_img:
        raise RuntimeError("real QEMU packages are required; no fake fallback")
    root = Path("omni-real-qemu-evidence")
    if root.exists():
        raise RuntimeError("refusing to overwrite prior evidence")
    root.mkdir()
    version = subprocess.run([qemu, "--version"], check=True, capture_output=True, text=True)
    image_version = subprocess.run([qemu_img, "--version"], check=True, capture_output=True, text=True)
    if "QEMU" not in version.stdout or "qemu-img" not in image_version.stdout:
        raise RuntimeError("real QEMU identity checks failed")
    with tempfile.TemporaryDirectory(prefix="omni-real-qemu-") as temp:
        disk = Path(temp) / "blank.qcow2"
        subprocess.run([qemu_img, "create", "-f", "qcow2", str(disk), "16M"], check=True,
                       capture_output=True, text=True)
        digest = hashlib.sha256(disk.read_bytes()).hexdigest()
        report = capture(disk, digest, root / "attempt", allow_boot=True, qemu=qemu, timeout=3)
    integrity = verify(root / "attempt")
    summary = {"qemu_version": version.stdout.strip(), "qemu_img_version": image_version.stdout.strip(),
               "qemu_binary": qemu, "qemu_img_binary": qemu_img,
               "qemu_process_started": report["qemu_started"],
               "qemu_process_timed_out": report["timed_out"],
               "status": report["status"], "evidence_integrity": integrity["status"],
               "guest_os_present": False, "guest_boot_verified": False,
               "third_party_app_executed": False, "compatibility_certified": False}
    (root / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True, indent=2))
    if not report["qemu_started"] or not report["timed_out"] or integrity["status"] != "CONSISTENT_UNATTESTED":
        raise RuntimeError("real QEMU smoke failed: inspect captured evidence")


if __name__ == "__main__":
    main()
