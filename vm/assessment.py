"""Read-only assessment of a saved QEMU attempt and its guest serial marker."""
import json
from pathlib import Path
from vm.evidence import verify
from vm.guest_marker import inspect_serial


def assess_bundle(bundle, expected_nonce):
    bundle = Path(bundle)
    integrity = verify(bundle)
    report = {"status": "BLOCKED", "bundle_integrity": integrity["status"],
              "marker_status": "NOT_CHECKED", "guest_boot_verified": False,
              "compatibility_verdict": "NOT_CERTIFIED", "errors": list(integrity["errors"])}
    if integrity["status"] != "CONSISTENT_UNATTESTED":
        return report
    try:
        manifest = json.loads((bundle / "manifest.json").read_text())
    except (OSError, ValueError):
        report["errors"].append("manifest_unreadable")
        return report
    if manifest.get("serial_sha256") is None:
        report["errors"].append("serial_evidence_absent")
        return report
    marker = inspect_serial(bundle / "serial.log", expected_nonce)
    report["marker_status"] = marker["status"]
    report["errors"].extend(marker["errors"])
    if marker["status"] == "GUEST_MARKER_OBSERVED_UNTRUSTED":
        report["status"] = "SERIAL_MARKER_CORRELATED_UNATTESTED"
    return report
