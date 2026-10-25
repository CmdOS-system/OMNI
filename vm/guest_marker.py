"""Parse an explicit guest boot marker from QEMU serial output.

A marker in a serial log is not independently authenticated; guest boot
remains unverified without a trusted witness or cryptographic root of trust.
"""
import json
from pathlib import Path
import re

PREFIX = "OMNI_GUEST_BOOT_V1 "
MAX_LOG = 8 * 1024 * 1024


def inspect_serial(path, expected_nonce):
    result = {"status": "UNATTESTED", "marker_found": False,
              "nonce_matches": False, "guest_boot_verified": False,
              "compatibility_verdict": "NOT_CERTIFIED", "errors": []}
    if not isinstance(expected_nonce, str) or not re.fullmatch("[0-9a-f]{32}", expected_nonce):
        result["errors"].append("invalid_expected_nonce")
        return result
    try:
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_LOG:
            result["errors"].append("serial_missing_or_unsafe")
            return result
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        result["errors"].append("serial_unreadable")
        return result
    markers = [line[len(PREFIX):] for line in lines if line.startswith(PREFIX)]
    if len(markers) != 1:
        result["errors"].append("marker_count_not_one")
        return result
    result["marker_found"] = True
    try:
        payload = json.loads(markers[0])
    except (ValueError, TypeError):
        result["errors"].append("marker_invalid_json")
        return result
    if not isinstance(payload, dict):
        result["errors"].append("marker_not_object")
        return result
    if payload.get("nonce") != expected_nonce:
        result["errors"].append("nonce_mismatch")
        return result
    if not isinstance(payload.get("kernel"), str) or not payload["kernel"]:
        result["errors"].append("kernel_missing")
        return result
    result["nonce_matches"] = True
    result["status"] = "GUEST_MARKER_OBSERVED_UNTRUSTED"
    return result
