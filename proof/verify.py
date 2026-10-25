"""OMNI: fail-closed verification of a locally supplied evidence dossier.

This checks file integrity and internal consistency, NOT authenticity of the
recording agent, isolation, or third-party application compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_dossier(dossier: dict) -> dict:
    errors = []
    if not isinstance(dossier, dict):
        return {"status": "REJECTED", "errors": ["dossier must be an object"]}
    if dossier.get("verdict") in ("PASS", "CERTIFIED", "COMPATIBLE"):
        errors.append("self-asserted certification is prohibited")
    for field in ("run_id", "source_path", "source_sha256", "process"):
        if field not in dossier:
            errors.append(f"missing {field}")
    source = dossier.get("source_path")
    digest = dossier.get("source_sha256")
    if not isinstance(source, str) or not source:
        errors.append("invalid source_path")
    elif not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        errors.append("invalid source_sha256")
    else:
        try:
            path = Path(source)
            if path.is_symlink() or not path.is_file():
                errors.append("source missing or symlink")
            elif sha256_file(path) != digest:
                errors.append("source SHA-256 mismatch")
        except (OSError, ValueError) as exc:
            errors.append(f"cannot read source: {type(exc).__name__}")
    process = dossier.get("process")
    if not isinstance(process, dict):
        errors.append("process must be an object")
    else:
        pid = process.get("pid")
        if type(pid) is not int or pid <= 0:
            errors.append("invalid pid")
        if type(process.get("exit_code")) is not int:
            errors.append("missing integer exit_code")
    if not isinstance(dossier.get("run_id"), str) or not dossier.get("run_id"):
        errors.append("invalid run_id")
    return {
        "status": "REJECTED" if errors else "CONSISTENT_UNATTESTED",
        "errors": errors,
        "compatibility_certified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="OMNI evidence consistency checker")
    parser.add_argument("dossier", type=Path)
    args = parser.parse_args()
    try:
        with args.dossier.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
        result = verify_dossier(data)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "REJECTED", "errors": [str(exc)], "compatibility_certified": False}
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "CONSISTENT_UNATTESTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
