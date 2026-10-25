"""Read-only integrity check for a previously inspected OMNI library entry.

Checking never updates the trusted fingerprint and never executes the file.
The file may still change between this check and a later launch.
"""
from omni.windows_preview import inspect_preview


def check_catalog_integrity(record):
    if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not record["path"]:
        raise ValueError("Catalog entry must have a nonempty path")
    path = record["path"]
    try:
        observed = inspect_preview(path)
    except FileNotFoundError:
        return {"path": path, "status": "missing", "changed_fields": [],
                "execution_performed": False}
    except (OSError, ValueError) as exc:
        return {"path": path, "status": "unavailable",
                "error_type": type(exc).__name__, "changed_fields": [],
                "execution_performed": False}
    fields = ("sha256", "format", "architecture")
    changed = [field for field in fields if record.get(field) != observed[field]]
    return {"path": path, "status": "modified" if changed else "unchanged",
            "changed_fields": changed, "observed": {
                field: observed[field] for field in fields},
            "execution_performed": False}
