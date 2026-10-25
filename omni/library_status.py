"""Read-only status summaries for the Windows application library.

A status is a point-in-time observation, not a trust or launch decision.
"""
from omni.library_health import check_catalog_integrity

STATUS_LABELS = {
    "checking": "Comprobando…",
    "unchanged": "Sin cambios",
    "modified": "Modificado",
    "missing": "No encontrado",
    "unavailable": "No disponible",
}


def format_catalog_row(record, status="checking"):
    """Present status without suggesting compatibility or security certification."""
    label = STATUS_LABELS.get(status, STATUS_LABELS["unavailable"])
    return (f'{record["name"]}  ·  {record["format"]}  ·  '
            f'{record["architecture"]}  ·  {label}')


def scan_catalog_statuses(records, checker=check_catalog_integrity):
    """Inspect a snapshot; failures of one file must not hide other entries.

    The caller runs this on a worker thread and discards stale generations.
    The scan does not alter catalog records or execute applications.
    """
    statuses = {}
    for record in records:
        # Corrupt or incomplete catalog entries must not abort the whole scan.
        # Skip entries without usable path keys; they cannot be shown safely.
        if not isinstance(record, dict):
            continue
        path = record.get("path")
        if not isinstance(path, str) or not path:
            continue
        try:
            result = checker(record)
            status = result.get("status") if isinstance(result, dict) else None
            if status not in ("unchanged", "modified", "missing", "unavailable"):
                status = "unavailable"
        except Exception:
            status = "unavailable"
        statuses[path] = status
    return statuses
