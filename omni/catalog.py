"""Local OMNI inspected-file catalog. Metadata only, never executes files."""
import json
import os
from pathlib import Path
import tempfile


def default_catalog_path():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = str(Path.home() / ".local" / "share")
    return Path(base) / "OMNI" / "catalog.json"


def load_catalog(path=None):
    path = Path(path) if path is not None else default_catalog_path()
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or len(data) > 1000:
        raise ValueError("Invalid OMNI catalog")
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("Invalid OMNI catalog entry")
    return data


def save_catalog(entries, path=None):
    path = Path(path) if path is not None else default_catalog_path()
    if len(entries) > 1000:
        raise ValueError("OMNI catalog is full")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".omni-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(entries, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def add_inspection(file_path, inspection, catalog_path=None):
    entries = load_catalog(catalog_path)
    absolute = str(Path(file_path).resolve())
    record = {"path": absolute, "name": inspection["name"],
              "format": inspection["format"], "architecture": inspection["architecture"],
              "sha256": inspection["sha256"], "execution_authorized": False}
    entries = [e for e in entries if e["path"] != absolute]
    entries.insert(0, record)
    save_catalog(entries, catalog_path)
    return entries


def remove_inspection(file_path, catalog_path=None):
    entries = load_catalog(catalog_path)
    absolute = str(Path(file_path).resolve())
    entries = [e for e in entries if e["path"] != absolute]
    save_catalog(entries, catalog_path)
    return entries
