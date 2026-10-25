"""Local OMNI inspected-file catalog. Metadata only, never executes files."""
import json
import os
from pathlib import Path
import tempfile
import shutil


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
        if (not isinstance(entry, dict) or not all(
            isinstance(entry.get(field), str) and entry[field]
            for field in ("path", "name", "format", "architecture", "sha256")
        )):
            raise ValueError("Invalid OMNI catalog entry")
    return data


def backup_catalog(path=None):
    """Create a separate, timestamp-free backup of the current catalog.

    Does not parse or modify the original, so malformed JSON is preserved.
    Existing backups are never overwritten.
    """
    path = Path(path) if path is not None else default_catalog_path()
    if not path.is_file():
        raise FileNotFoundError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids overwriting an earlier recovery copy.
    for index in range(1, 1001):
        backup = path.with_name(f"{path.name}.backup-{index:04d}")
        try:
            destination = backup.open("xb")
        except FileExistsError:
            continue
        try:
            with destination:
                with path.open("rb") as source:
                    shutil.copyfileobj(source, destination)
            return backup
        except Exception:
            backup.unlink(missing_ok=True)
            raise
    raise FileExistsError("No available OMNI catalog backup filename")


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
