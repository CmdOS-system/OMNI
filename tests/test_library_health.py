"""Real-file tests for OMNI's read-only library integrity check."""
import tempfile
from pathlib import Path
import unittest

from omni.catalog import add_inspection, load_catalog
from omni.library_health import check_catalog_integrity
from omni.windows_preview import inspect_preview


class LibraryHealthTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "demo.wasm"
        self.path.write_bytes(bytes.fromhex("0061736d01000000"))
        self.db = Path(self.folder.name) / "catalog.json"
        add_inspection(self.path, inspect_preview(self.path), self.db)
        self.record = load_catalog(self.db)[0]

    def test_unchanged_file(self):
        result = check_catalog_integrity(self.record)
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["changed_fields"], [])
        self.assertFalse(result["execution_performed"])

    def test_modified_file_does_not_retrust_it(self):
        self.path.write_bytes(b"modified")
        result = check_catalog_integrity(self.record)
        self.assertEqual(result["status"], "modified")
        self.assertIn("sha256", result["changed_fields"])
        self.assertEqual(load_catalog(self.db)[0], self.record)
        self.assertFalse(result["execution_performed"])

    def test_missing_file(self):
        self.path.unlink()
        self.assertEqual(check_catalog_integrity(self.record)["status"], "missing")

    def test_directory_replacement_is_unavailable(self):
        self.path.unlink()
        self.path.mkdir()
        self.assertEqual(check_catalog_integrity(self.record)["status"], "unavailable")

    def test_metadata_tampering_is_reported(self):
        record = {**self.record, "architecture": "x86_64"}
        result = check_catalog_integrity(record)
        self.assertEqual(result["status"], "modified")
        self.assertIn("architecture", result["changed_fields"])

    def test_invalid_catalog_path_rejected(self):
        with self.assertRaises(ValueError):
            check_catalog_integrity({"path": ""})


if __name__ == "__main__":
    unittest.main()
