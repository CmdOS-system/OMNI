"""Exercise Windows library badges with real files and isolated failures."""
import tempfile
from pathlib import Path
import unittest

from omni.catalog import add_inspection, load_catalog
from omni.library_status import format_catalog_row, scan_catalog_statuses
from omni.windows_preview import inspect_preview


class LibraryStatusTests(unittest.TestCase):
    def test_real_file_statuses_and_unchanged_catalog(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            files = [base / "same.wasm", base / "changed.wasm", base / "gone.wasm"]
            db = base / "catalog.json"
            for path in files:
                path.write_bytes(b"\x00asm\x01\x00\x00\x00")
                add_inspection(path, inspect_preview(path), db)
            before = load_catalog(db)
            files[1].write_bytes(b"changed")
            files[2].unlink()
            statuses = scan_catalog_statuses(before)
            self.assertEqual(statuses[str(files[0])], "unchanged")
            self.assertEqual(statuses[str(files[1])], "modified")
            self.assertEqual(statuses[str(files[2])], "missing")
            self.assertEqual(load_catalog(db), before)

    def test_one_failure_does_not_abort_scan(self):
        records = [{"path": "bad"}, {"path": "good"}, {"path": "unexpected"}]

        def checker(record):
            if record["path"] == "bad":
                raise RuntimeError("disk failure")
            return {"status": "unchanged" if record["path"] == "good" else "mystery"}

        self.assertEqual(scan_catalog_statuses(records, checker), {
            "bad": "unavailable", "good": "unchanged", "unexpected": "unavailable"})

    def test_row_labels_do_not_claim_safety(self):
        record = {"name": "sample.exe", "format": "PE", "architecture": "x86_64"}
        self.assertIn("Comprobando", format_catalog_row(record))
        self.assertIn("Modificado", format_catalog_row(record, "modified"))
        self.assertNotIn("Seguro", format_catalog_row(record, "unchanged"))


if __name__ == "__main__":
    unittest.main()
