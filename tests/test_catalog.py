import tempfile
from pathlib import Path
import unittest
from omni.catalog import add_inspection, load_catalog, remove_inspection


class CatalogTests(unittest.TestCase):
    def test_add_update_remove(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            target = Path(td) / "example.exe"
            data = {"name": "example.exe", "format": "PE", "architecture": "x86_64", "sha256": "abc"}
            self.assertEqual(len(add_inspection(target, data, db)), 1)
            self.assertEqual(len(add_inspection(target, data, db)), 1)
            self.assertFalse(load_catalog(db)[0]["execution_authorized"])
            self.assertEqual(remove_inspection(target, db), [])

    def test_corrupt_catalog_fails(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            db.write_text('{"not":"a list"}')
            with self.assertRaises(ValueError):
                load_catalog(db)
