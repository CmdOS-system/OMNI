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

    def test_incomplete_entries_fail_before_gui_rendering(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            valid = {"path": "C:/apps/demo.exe", "name": "demo.exe",
                     "format": "PE", "architecture": "x86_64", "sha256": "abc"}
            for field in valid:
                invalid = dict(valid)
                invalid.pop(field)
                db.write_text(__import__("json").dumps([invalid]), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    load_catalog(db)
            db.write_text(__import__("json").dumps([valid]), encoding="utf-8")
            self.assertEqual(load_catalog(db), [valid])

    def test_corrupt_catalog_fails(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            db.write_text('{"not":"a list"}')
            with self.assertRaises(ValueError):
                load_catalog(db)
