import tempfile
import json
from unittest import mock
from pathlib import Path
import unittest
from omni.catalog import add_inspection, backup_catalog, load_catalog, remove_inspection


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
                db.write_text(json.dumps([invalid]), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    load_catalog(db)
            db.write_text(json.dumps([valid]), encoding="utf-8")
            self.assertEqual(load_catalog(db), [valid])

    def test_backup_preserves_corrupt_json_without_overwriting(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            db.write_bytes(b"{not valid json")
            first = backup_catalog(db)
            self.assertEqual(first.read_bytes(), db.read_bytes())
            db.write_bytes(b"changed content")
            second = backup_catalog(db)
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_bytes(), b"{not valid json")
            self.assertEqual(second.read_bytes(), b"changed content")
            self.assertEqual(db.read_bytes(), b"changed content")

    def test_backup_collision_does_not_delete_existing_file(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            db.write_bytes(b"original")
            occupied = db.with_name("catalog.json.backup-0001")
            occupied.write_bytes(b"keep this")
            created = backup_catalog(db)
            self.assertEqual(created.name, "catalog.json.backup-0002")
            self.assertEqual(occupied.read_bytes(), b"keep this")
            self.assertEqual(created.read_bytes(), b"original")

    def test_backup_fsync_failure_removes_only_new_copy(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            db.write_bytes(b"important data")
            existing = db.with_name("catalog.json.backup-0001")
            existing.write_bytes(b"preserve")
            with mock.patch("omni.catalog.os.fsync", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    backup_catalog(db)
            self.assertEqual(db.read_bytes(), b"important data")
            self.assertEqual(existing.read_bytes(), b"preserve")
            self.assertFalse(db.with_name("catalog.json.backup-0002").exists())

    def test_corrupt_catalog_fails(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "catalog.json"
            db.write_text('{"not":"a list"}')
            with self.assertRaises(ValueError):
                load_catalog(db)
