import tempfile
from pathlib import Path
import unittest
from omni.windows_preview import inspect_preview


class WindowsPreviewTests(unittest.TestCase):
    def test_wasm_readonly(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "demo.wasm"
            path.write_bytes(b"\x00asm\x01\x00\x00\x00")
            result = inspect_preview(path)
            self.assertEqual(result["format"], "WASM")
            self.assertFalse(result["execution_performed"])

    def test_unknown_never_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.exe"
            path.write_bytes(b"not a real executable")
            result = inspect_preview(path)
            self.assertEqual(result["format"], "UNKNOWN")
            self.assertFalse(result["execution_authorized"])

    def test_directory_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                inspect_preview(td)
