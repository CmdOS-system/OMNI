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

    def test_valid_pe_x64_header_is_identified(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.exe"
            payload = bytearray(256)
            payload[:2] = b"MZ"
            payload[60:64] = (128).to_bytes(4, "little")
            payload[128:132] = b"PE\\0\\0"
            payload[132:134] = (0x8664).to_bytes(2, "little")
            path.write_bytes(payload)
            result = inspect_preview(path)
            self.assertEqual(result["format"], "PE")
            self.assertEqual(result["architecture"], "x86_64")
            self.assertFalse(result["execution_authorized"])

    def test_truncated_pe_header_is_not_misidentified(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "truncated.exe"
            payload = bytearray(64)
            payload[:2] = b"MZ"
            payload[60:64] = (4096).to_bytes(4, "little")
            path.write_bytes(payload)
            result = inspect_preview(path)
            self.assertEqual(result["format"], "UNKNOWN")
            self.assertFalse(result["execution_performed"])
