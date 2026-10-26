import json
import os
import tempfile
from unittest import mock
from pathlib import Path
import unittest
from omni.windows_preview import inspect_preview, _self_test_entrypoint


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
            payload[128:132] = b"PE\0\0"
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

    def test_self_test_writes_success_report(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "result.json"
            with mock.patch.dict(os.environ, {"OMNI_SELF_TEST_REPORT": str(report)}):
                with mock.patch("omni.windows_preview.packaged_self_test", return_value=0):
                    self.assertEqual(_self_test_entrypoint("runtime"), 0)
            self.assertEqual(json.loads(report.read_text(encoding="utf-8")),
                             {"status": "passed", "kind": "runtime"})

    def test_gui_self_test_failure_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "result.json"
            with mock.patch.dict(os.environ, {"OMNI_SELF_TEST_REPORT": str(report)}):
                with mock.patch("omni.windows_preview.packaged_gui_self_test",
                                side_effect=RuntimeError("Tk initialization failed")):
                    self.assertEqual(_self_test_entrypoint("gui"), 1)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["kind"], "gui")
            self.assertEqual(result["error_type"], "RuntimeError")
            self.assertIn("Tk initialization failed", result["message"])

    def test_app_self_test_invokes_complete_desktop_startup(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "app-result.json"
            with mock.patch.dict(os.environ, {"OMNI_SELF_TEST_REPORT": str(report)}):
                with mock.patch("omni.windows_preview.main") as desktop:
                    self.assertEqual(_self_test_entrypoint("app"), 0)
            desktop.assert_called_once_with(smoke_test=True)
            self.assertEqual(json.loads(report.read_text(encoding="utf-8")),
                             {"status": "passed", "kind": "app"})

    def test_app_self_test_reports_desktop_startup_failure(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "app-failure.json"
            with mock.patch.dict(os.environ, {"OMNI_SELF_TEST_REPORT": str(report)}):
                with mock.patch("omni.windows_preview.main",
                                side_effect=RuntimeError("Desktop initialization failed")):
                    self.assertEqual(_self_test_entrypoint("app"), 1)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["kind"], "app")
            self.assertEqual(result["error_type"], "RuntimeError")
