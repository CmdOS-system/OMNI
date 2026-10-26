"""Actual Windows native launch smoke test, not a GUI or sandbox certification."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from omni.process_manager import NativeProcessManager
from omni.windows_preview import inspect_preview, packaged_self_test
from omni.windows_runtime import assess_native_windows, launch_native_windows


@unittest.skipUnless(sys.platform == "win32", "Requires real Windows host")
class WindowsNativeSmokeTests(unittest.TestCase):
    def setUp(self):
        self.whoami = Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe"
        self.assertTrue(self.whoami.is_file(), "Windows whoami.exe is required")

    def test_real_windows_process_launch_and_exit_tracking(self):
        record = inspect_preview(self.whoami)
        record["path"] = str(self.whoami)
        self.assertEqual(record["format"], "PE")
        self.assertTrue(assess_native_windows(record)["launch_available"])
        with self.assertRaises(PermissionError):
            launch_native_windows(record)
        process = launch_native_windows(record, confirmed=True)
        manager = NativeProcessManager()
        manager.register("whoami.exe", process)
        try:
            self.assertEqual(process.wait(timeout=15), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        row = manager.snapshot()[0]
        self.assertEqual(row["status"], "exited")
        self.assertEqual(row["exit_code"], 0)
        self.assertEqual(row["pid"], process.pid)

    def test_changed_real_exe_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / "whoami.exe"
            shutil.copyfile(self.whoami, copy)
            record = inspect_preview(copy)
            record["path"] = str(copy)
            copy.write_bytes(b"changed after inspection")
            with self.assertRaisesRegex(ValueError, "changed"):
                launch_native_windows(record, confirmed=True)

    def test_runtime_self_test_on_real_windows_python(self):
        """The same read-only self-test also runs before packaging."""
        self.assertEqual(packaged_self_test(), 0)
