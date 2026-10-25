import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from omni.windows_preview import inspect_preview
from omni.windows_runtime import assess_native_windows, launch_native_windows


def sample_pe(path):
    data = bytearray(128)
    data[:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    data[68:70] = (0x8664).to_bytes(2, "little")
    path.write_bytes(data)
    result = inspect_preview(path)
    result["path"] = str(path)
    return result


class NativeWindowsTests(unittest.TestCase):
    def test_native_plan_never_claims_sandbox(self):
        record = {"path": "C:/Program Files/test.exe", "format": "PE",
                  "architecture": "x86_64", "sha256": "abc"}
        plan = assess_native_windows(record, host_system="Windows", host_arch="AMD64")
        self.assertTrue(plan["launch_available"])
        self.assertFalse(plan["sandboxed"])
        self.assertFalse(plan["cross_os_compatibility"])

    def test_linux_and_elf_are_blocked(self):
        record = {"path": "/tmp/test.exe", "format": "ELF",
                  "architecture": "x86_64", "sha256": "abc"}
        plan = assess_native_windows(record, host_system="Linux", host_arch="x86_64")
        self.assertFalse(plan["launch_available"])
        with self.assertRaises(ValueError):
            launch_native_windows(record, confirmed=True, host_system="Linux",
                                  host_arch="x86_64")

    def test_requires_explicit_consent(self):
        with self.assertRaises(PermissionError):
            launch_native_windows({})

    def test_tampering_blocks_launch(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "demo.exe"
            record = sample_pe(path)
            path.write_bytes(b"tampered")
            with patch("omni.windows_runtime.subprocess.Popen") as popen:
                with self.assertRaises(ValueError):
                    launch_native_windows(record, confirmed=True,
                                          host_system="Windows", host_arch="AMD64")
                popen.assert_not_called()

    def test_mocked_native_launch_uses_no_shell(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "demo.exe"
            record = sample_pe(path)
            with patch("omni.windows_runtime.subprocess.Popen") as popen:
                launch_native_windows(record, confirmed=True,
                                      host_system="Windows", host_arch="AMD64")
                args, kwargs = popen.call_args
                self.assertEqual(args[0], [str(path)])
                self.assertFalse(kwargs["shell"])
                self.assertEqual(kwargs["cwd"], str(path.parent))

    def test_dll_cannot_launch(self):
        record = {"path": "C:/demo.dll", "format": "PE",
                  "architecture": "x86_64", "sha256": "abc"}
        self.assertFalse(assess_native_windows(
            record, host_system="Windows", host_arch="AMD64")["launch_available"])
