"""Tests for the explicit unified Windows/WSL2 launch coordinator."""
import unittest
from unittest.mock import Mock

from omni.launch_coordinator import launch_with_recommended_runtime


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.discovery = {"status": "WSL2_DETECTED",
                          "wsl2_distributions": ["Ubuntu"]}
        self.native = Mock(return_value=Mock(pid=101))
        self.wsl = Mock(return_value=Mock(pid=202))
        self.native_record = {
            "path": r"C:\Apps\demo.exe", "format": "PE",
            "architecture": "x86_64", "sha256": "abc"}
        self.linux_record = {
            "path": r"C:\Apps\demo", "format": "ELF",
            "architecture": "x86_64", "sha256": "def"}

    def launch(self, record, *, confirmed=True, distribution="Ubuntu"):
        return launch_with_recommended_runtime(
            record, self.discovery, distribution, confirmed=confirmed,
            host_system="Windows", host_arch="AMD64",
            native_launcher=self.native, wsl_launcher=self.wsl)

    def test_no_consent_never_invokes_any_adapter(self):
        with self.assertRaises(PermissionError):
            self.launch(self.native_record, confirmed=False)
        self.native.assert_not_called()
        self.wsl.assert_not_called()

    def test_native_exe_uses_only_windows_adapter(self):
        result = self.launch(self.native_record)
        self.assertEqual(result["runtime"], "windows-native")
        self.assertEqual(result["process"].pid, 101)
        self.native.assert_called_once_with(
            self.native_record, confirmed=True, host_system="Windows", host_arch="AMD64")
        self.wsl.assert_not_called()

    def test_elf_uses_only_selected_wsl2_adapter(self):
        result = self.launch(self.linux_record)
        self.assertEqual(result["runtime"], "wsl2-elf")
        self.assertEqual(result["process"].pid, 202)
        self.wsl.assert_called_once_with(
            self.linux_record, "Ubuntu", confirmed=True,
            host_system="Windows", host_arch="AMD64")
        self.native.assert_not_called()

    def test_missing_distribution_blocks_all_execution(self):
        with self.assertRaisesRegex(ValueError, "No available runtime"):
            self.launch(self.linux_record, distribution="Debian")
        self.native.assert_not_called()
        self.wsl.assert_not_called()

    def test_unsupported_format_blocks_all_execution(self):
        record = {**self.native_record, "format": "WASM"}
        with self.assertRaisesRegex(ValueError, "No available runtime"):
            self.launch(record)
        self.native.assert_not_called()
        self.wsl.assert_not_called()

    def test_failed_native_launch_does_not_fallback_to_wsl(self):
        self.native.side_effect = OSError("Launch failed")
        with self.assertRaisesRegex(OSError, "Launch failed"):
            self.launch(self.native_record)
        self.native.assert_called_once()
        self.wsl.assert_not_called()


if __name__ == "__main__":
    unittest.main()
