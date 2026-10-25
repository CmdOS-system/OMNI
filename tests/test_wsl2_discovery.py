import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from omni.wsl2_discovery import (
    assess_elf_wsl, decode_wsl_output, discover_wsl2, parse_wsl_list,
)


class WSL2DiscoveryTests(unittest.TestCase):
    def test_utf16_and_utf8_wsl_list(self):
        sample = "  NAME                   STATE           VERSION\r\n* Ubuntu 22.04           Running         2\r\n  Debian                 Stopped         1\r\n"
        expected = [
            {"name": "Ubuntu 22.04", "state": "Running", "version": 2, "default": True},
            {"name": "Debian", "state": "Stopped", "version": 1, "default": False},
        ]
        self.assertEqual(parse_wsl_list(sample.encode("utf-16-le")), expected)
        self.assertEqual(parse_wsl_list(sample.encode("utf-8")), expected)
        self.assertEqual(decode_wsl_output(sample.encode("utf-16")), sample)

    def test_discovery_readonly_fixed_arguments(self):
        runner = Mock(return_value=SimpleNamespace(
            returncode=0, stdout="* Ubuntu    Running    2\n  Debian    Stopped    1".encode("utf-16-le"),
            stderr=b""))
        result = discover_wsl2(host_system="Windows", which=lambda _: r"C:\Windows\System32\wsl.exe",
                               runner=runner)
        self.assertEqual(result["status"], "WSL2_DETECTED")
        self.assertEqual(result["wsl2_distributions"], ["Ubuntu"])
        args, kwargs = runner.call_args
        self.assertEqual(args[0], [r"C:\Windows\System32\wsl.exe", "--list", "--verbose"])
        self.assertEqual(kwargs["timeout"], 6)
        self.assertFalse(kwargs["check"])
        self.assertNotIn("shell", kwargs)
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["execution_authorized"])

    def test_no_windows_no_subprocess(self):
        runner = Mock()
        result = discover_wsl2(host_system="Linux", runner=runner)
        self.assertEqual(result["status"], "NOT_WINDOWS")
        runner.assert_not_called()

    def test_missing_wsl(self):
        result = discover_wsl2(host_system="Windows", which=lambda _: None)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertFalse(result["wsl_available"])

    def test_wsl1_only_not_eligible(self):
        runner = Mock(return_value=SimpleNamespace(
            returncode=0, stdout=b"  Debian    Stopped    1\n", stderr=b""))
        result = discover_wsl2(host_system="Windows", which=lambda _: "wsl.exe", runner=runner)
        self.assertEqual(result["status"], "NO_WSL2_DISTRIBUTION")
        plan = assess_elf_wsl({"format": "ELF", "architecture": "x86_64", "sha256": "abc"},
                              result, host_arch="AMD64")
        self.assertFalse(plan["preflight_candidate"])
        self.assertFalse(plan["launch_available"])

    def test_timeout_and_failure_are_fail_closed(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired(["wsl.exe"], 6))
        result = discover_wsl2(host_system="Windows", which=lambda _: "wsl.exe", runner=runner)
        self.assertEqual(result["status"], "TIMED_OUT")
        runner.side_effect = None
        runner.return_value = SimpleNamespace(returncode=1, stdout=b"", stderr=b"failed")
        result = discover_wsl2(host_system="Windows", which=lambda _: "wsl.exe", runner=runner)
        self.assertEqual(result["status"], "WSL_LIST_FAILED")
        self.assertFalse(result["execution_authorized"])

    def test_elf_candidate_is_not_launch_authorization(self):
        discovery = {"status": "WSL2_DETECTED", "wsl2_distributions": ["Ubuntu"]}
        record = {"format": "ELF", "architecture": "x86_64", "sha256": "abc"}
        plan = assess_elf_wsl(record, discovery, host_arch="AMD64")
        self.assertTrue(plan["preflight_candidate"])
        self.assertFalse(plan["launch_available"])
        self.assertFalse(plan["execution_authorized"])
        self.assertFalse(plan["sandboxed"])
        self.assertEqual(plan["reasons"], ["wsl2_execution_adapter_not_implemented"])
        record["architecture"] = "aarch64"
        self.assertFalse(assess_elf_wsl(record, discovery, host_arch="AMD64")["preflight_candidate"])


if __name__ == "__main__":
    unittest.main()
