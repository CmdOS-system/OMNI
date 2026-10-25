import unittest

from omni.runtime_choices import build_runtime_overview


class RuntimeChoicesTests(unittest.TestCase):
    def setUp(self):
        self.discovery = {"status": "WSL2_DETECTED",
                          "wsl2_distributions": ["Ubuntu", "Debian"]}

    def test_native_windows_preferred_for_exe(self):
        record = {"path": r"C:\Apps\demo.exe", "format": "PE",
                  "architecture": "x86_64", "sha256": "abc"}
        result = build_runtime_overview(
            record, self.discovery, "Ubuntu",
            host_system="Windows", host_arch="AMD64")
        self.assertEqual(result["preferred_runtime"], "windows-native")
        self.assertTrue(result["native_windows"]["launch_available"])
        self.assertFalse(result["linux_wsl2"]["launch_available"])
        self.assertFalse(result["execution_performed"])

    def test_elf_uses_selected_wsl2_distribution(self):
        record = {"path": r"C:\Apps\hello", "format": "ELF",
                  "architecture": "x86_64", "sha256": "abc"}
        result = build_runtime_overview(
            record, self.discovery, "Ubuntu",
            host_system="Windows", host_arch="AMD64")
        self.assertEqual(result["preferred_runtime"], "wsl2-elf")
        self.assertTrue(result["linux_wsl2"]["launch_available"])
        self.assertFalse(result["native_windows"]["launch_available"])
        self.assertFalse(result["sandboxed"])
        self.assertFalse(result["compatibility_certified"])

    def test_unselected_or_unavailable_distro_blocks(self):
        record = {"path": r"C:\Apps\hello", "format": "ELF",
                  "architecture": "x86_64", "sha256": "abc"}
        for distro, discovery in [("", self.discovery),
                                  ("Missing", self.discovery),
                                  ("Ubuntu", {})]:
            with self.subTest(distro=distro):
                result = build_runtime_overview(
                    record, discovery, distro,
                    host_system="Windows", host_arch="AMD64")
                self.assertIsNone(result["preferred_runtime"])
                self.assertFalse(result["linux_wsl2"]["launch_available"])

    def test_wrong_host_and_unknown_format_block(self):
        record = {"path": "/tmp/hello", "format": "ELF",
                  "architecture": "x86_64", "sha256": "abc"}
        result = build_runtime_overview(
            record, self.discovery, "Ubuntu",
            host_system="Linux", host_arch="x86_64")
        self.assertIsNone(result["preferred_runtime"])
        record["format"] = "UNKNOWN"
        self.assertIsNone(build_runtime_overview(
            record, self.discovery, "Ubuntu",
            host_system="Windows", host_arch="AMD64")["preferred_runtime"])

    def test_never_executes_or_claims_certification(self):
        record = {"path": r"C:\Apps\demo.exe", "format": "PE",
                  "architecture": "x86_64", "sha256": "abc"}
        result = build_runtime_overview(
            record, self.discovery, "Ubuntu",
            host_system="Windows", host_arch="AMD64")
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["compatibility_certified"])
        with self.assertRaises(ValueError):
            build_runtime_overview(None)
