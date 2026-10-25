import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from omni.windows_preview import inspect_preview
from omni.wsl2_runtime import assess_elf_wsl_launch, launch_elf_wsl


def elf_record(path):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    path.write_bytes(header)
    result = inspect_preview(path)
    result["path"] = str(path)
    return result


class WSL2RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.discovered = {"status": "WSL2_DETECTED", "wsl2_distributions": ["Ubuntu"]}

    def test_preflight_windows_local_drive_and_distro(self):
        record = {"path": r"C:\Users\me\hello", "format": "ELF",
                  "architecture": "x86_64", "sha256": "hash"}
        plan = assess_elf_wsl_launch(record, self.discovered, "Ubuntu",
                                     host_system="Windows", host_arch="AMD64")
        self.assertTrue(plan["launch_available"])
        self.assertFalse(plan["sandboxed"])
        self.assertFalse(plan["guest_process_contained"])
        self.assertFalse(plan["compatibility_certified"])
        self.assertFalse(assess_elf_wsl_launch(
            record, self.discovered, "Debian", host_system="Windows",
            host_arch="AMD64")["launch_available"])
        record["path"] = r"\\server\share\hello"
        self.assertFalse(assess_elf_wsl_launch(
            record, self.discovered, "Ubuntu", host_system="Windows",
            host_arch="AMD64")["launch_available"])

    def test_no_consent_never_calls_subprocess(self):
        runner, popen = Mock(), Mock()
        with self.assertRaises(PermissionError):
            launch_elf_wsl({}, "Ubuntu", runner=runner, popen=popen)
        runner.assert_not_called()
        popen.assert_not_called()

    def test_non_windows_never_calls_subprocess(self):
        runner, popen = Mock(), Mock()
        with self.assertRaises(ValueError):
            launch_elf_wsl({}, "Ubuntu", confirmed=True, host_system="Linux",
                           runner=runner, popen=popen)
        runner.assert_not_called()
        popen.assert_not_called()

    def test_argv_launch_without_shell(self):
        # On Linux CI use a real temporary file but mock Windows-path checks.
        # The launch module's PureWindowsPath preflight is covered separately.
        with tempfile.TemporaryDirectory() as td:
            record = elf_record(Path(td) / "hello")
            record["path"] = r"C:\Temp\hello"
            runner = Mock(side_effect=[
                SimpleNamespace(returncode=0, stdout="* Ubuntu    Running    2\n".encode("utf-16-le")),
                SimpleNamespace(returncode=0, stdout=b"/mnt/c/Temp/hello\n"),
            ])
            popen = Mock(return_value=SimpleNamespace(pid=123))
            from unittest.mock import patch
            with patch("omni.wsl2_runtime.inspect_preview", return_value=record), \
                 patch("omni.wsl2_runtime._validate_elf_header"):
                process = launch_elf_wsl(
                    record, "Ubuntu", confirmed=True, host_system="Windows",
                    host_arch="AMD64", which=lambda _: "wsl.exe",
                    runner=runner, popen=popen)
            self.assertEqual(process.pid, 123)
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(runner.call_args_list[1].args[0],
                ["wsl.exe", "--distribution", "Ubuntu", "--exec",
                 "wslpath", "-a", "-u", r"C:\Temp\hello"])
            args, kwargs = popen.call_args
            self.assertEqual(args[0], ["wsl.exe", "--distribution", "Ubuntu",
                                        "--exec", "/mnt/c/Temp/hello"])
            self.assertFalse(kwargs["shell"])

    def test_changed_file_blocks_before_path_translation(self):
        with tempfile.TemporaryDirectory() as td:
            record = elf_record(Path(td) / "hello")
            record["path"] = r"C:\Temp\hello"
            runner = Mock(return_value=SimpleNamespace(
                returncode=0, stdout="* Ubuntu    Running    2\n".encode("utf-16-le")))
            popen = Mock()
            from unittest.mock import patch
            with patch("omni.wsl2_runtime.inspect_preview",
                       return_value={"sha256": "different", "format": "ELF",
                                     "architecture": "x86_64"}):
                with self.assertRaisesRegex(ValueError, "File changed"):
                    launch_elf_wsl(record, "Ubuntu", confirmed=True,
                        host_system="Windows", host_arch="AMD64",
                        which=lambda _: "wsl.exe", runner=runner, popen=popen)
            self.assertEqual(runner.call_count, 1)
            popen.assert_not_called()

    def test_path_conversion_failure_blocks(self):
        record = {"path": r"C:\Temp\hello", "format": "ELF",
                  "architecture": "x86_64", "sha256": "abc"}
        runner = Mock(side_effect=[
            SimpleNamespace(returncode=0, stdout="* Ubuntu    Running    2\n".encode("utf-16-le")),
            SimpleNamespace(returncode=1, stdout=b"", stderr=b"error")])
        popen = Mock()
        from unittest.mock import patch
        with patch("omni.wsl2_runtime.inspect_preview", return_value=record), \
             patch("omni.wsl2_runtime._validate_elf_header"):
            with self.assertRaisesRegex(ValueError, "translate"):
                launch_elf_wsl(record, "Ubuntu", confirmed=True,
                    host_system="Windows", host_arch="AMD64",
                    which=lambda _: "wsl.exe", runner=runner, popen=popen)
        popen.assert_not_called()

    def test_elf_header_rejects_non_executable(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "library.so"
            record = elf_record(path)
            data = bytearray(path.read_bytes())
            data[16:18] = (1).to_bytes(2, "little")
            path.write_bytes(data)
            from omni.wsl2_runtime import _validate_elf_header
            with self.assertRaises(ValueError):
                _validate_elf_header(path, "x86_64")


if __name__ == "__main__":
    unittest.main()
