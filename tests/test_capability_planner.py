import tempfile
import unittest
from pathlib import Path
from omni.planner import inspect_file, plan


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample"

    def write(self, value):
        self.path.write_bytes(value)
        return self.path

    def test_fake_mz_rejected(self):
        self.assertEqual(inspect_file(self.write(b"MZ" + bytes(128)))["format"], "UNKNOWN")

    def test_wasm_version(self):
        self.assertEqual(inspect_file(self.write(b"\0asm\x01\0\0\0"))["format"], "WASM")

    def test_invalid_wasm_version(self):
        self.assertEqual(inspect_file(self.write(b"\0asm\x02\0\0\0"))["format"], "UNKNOWN")

    def test_elf_architecture(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[6] = 1
        header[18:20] = (62).to_bytes(2, "little")
        result = plan(self.write(header), host_system="Linux", host_arch="x86_64", which=lambda _: None)
        self.assertEqual(result["input"]["architecture"], "x86_64")
        self.assertTrue(next(o for o in result["options"] if o["runtime"] == "linux-native")["eligible_for_preflight"])
        self.assertFalse(result["execution_performed"])

    def test_mismatched_native_architecture(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[6] = 1
        header[18:20] = (183).to_bytes(2, "little")
        result = plan(self.write(header), host_system="Linux", host_arch="x86_64", which=lambda _: None)
        native = next(o for o in result["options"] if o["runtime"] == "linux-native")
        self.assertFalse(native["eligible_for_preflight"])

    def test_unknown_never_authorized(self):
        result = plan(self.write(b"not executable"), host_system="Linux", which=lambda _: "/bin/true")
        self.assertEqual(result["options"], [])
        self.assertFalse(result["execution_authorized"])

    def test_symlink_rejected(self):
        real = Path(self.temp.name) / "real"
        real.write_bytes(b"data")
        self.path.symlink_to(real)
        with self.assertRaises(ValueError):
            inspect_file(self.path)


if __name__ == "__main__":
    unittest.main()
