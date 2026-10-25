import unittest
from scripts.native_guest_elf_probe import assess_native_guest


class NativeELFGateTests(unittest.TestCase):
    def setUp(self):
        self.serial = (b"Linux version 6.8.0\n"
                       b"OMNI_GUEST_NATIVE_PROGRAM_V1 value=42\n"
                       b"OMNI_NATIVE_EXIT_V1 nonce=abc code=0\n")

    def check(self, data=None, nonce="abc", value=42, rc=0, timeout=False):
        return assess_native_guest(self.serial if data is None else data,
                                   nonce, value, rc, timeout)["status"]

    def test_success(self):
        self.assertEqual(self.check(), "NATIVE_ELF_GUEST_EXECUTED_UNATTESTED")

    def test_wrong_result(self):
        self.assertEqual(self.check(value=41), "BLOCKED")

    def test_wrong_nonce(self):
        self.assertEqual(self.check(nonce="xyz"), "BLOCKED")

    def test_panic(self):
        self.assertEqual(self.check(data=self.serial + b"Kernel panic - not syncing\n"), "BLOCKED")

    def test_bad_exit(self):
        self.assertEqual(self.check(rc=1), "BLOCKED")

    def test_timeout(self):
        self.assertEqual(self.check(timeout=True), "BLOCKED")

    def test_missing_program_output(self):
        self.assertEqual(self.check(data=b"Linux version 6.8.0\nOMNI_NATIVE_EXIT_V1 nonce=abc code=0\n"), "BLOCKED")


if __name__ == "__main__":
    unittest.main()
