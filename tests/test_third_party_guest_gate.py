import unittest
from scripts.third_party_guest_probe import assess_third_party


class ThirdPartyGuestGateTests(unittest.TestCase):
    def setUp(self):
        self.serial = (b"Linux version 6.8.0\n"
                       b"OMNI_THIRD_PARTY_BEGIN_V1 nonce=abc\n"
                       b"Hello, world!\n"
                       b"OMNI_THIRD_PARTY_EXIT_V1 nonce=abc code=0\n")

    def check(self, data=None, nonce="abc", rc=0, timed_out=False):
        return assess_third_party(self.serial if data is None else data, nonce, rc, timed_out)["status"]

    def test_success(self):
        self.assertEqual(self.check(), "THIRD_PARTY_GNU_HELLO_EXECUTED_UNATTESTED")

    def test_wrong_nonce(self):
        self.assertEqual(self.check(nonce="xyz"), "BLOCKED")

    def test_missing_output(self):
        self.assertEqual(self.check(data=self.serial.replace(b"Hello, world!\n", b"")), "BLOCKED")

    def test_wrong_exit(self):
        self.assertEqual(self.check(data=self.serial.replace(b"code=0", b"code=127")), "BLOCKED")

    def test_kernel_panic(self):
        self.assertEqual(self.check(data=self.serial + b"Kernel panic - not syncing\n"), "BLOCKED")

    def test_qemu_failure(self):
        self.assertEqual(self.check(rc=1), "BLOCKED")

    def test_timeout(self):
        self.assertEqual(self.check(timed_out=True), "BLOCKED")


if __name__ == "__main__":
    unittest.main()
