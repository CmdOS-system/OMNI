import unittest
from scripts.linux_userspace_probe import marker_seen


class MarkerTests(unittest.TestCase):
    def test_exact_marker(self):
        self.assertTrue(marker_seen(b"boot\nOMNI_GUEST_USERSPACE_READY_V1 nonce=abc123\n", "abc123"))

    def test_wrong_nonce(self):
        self.assertFalse(marker_seen(b"OMNI_GUEST_USERSPACE_READY_V1 nonce=wrong\n", "abc123"))

    def test_embedded_marker_rejected(self):
        self.assertFalse(marker_seen(b"prefix OMNI_GUEST_USERSPACE_READY_V1 nonce=abc123\n", "abc123"))


if __name__ == "__main__":
    unittest.main()
