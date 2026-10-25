import unittest
from scripts.linux_guest_probe import classify_console


class ConsoleClassificationTests(unittest.TestCase):
    def test_kernel_banner_is_not_userspace(self):
        result = classify_console(b"[ 0.00] Linux version 6.8.0 (builder)\\n")
        self.assertEqual(result["status"], "KERNEL_BANNER_OBSERVED_UNATTESTED")
        self.assertFalse(result["userspace_marker_observed"])

    def test_panic_is_explicitly_reported(self):
        result = classify_console(b"Linux version 6.8.0\\nKernel panic - not syncing: no init\\n")
        self.assertEqual(result["status"], "KERNEL_BANNER_WITH_PANIC_UNATTESTED")
        self.assertTrue(result["kernel_panic_observed"])

    def test_no_kernel_banner_blocks(self):
        self.assertEqual(classify_console(b"SeaBIOS"), {
            "kernel_banner_observed": False,
            "kernel_panic_observed": False,
            "userspace_marker_observed": False,
            "status": "BLOCKED",
        })


if __name__ == "__main__":
    unittest.main()
