import unittest
from scripts.linux_userspace_probe import evaluate_guest_output


class GuestEvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.log = (b"Linux version 6.8.0\n"
                    b"OMNI_GUEST_USERSPACE_READY_V1 nonce=abc\n"
                    b"OMNI_GUEST_TASK_RESULT_V1 nonce=abc value=15\n")

    def test_valid_execution(self):
        self.assertEqual(evaluate_guest_output(self.log, "abc", 15, 0, False)["status"],
                         "GUEST_FUNCTIONAL_TASK_OBSERVED_UNATTESTED")

    def test_wrong_result_blocks(self):
        self.assertEqual(evaluate_guest_output(self.log, "abc", 16, 0, False)["status"], "BLOCKED")

    def test_wrong_nonce_blocks(self):
        self.assertEqual(evaluate_guest_output(self.log, "xyz", 15, 0, False)["status"], "BLOCKED")

    def test_kernel_panic_blocks(self):
        data = self.log + b"Kernel panic - not syncing: error\n"
        self.assertEqual(evaluate_guest_output(data, "abc", 15, 0, False)["status"], "BLOCKED")

    def test_nonzero_exit_blocks(self):
        self.assertEqual(evaluate_guest_output(self.log, "abc", 15, 1, False)["status"], "BLOCKED")

    def test_timeout_blocks(self):
        self.assertEqual(evaluate_guest_output(self.log, "abc", 15, None, True)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
