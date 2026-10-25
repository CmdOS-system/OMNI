import unittest
from scripts.linux_userspace_probe import evaluate_guest_output


class FileProofGateTests(unittest.TestCase):
    def setUp(self):
        self.serial = (b"Linux version 6.8.0\n"
                       b"OMNI_GUEST_USERSPACE_READY_V1 nonce=abc\n"
                       b"OMNI_GUEST_TASK_RESULT_V1 nonce=abc value=8\n"
                       b"OMNI_GUEST_FILE_RESULT_V1 nonce=abc sha256=feed123\n")

    def test_file_hash_matches(self):
        r = evaluate_guest_output(self.serial, "abc", 8, 0, False, "feed123")
        self.assertTrue(r["file_task_observed"])
        self.assertNotEqual(r["status"], "BLOCKED")

    def test_file_hash_mismatch_fails(self):
        r = evaluate_guest_output(self.serial, "abc", 8, 0, False, "bad")
        self.assertFalse(r["file_task_observed"])
        self.assertEqual(r["status"], "BLOCKED")

    def test_missing_file_result_fails(self):
        r = evaluate_guest_output(self.serial.split(b"OMNI_GUEST_FILE_RESULT")[0],
                                  "abc", 8, 0, False, "feed123")
        self.assertEqual(r["status"], "BLOCKED")

    def test_file_hash_with_wrong_nonce_fails(self):
        data = self.serial.replace(b"nonce=abc sha256", b"nonce=xyz sha256")
        self.assertEqual(evaluate_guest_output(data, "abc", 8, 0, False, "feed123")["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
