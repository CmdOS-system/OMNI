import json
import tempfile
import unittest
from pathlib import Path
from vm.guest_marker import inspect_serial, PREFIX


class MarkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "serial.log"
        self.nonce = "a" * 32

    def test_matching_marker_not_attestation(self):
        self.log.write_text(PREFIX + json.dumps({"nonce": self.nonce, "kernel": "Linux"}) + "\n")
        result = inspect_serial(self.log, self.nonce)
        self.assertEqual(result["status"], "GUEST_MARKER_OBSERVED_UNTRUSTED")
        self.assertFalse(result["guest_boot_verified"])

    def test_nonce_mismatch(self):
        self.log.write_text(PREFIX + json.dumps({"nonce": "b" * 32, "kernel": "Linux"}) + "\n")
        self.assertIn("nonce_mismatch", inspect_serial(self.log, self.nonce)["errors"])

    def test_duplicate_marker(self):
        line = PREFIX + json.dumps({"nonce": self.nonce, "kernel": "Linux"}) + "\n"
        self.log.write_text(line + line)
        self.assertIn("marker_count_not_one", inspect_serial(self.log, self.nonce)["errors"])

    def test_missing_log(self):
        self.assertIn("serial_missing_or_unsafe", inspect_serial(self.log, self.nonce)["errors"])

    def test_symlink_rejected(self):
        target = Path(self.tmp.name) / "target"
        target.write_text("log")
        self.log.symlink_to(target)
        self.assertIn("serial_missing_or_unsafe", inspect_serial(self.log, self.nonce)["errors"])

    def test_invalid_nonce(self):
        self.assertIn("invalid_expected_nonce", inspect_serial(self.log, "abc")["errors"])


if __name__ == "__main__":
    unittest.main()
