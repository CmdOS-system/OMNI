import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from vm.evidence import store
from vm.assessment import assess_bundle
from vm.guest_marker import PREFIX


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bundle = Path(self.tmp.name) / "bundle"
        self.nonce = "a" * 32
        self.report = {"status": "BOOT_ATTEMPTED_UNATTESTED", "qemu_started": True}

    def test_matching_serial_still_not_certified(self):
        log = Path(self.tmp.name) / "serial"
        log.write_text(PREFIX + json.dumps({"nonce": self.nonce, "kernel": "Linux"}) + "\n")
        store(self.report, self.bundle, serial_log=log)
        result = assess_bundle(self.bundle, self.nonce)
        self.assertEqual(result["status"], "SERIAL_MARKER_CORRELATED_UNATTESTED")
        self.assertFalse(result["guest_boot_verified"])

    def test_no_serial_blocks(self):
        store(self.report, self.bundle)
        self.assertIn("serial_evidence_absent", assess_bundle(self.bundle, self.nonce)["errors"])

    def test_wrong_nonce_blocks(self):
        log = Path(self.tmp.name) / "serial"
        log.write_text(PREFIX + json.dumps({"nonce": "b" * 32, "kernel": "Linux"}) + "\n")
        store(self.report, self.bundle, serial_log=log)
        self.assertIn("nonce_mismatch", assess_bundle(self.bundle, self.nonce)["errors"])

    def test_modified_log_blocks(self):
        log = Path(self.tmp.name) / "serial"
        log.write_text("fixture")
        store(self.report, self.bundle, serial_log=log)
        (self.bundle / "serial.log").write_text("modified")
        self.assertEqual(assess_bundle(self.bundle, self.nonce)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
