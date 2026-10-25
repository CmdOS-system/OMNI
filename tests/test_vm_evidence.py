import tempfile
import unittest
from pathlib import Path
from vm.evidence import store, verify


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / "bundle"
        self.report = {"status": "BOOT_ATTEMPTED_UNATTESTED", "qemu_started": True}

    def test_valid_bundle_remains_unattested(self):
        store(self.report, self.folder)
        result = verify(self.folder)
        self.assertEqual(result["status"], "CONSISTENT_UNATTESTED")
        self.assertFalse(result["compatibility_certified"])

    def test_fake_report_rejected(self):
        with self.assertRaises(ValueError):
            store({"status": "BLOCKED", "qemu_started": False}, self.folder)

    def test_no_overwrite(self):
        store(self.report, self.folder)
        with self.assertRaises(FileExistsError):
            store(self.report, self.folder)

    def test_tampering_rejected(self):
        store(self.report, self.folder)
        (self.folder / "report.json").write_text("{}")
        self.assertEqual(verify(self.folder)["status"], "REJECTED")

    def test_serial_tampering_rejected(self):
        serial = Path(self.tmp.name) / "serial"
        serial.write_bytes(b"boot attempt log")
        store(self.report, self.folder, serial_log=serial)
        (self.folder / "serial.log").write_bytes(b"tampered")
        self.assertEqual(verify(self.folder)["status"], "REJECTED")

    def test_claim_is_overridden(self):
        self.report["guest_boot_verified"] = True
        store(self.report, self.folder)
        self.assertEqual(verify(self.folder)["status"], "CONSISTENT_UNATTESTED")


if __name__ == "__main__":
    unittest.main()
