import hashlib
import tempfile
import unittest
from pathlib import Path
from vm.capture import capture
from vm.evidence import verify


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.disk = Path(self.tmp.name) / "disk.qcow2"
        self.disk.write_bytes(b"fixture-not-real-qcow2")
        self.digest = hashlib.sha256(self.disk.read_bytes()).hexdigest()
        self.destination = Path(self.tmp.name) / "evidence"

    def test_opt_in(self):
        self.assertIn("explicit_opt_in_required", capture(self.disk, self.digest, self.destination)["blockers"])

    def test_hash_mismatch(self):
        self.assertIn("overlay_hash_mismatch", capture(self.disk, "0" * 64, self.destination, allow_boot=True)["blockers"])

    def test_missing_binary(self):
        self.assertIn("qemu_missing", capture(self.disk, self.digest, self.destination, allow_boot=True, qemu="")["blockers"])

    def test_capture_fake_process_does_not_certify(self):
        fake = Path(self.tmp.name) / "fake-qemu"
        fake.write_text("#!/bin/sh\necho 'fixture only' >&2\nexit 0\n")
        fake.chmod(0o700)
        result = capture(self.disk, self.digest, self.destination, allow_boot=True, qemu=str(fake), timeout=2)
        self.assertEqual(result["status"], "BOOT_ATTEMPTED_UNATTESTED")
        self.assertEqual(verify(self.destination)["status"], "CONSISTENT_UNATTESTED")
        self.assertFalse(result["guest_boot_verified"])

    def test_no_overwrite(self):
        self.destination.mkdir()
        result = capture(self.disk, self.digest, self.destination, allow_boot=True, qemu=__file__)
        self.assertIn("evidence_destination_invalid", result["blockers"])


if __name__ == "__main__":
    unittest.main()
