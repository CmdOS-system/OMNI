import hashlib
import tempfile
import unittest
from pathlib import Path
from vm.prerequisites import assess


class VMPrerequisitesTests(unittest.TestCase):
    def test_missing_everything_blocks(self):
        result = assess(host="Linux", executable="", kvm=False)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["isolation_verified"])

    def test_matching_image_still_not_certified(self):
        with tempfile.TemporaryDirectory() as folder:
            disk = Path(folder) / "guest.img"
            qemu = Path(folder) / "qemu-system-x86_64"
            disk.write_bytes(b"fixture, not real guest")
            qemu.write_bytes(b"fixture, not real qemu")
            digest = hashlib.sha256(disk.read_bytes()).hexdigest()
            result = assess(disk, digest, host="Linux", executable=str(qemu), kvm=True)
            self.assertEqual(result["status"], "PREREQUISITES_ONLY")
            self.assertEqual(result["compatibility_verdict"], "NOT_CERTIFIED")
            self.assertFalse(result["guest_attested"])

    def test_hash_mismatch_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            disk = Path(folder) / "guest.img"
            disk.write_bytes(b"fixture")
            result = assess(disk, "0" * 64, host="Linux", executable=__file__, kvm=True)
            self.assertIn("guest_image_hash_mismatch", result["blockers"])

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            disk = Path(folder) / "guest.img"
            link = Path(folder) / "link.img"
            disk.write_bytes(b"fixture")
            link.symlink_to(disk)
            result = assess(link, hashlib.sha256(disk.read_bytes()).hexdigest(), host="Linux", executable=__file__, kvm=True)
            self.assertIn("guest_image_not_regular_file", result["blockers"])


if __name__ == "__main__":
    unittest.main()
