import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from vm.overlay import lifecycle


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "trusted.raw"
        self.base.write_bytes(b"fixture-only")
        self.digest = hashlib.sha256(self.base.read_bytes()).hexdigest()

    def test_missing_tool_blocks(self):
        self.assertEqual(lifecycle(self.base, self.digest, qemu_img="")["status"], "BLOCKED")

    def test_wrong_hash_blocks(self):
        self.assertIn("base_hash_mismatch", lifecycle(self.base, "0" * 64)["blockers"])

    def test_symlink_blocks(self):
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.base)
        self.assertIn("base_not_regular", lifecycle(link, self.digest)["blockers"])

    def test_invalid_hash_blocks(self):
        self.assertIn("invalid_expected_sha256", lifecycle(self.base, "bad")["blockers"])

    def test_no_guest_claim(self):
        result = lifecycle(self.base, self.digest, qemu_img="")
        self.assertFalse(result["guest_booted"])
        self.assertFalse(result["isolation_verified"])
        self.assertEqual(result["compatibility_verdict"], "NOT_CERTIFIED")


if __name__ == "__main__":
    unittest.main()
