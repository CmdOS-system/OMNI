import hashlib
import tempfile
import unittest
from pathlib import Path
from vm.boot import attempt, command


class BootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.overlay = Path(self.tmp.name) / "disk.qcow2"
        self.overlay.write_bytes(b"fixture-not-real-qcow2")
        self.digest = hashlib.sha256(self.overlay.read_bytes()).hexdigest()

    def test_opt_in_required(self):
        self.assertIn("explicit_opt_in_required", attempt(self.overlay, self.digest)["blockers"])

    def test_missing_qemu_blocks(self):
        self.assertIn("qemu_missing", attempt(self.overlay, self.digest, allow_boot=True, qemu="")["blockers"])

    def test_bad_hash_blocks(self):
        self.assertIn("overlay_untrusted_or_modified", attempt(self.overlay, "0" * 64, allow_boot=True)["blockers"])

    def test_no_network_or_host_sharing(self):
        args = command("/usr/bin/qemu", "/tmp/overlay", "/tmp/serial")
        self.assertEqual(args[args.index("-nic") + 1], "none")
        self.assertNotIn("-virtfs", args)
        self.assertNotIn("-netdev", args)
        self.assertNotIn("-usb", args)

    def test_limits(self):
        with self.assertRaises(ValueError):
            command("qemu", "disk", "log", memory_mib=65536)

    def test_fixture_process_is_not_guest_proof(self):
        fake = Path(self.tmp.name) / "fake-qemu"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o700)
        report = attempt(self.overlay, self.digest, allow_boot=True, qemu=str(fake), timeout=2)
        self.assertEqual(report["status"], "BOOT_ATTEMPTED_UNATTESTED")
        self.assertFalse(report["guest_boot_verified"])
        self.assertEqual(report["compatibility_verdict"], "NOT_CERTIFIED")


if __name__ == "__main__":
    unittest.main()
