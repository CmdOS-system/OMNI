import hashlib
import tempfile
import unittest
from pathlib import Path
from proof.verify import verify_dossier


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "original.bin"
        self.path.write_bytes(b"original third-party bytes")
        self.dossier = {
            "run_id": "run-1",
            "source_path": str(self.path),
            "source_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
            "process": {"pid": 42, "exit_code": 0},
        }

    def test_consistency_does_not_certify(self):
        result = verify_dossier(self.dossier)
        self.assertEqual(result["status"], "CONSISTENT_UNATTESTED")
        self.assertFalse(result["compatibility_certified"])

    def test_modified_original_rejected(self):
        self.path.write_bytes(b"tampered")
        self.assertEqual(verify_dossier(self.dossier)["status"], "REJECTED")

    def test_forged_pass_rejected(self):
        self.dossier["verdict"] = "PASS"
        self.assertEqual(verify_dossier(self.dossier)["status"], "REJECTED")

    def test_missing_process_rejected(self):
        del self.dossier["process"]
        self.assertEqual(verify_dossier(self.dossier)["status"], "REJECTED")

    def test_invalid_pid_rejected(self):
        self.dossier["process"]["pid"] = True
        self.assertEqual(verify_dossier(self.dossier)["status"], "REJECTED")

    def test_symlink_rejected(self):
        link = Path(self.temp.name) / "link.bin"
        link.symlink_to(self.path)
        self.dossier["source_path"] = str(link)
        self.assertEqual(verify_dossier(self.dossier)["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
