import unittest
from unittest.mock import patch
from omni.bwrap_probe import probe_bubblewrap


class BubblewrapProbeTests(unittest.TestCase):
    @patch("omni.bwrap_probe.shutil.which", return_value=None)
    def test_missing_binary_fails_closed(self, _):
        self.assertEqual(probe_bubblewrap()["status"], "UNAVAILABLE")

    @patch("omni.bwrap_probe.shutil.which", return_value="/usr/bin/bwrap")
    @patch("omni.bwrap_probe.subprocess.run")
    def test_positive_boundary_still_not_authorized(self, run, _):
        run.return_value.returncode = 0
        run.return_value.stdout = "OMNI_PRIVATE_HIDDEN\n"
        run.return_value.stderr = ""
        result = probe_bubblewrap()
        self.assertEqual(result["status"], "BOUNDARY_OBSERVED")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["network_denial_verified"])

    @patch("omni.bwrap_probe.shutil.which", return_value="/usr/bin/bwrap")
    @patch("omni.bwrap_probe.subprocess.run")
    def test_visible_private_path_blocks(self, run, _):
        run.return_value.returncode = 0
        run.return_value.stdout = "OMNI_PRIVATE_VISIBLE\n"
        run.return_value.stderr = ""
        self.assertEqual(probe_bubblewrap()["status"], "BLOCKED")
