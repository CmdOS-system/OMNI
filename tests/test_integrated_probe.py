import unittest
from unittest.mock import patch
from omni.integrated_probe import probe_integrated


class IntegratedProbeTests(unittest.TestCase):
    @patch("omni.integrated_probe.shutil.which", return_value=None)
    def test_unavailable(self, _):
        result = probe_integrated()
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["status"], "UNAVAILABLE")

    @patch("omni.integrated_probe.shutil.which", return_value="/usr/bin/python3")
    @patch("omni.integrated_probe.subprocess.run")
    def test_two_boundaries(self, run, _):
        run.return_value.returncode = 0
        run.return_value.stdout = "PRIVATE_HIDDEN=True\nNETNS=net:[1234]\nNETWORK_ERRNO=101\n"
        run.return_value.stderr = ""
        result = probe_integrated()
        self.assertEqual(result["status"], "TWO_BOUNDARIES_OBSERVED")
        self.assertFalse(result["resource_limits_verified"])
        self.assertFalse(result["execution_authorized"])

    @patch("omni.integrated_probe.shutil.which", return_value="/usr/bin/python3")
    @patch("omni.integrated_probe.subprocess.run")
    def test_network_missing_blocks(self, run, _):
        run.return_value.returncode = 0
        run.return_value.stdout = "PRIVATE_HIDDEN=True\nNETWORK_ERRNO=110\n"
        run.return_value.stderr = ""
        self.assertEqual(probe_integrated()["status"], "BLOCKED")
