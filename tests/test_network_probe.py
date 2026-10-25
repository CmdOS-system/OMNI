import unittest
from unittest.mock import patch
from omni.network_probe import probe_network


class NetworkProbeTests(unittest.TestCase):
    @patch("omni.network_probe.shutil.which", return_value=None)
    def test_unavailable(self, _):
        self.assertEqual(probe_network()["status"], "UNAVAILABLE")

    @patch("omni.network_probe.shutil.which", return_value="/usr/bin/python3")
    @patch("omni.network_probe.subprocess.run")
    def test_enetunreach(self, run, _):
        run.return_value.returncode = 0
        run.return_value.stdout = "NETNS=net:[1234]\nDENIED=101\n"
        run.return_value.stderr = ""
        result = probe_network()
        self.assertTrue(result["network_denial_verified"])
        self.assertFalse(result["execution_authorized"])

    @patch("omni.network_probe.shutil.which", return_value="/usr/bin/python3")
    @patch("omni.network_probe.subprocess.run")
    def test_timeout_is_not_denial(self, run, _):
        run.return_value.returncode = 0
        run.return_value.stdout = "NETNS=net:[1234]\nDENIED=110\n"
        run.return_value.stderr = ""
        self.assertFalse(probe_network()["network_denial_verified"])
