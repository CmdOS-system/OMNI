import unittest
from unittest.mock import patch
from omni.timeout_probe import probe_wall_timeout


class TimeoutProbeTests(unittest.TestCase):
    def test_invalid_timeout(self):
        with self.assertRaises(ValueError):
            probe_wall_timeout(limit_seconds=0)

    @patch("omni.timeout_probe.shutil.which", return_value=None)
    def test_unavailable_is_blocked(self, _):
        result = probe_wall_timeout()
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertFalse(result["execution_authorized"])

    @patch("omni.timeout_probe.shutil.which", return_value="/usr/bin/bwrap")
    @patch("omni.timeout_probe.subprocess.Popen")
    def test_timeout_kills_process_group(self, popen, _):
        import subprocess
        proc = popen.return_value
        proc.pid = 1234
        proc.communicate.side_effect = [subprocess.TimeoutExpired("sleep", 0.4), (b"", b"")]
        proc.poll.return_value = -9
        proc.returncode = -9
        with patch("omni.timeout_probe.os.killpg") as kill:
            result = probe_wall_timeout()
        kill.assert_called_once()
        self.assertEqual(result["status"], "WALL_TIMEOUT_ENFORCED")
        self.assertTrue(result["process_reaped"])
        self.assertFalse(result["execution_authorized"])
