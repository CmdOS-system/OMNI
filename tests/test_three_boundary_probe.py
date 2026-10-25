import unittest
from unittest.mock import patch
from omni.three_boundary_probe import probe_three_boundaries


class ThreeBoundaryTests(unittest.TestCase):
    def test_bad_timeout(self):
        with self.assertRaises(ValueError):
            probe_three_boundaries(timeout=0)

    @patch("omni.three_boundary_probe.shutil.which", return_value=None)
    def test_unavailable_fails_closed(self, _):
        result = probe_three_boundaries()
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertFalse(result["execution_authorized"])
