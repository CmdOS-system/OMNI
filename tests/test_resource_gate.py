import tempfile
import unittest
from pathlib import Path
from omni.resource_gate import probe_limits


class ResourceGateTests(unittest.TestCase):
    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            probe_limits("/tmp", memory_mib=1)

    def test_missing_delegation_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = probe_limits(tmp)
            self.assertFalse(result["execution_authorized"])
            self.assertFalse(result["limits_verified"])
            self.assertTrue(result["cleanup_verified"])
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_no_cgroup_root(self):
        result = probe_limits("/sys/fs/cgroup")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["limits_verified"])
