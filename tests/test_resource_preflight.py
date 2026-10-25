import tempfile
from pathlib import Path
import unittest
from omni.resource_preflight import assess_resources, parse_cpu_max


class ResourcePreflightTests(unittest.TestCase):
    def test_cpu_quota(self):
        self.assertEqual(parse_cpu_max("50000 100000"), {"quota_us": 50000, "period_us": 100000})

    def test_unlimited_cpu(self):
        self.assertIsNone(parse_cpu_max("max 100000")["quota_us"])

    def test_bad_cpu_format(self):
        for value in ("max 0", "0 100000", "banana 100000", "100000", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_cpu_max(value)

    def test_missing_cgroup_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            result = assess_resources(td)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse(result["resource_limits_enforced_by_omni"])

    def test_present_interfaces_are_not_enforcement(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "cgroup.controllers").write_text("cpu memory io")
            (root / "cpu.max").write_text("50000 100000")
            (root / "memory.max").write_text("536870912")
            (root / "memory.events").write_text("oom 0")
            result = assess_resources(td)
            self.assertTrue(result["checks"]["cpu_controller_advertised"])
            self.assertEqual(result["current_cpu_max"]["quota_us"], 50000)
            self.assertFalse(result["resource_limits_enforced_by_omni"])
            self.assertFalse(result["execution_authorized"])
