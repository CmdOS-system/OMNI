import unittest
from omni.environment import build_environment


def sample_plan():
    return {"schema": "omni.capability_plan.v1", "status": "PREFLIGHT_ONLY",
            "input": {"sha256": "a" * 64, "format": "ELF"},
            "options": [{"runtime": "linux-native", "available": True,
                         "eligible_for_preflight": True, "reasons": []}]}


class EnvironmentTests(unittest.TestCase):
    def test_default_denies_execution(self):
        result = build_environment(sample_plan(), "linux-native")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["isolation_verified"])
        self.assertEqual(result["status"], "BLOCKED_PENDING_ISOLATION")

    def test_stable_contract_digest(self):
        a = build_environment(sample_plan(), "linux-native", permissions=["network", "clipboard"])
        b = build_environment(sample_plan(), "linux-native", permissions=["clipboard", "network"])
        self.assertEqual(a["contract_sha256"], b["contract_sha256"])

    def test_permissions_are_not_granted(self):
        result = build_environment(sample_plan(), "linux-native", permissions=["network"])
        self.assertIn("requested_permissions_require_enforced_policy", result["reasons"])

    def test_unknown_runtime_rejected(self):
        with self.assertRaises(ValueError):
            build_environment(sample_plan(), "unknown")

    def test_unplanned_runtime_rejected(self):
        with self.assertRaises(ValueError):
            build_environment(sample_plan(), "wine")

    def test_invalid_limits_rejected(self):
        for limits in ({"memory_mib": 0}, {"cpu_seconds": -1}, {"wall_seconds": 999999},
                       {"memory_mib": True}, {"memory_mib": 1.5}, {"unknown": 1}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                build_environment(sample_plan(), "linux-native", limits=limits)

    def test_unknown_permission_rejected(self):
        with self.assertRaises(ValueError):
            build_environment(sample_plan(), "linux-native", permissions=["root"])

    def test_wrong_schema_rejected(self):
        data = sample_plan()
        data["schema"] = "untrusted"
        with self.assertRaises(ValueError):
            build_environment(data, "linux-native")
