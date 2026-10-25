import unittest
from omni.environment import build_environment
from omni.linux_isolation import assess_environment, check_linux_isolation


class LinuxIsolationTests(unittest.TestCase):
    def test_non_linux_fails_closed(self):
        result = check_linux_isolation(system="Windows")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["execution_authorized"])

    def test_missing_tools_never_authorizes(self):
        result = check_linux_isolation(system="Linux", which=lambda _: None)
        self.assertFalse(result["checks"]["bubblewrap_installed"])
        self.assertFalse(result["execution_authorized"])

    def test_tools_present_still_not_proof(self):
        result = check_linux_isolation(system="Linux", which=lambda _: "/bin/true")
        self.assertTrue(result["checks"]["bubblewrap_installed"])
        self.assertFalse(result["isolation_verified"])

    def test_readiness_stays_blocked(self):
        plan = {"schema": "omni.capability_plan.v1", "status": "PREFLIGHT_ONLY",
                "input": {"sha256": "f" * 64, "format": "ELF"},
                "options": [{"runtime": "linux-native", "available": True,
                             "eligible_for_preflight": True, "reasons": []}]}
        contract = build_environment(plan, "linux-native")
        readiness = assess_environment(contract, check_linux_isolation(system="Linux"))
        self.assertEqual(readiness["status"], "BLOCKED_PENDING_ENFORCEMENT")
        self.assertFalse(readiness["execution_authorized"])

    def test_unknown_contract_rejected(self):
        with self.assertRaises(ValueError):
            assess_environment({"schema": "fake"}, check_linux_isolation(system="Linux"))
