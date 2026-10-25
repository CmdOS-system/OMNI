import unittest
from omni.boundary_gate import evaluate_boundaries


def evidence():
    return (
        {"schema": "omni.bwrap_probe.v1", "status": "BOUNDARY_OBSERVED",
         "private_path_hidden": True, "returncode": 0},
        {"schema": "omni.network_probe.v1", "status": "NETWORK_DENIAL_OBSERVED",
         "network_denial_verified": True, "returncode": 0},
        {"schema": "omni.resource_gate.v1", "status": "LIMITS_AND_PLACEMENT_OBSERVED",
         "limits_verified": True, "process_placed": True, "cleanup_verified": True},
    )


class BoundaryGateTests(unittest.TestCase):
    def test_complete_evidence_still_does_not_authorize_execution(self):
        result = evaluate_boundaries(*evidence())
        self.assertTrue(result["observations_complete"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["same_process_isolation_verified"])

    def test_missing_resource_delegation_blocks(self):
        fs, net, res = evidence()
        res["status"] = "NOT_DELEGATED"
        self.assertEqual(evaluate_boundaries(fs, net, res)["status"],
                         "BLOCKED_INCOMPLETE_EVIDENCE")

    def test_each_missing_control_blocks(self):
        for index in range(3):
            records = list(evidence())
            records[index] = {}
            with self.subTest(index=index):
                self.assertFalse(evaluate_boundaries(*records)["observations_complete"])

    def test_false_positive_values_rejected(self):
        fs, net, res = evidence()
        fs["private_path_hidden"] = 1
        self.assertFalse(evaluate_boundaries(fs, net, res)["checks"]["filesystem_boundary"])

    def test_cleanup_required(self):
        fs, net, res = evidence()
        res["cleanup_verified"] = False
        self.assertFalse(evaluate_boundaries(fs, net, res)["checks"]["resource_limits"])
