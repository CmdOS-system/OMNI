"""Strict composition of independently observed OMNI boundary evidence.

This is an evidence gate, not a sandbox or execution authorization.
"""
import json


def evaluate_boundaries(filesystem, network, resources):
    checks = {
        "filesystem_boundary": (
            filesystem.get("schema") == "omni.bwrap_probe.v1"
            and filesystem.get("status") == "BOUNDARY_OBSERVED"
            and filesystem.get("private_path_hidden") is True
            and filesystem.get("returncode") == 0
        ),
        "network_boundary": (
            network.get("schema") == "omni.network_probe.v1"
            and network.get("status") == "NETWORK_DENIAL_OBSERVED"
            and network.get("network_denial_verified") is True
            and network.get("returncode") == 0
        ),
        "resource_limits": (
            resources.get("schema") == "omni.resource_gate.v1"
            and resources.get("status") == "LIMITS_AND_PLACEMENT_OBSERVED"
            and resources.get("limits_verified") is True
            and resources.get("process_placed") is True
            and resources.get("cleanup_verified") is True
        ),
    }
    return {
        "schema": "omni.combined_boundaries.v1",
        "checks": checks,
        "observations_complete": all(checks.values()),
        "status": "OBSERVATIONS_COMPLETE" if all(checks.values()) else "BLOCKED_INCOMPLETE_EVIDENCE",
        "same_process_isolation_verified": False,
        "execution_authorized": False,
        "isolation_certified": False,
    }


def main():
    import sys
    if len(sys.argv) != 4:
        sys.exit("Usage: python -m omni.boundary_gate filesystem.json network.json resources.json")
    with open(sys.argv[1]) as f:
        filesystem = json.load(f)
    with open(sys.argv[2]) as f:
        network = json.load(f)
    with open(sys.argv[3]) as f:
        resources = json.load(f)
    print(json.dumps(evaluate_boundaries(filesystem, network, resources), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
