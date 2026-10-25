"""Read-only cgroup v2 resource-controller assessment for OMNI.

No cgroups are created or modified; limits are never claimed to be enforced.
"""
import json
from pathlib import Path


def parse_cpu_max(value):
    parts = value.strip().split()
    if len(parts) != 2 or not parts[1].isdigit() or int(parts[1]) <= 0:
        raise ValueError("invalid cpu.max")
    if parts[0] != "max" and (not parts[0].isdigit() or int(parts[0]) <= 0):
        raise ValueError("invalid cpu.max quota")
    return {"quota_us": None if parts[0] == "max" else int(parts[0]),
            "period_us": int(parts[1])}


def assess_resources(root="/sys/fs/cgroup"):
    """Inspect current cgroup interface only; do not mutate host settings."""
    root = Path(root)
    checks = {"cgroup_v2": (root / "cgroup.controllers").is_file()}
    controllers = set()
    if checks["cgroup_v2"]:
        try:
            controllers = set((root / "cgroup.controllers").read_text().split())
        except OSError:
            pass
    checks["memory_controller_advertised"] = "memory" in controllers
    checks["cpu_controller_advertised"] = "cpu" in controllers
    checks["memory_max_interface"] = (root / "memory.max").is_file()
    checks["cpu_max_interface"] = (root / "cpu.max").is_file()
    checks["memory_events_interface"] = (root / "memory.events").is_file()
    cpu = None
    try:
        if checks["cpu_max_interface"]:
            cpu = parse_cpu_max((root / "cpu.max").read_text())
    except (OSError, ValueError):
        pass
    return {"schema": "omni.resource_preflight.v1",
            "status": "PREFLIGHT_ONLY" if checks["cgroup_v2"] else "BLOCKED",
            "checks": checks, "current_cpu_max": cpu,
            "resource_limits_enforced_by_omni": False,
            "execution_authorized": False}


if __name__ == "__main__":
    print(json.dumps(assess_resources(), indent=2, sort_keys=True))
