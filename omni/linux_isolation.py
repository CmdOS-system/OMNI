"""OMNI Linux isolation preflight.

Checks actual kernel and runtime prerequisites. Does not create a sandbox or
claim isolation. Execution remains blocked until an enforcing backend exists.
"""
import json
import os
from pathlib import Path
import platform
import shutil


def check_linux_isolation(*, system=None, which=shutil.which, filesystem=Path):
    system = system or platform.system()
    checks = {}
    if system != "Linux":
        return {"schema": "omni.linux_isolation.v1", "host": system,
                "checks": {"linux_host": False}, "status": "BLOCKED",
                "isolation_verified": False, "execution_authorized": False}
    checks["linux_host"] = True
    checks["bubblewrap_installed"] = bool(which("bwrap"))
    checks["unshare_installed"] = bool(which("unshare"))
    checks["user_namespace_kernel_interface"] = filesystem("/proc/self/ns/user").exists()
    checks["mount_namespace_kernel_interface"] = filesystem("/proc/self/ns/mnt").exists()
    checks["pid_namespace_kernel_interface"] = filesystem("/proc/self/ns/pid").exists()
    checks["cgroup_v2_interface"] = filesystem("/sys/fs/cgroup/cgroup.controllers").exists()
    checks["seccomp_status_interface"] = filesystem("/proc/self/status").exists()
    checks["landlock_kernel_interface"] = filesystem("/sys/kernel/security/landlock").exists()
    return {"schema": "omni.linux_isolation.v1", "host": system,
            "checks": checks, "status": "PREFLIGHT_ONLY",
            "isolation_verified": False, "execution_authorized": False}


def assess_environment(contract, isolation):
    """Merge independent declarations; fail closed even if all checks exist."""
    if contract.get("schema") != "omni.environment.v1":
        raise ValueError("unsupported environment contract")
    if isolation.get("schema") != "omni.linux_isolation.v1":
        raise ValueError("unsupported isolation assessment")
    return {
        "schema": "omni.execution_readiness.v1",
        "contract_sha256": contract["contract_sha256"],
        "isolation_checks": isolation["checks"],
        "isolation_verified": False,
        "execution_authorized": False,
        "status": "BLOCKED_PENDING_ENFORCEMENT",
        "reasons": ["kernel_capabilities_do_not_prove_isolation",
                    "runtime_adapter_not_enforcing_contract"],
    }


def main():
    print(json.dumps(check_linux_isolation(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
