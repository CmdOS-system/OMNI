"""Opt-in cgroup v2 resource experiment; only fixed trusted sleep process."""
import json
from pathlib import Path
import subprocess
import sys
import uuid


def probe_limits(parent, memory_mib=128, cpu_quota_us=50000, period_us=100000):
    if not (16 <= memory_mib <= 1024 and 1000 <= cpu_quota_us <= period_us <= 1000000):
        raise ValueError("invalid bounded resource limits")
    result = {"schema": "omni.resource_gate.v1", "status": "BLOCKED",
              "limits_verified": False, "process_placed": False,
              "cleanup_verified": False, "execution_authorized": False}
    parent = Path(parent)
    child = parent / ("omni-probe-" + uuid.uuid4().hex)
    created = False
    process = None
    try:
        root = Path("/sys/fs/cgroup").resolve()
        resolved = parent.resolve()
        if resolved == root or root not in resolved.parents:
            raise PermissionError("parent must be an explicitly delegated cgroup v2 subdirectory")
        child.mkdir(mode=0o700)
        created = True
        memory_bytes = memory_mib * 1024 * 1024
        (child / "memory.max").write_text(str(memory_bytes))
        (child / "cpu.max").write_text(f"{cpu_quota_us} {period_us}")
        observed_memory = int((child / "memory.max").read_text().strip())
        observed_cpu = (child / "cpu.max").read_text().split()
        if observed_memory != memory_bytes or observed_cpu != [str(cpu_quota_us), str(period_us)]:
            raise RuntimeError("kernel did not accept limits")
        result["limits_verified"] = True
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.25)"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        (child / "cgroup.procs").write_text(str(process.pid))
        result["process_placed"] = str(process.pid) in (child / "cgroup.procs").read_text().split()
        process.wait(timeout=5)
        if not result["process_placed"]:
            raise RuntimeError("process placement not observed")
        result["status"] = "LIMITS_AND_PLACEMENT_OBSERVED"
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        result["error"] = type(error).__name__ + ": " + str(error)[:200]
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        if not created:
            result["cleanup_verified"] = True
        else:
            try:
                child.rmdir()
                result["cleanup_verified"] = True
            except OSError as error:
                result["cleanup_error"] = str(error)[:200]
        if not result["cleanup_verified"]:
            result["status"] = "BLOCKED_CLEANUP_UNVERIFIED"
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python -m omni.resource_gate /explicitly/delegated/cgroup/parent")
    print(json.dumps(probe_limits(sys.argv[1]), indent=2, sort_keys=True))
