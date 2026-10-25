"""Fixed-command Bubblewrap wall-time enforcement experiment.

Runs only a trusted sleep process. This is not a general sandbox executor.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time


def probe_wall_timeout(limit_seconds=0.4, sleep_seconds=4):
    if not (0.1 <= limit_seconds <= 10 and sleep_seconds > limit_seconds):
        raise ValueError("invalid bounded probe duration")
    result = {"schema": "omni.timeout_probe.v1", "status": "BLOCKED",
              "timeout_triggered": False, "process_reaped": False,
              "execution_authorized": False, "resource_limits_verified": False}
    bwrap = shutil.which("bwrap")
    if not bwrap:
        result["status"] = "UNAVAILABLE"
        return result
    cmd = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid",
           "--unshare-net", "--unshare-ipc", "--unshare-uts",
           "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for mount in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(mount).exists():
            cmd += ["--ro-bind", mount, mount]
    cmd += ["--", "/bin/sleep", str(sleep_seconds)]
    process = None
    start = time.monotonic()
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            process.communicate(timeout=limit_seconds)
            result["status"] = "PROCESS_EXITED_EARLY"
        except subprocess.TimeoutExpired:
            result["timeout_triggered"] = True
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            result["status"] = "WALL_TIMEOUT_ENFORCED"
        result["returncode"] = process.returncode
        result["process_reaped"] = process.poll() is not None
    except (OSError, subprocess.TimeoutExpired) as error:
        result["error"] = type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
    return result


if __name__ == "__main__":
    print(json.dumps(probe_wall_timeout(), indent=2, sort_keys=True))
