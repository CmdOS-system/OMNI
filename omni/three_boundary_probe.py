"""Integrated fixed-command Bubblewrap filesystem, network and wall-time probe."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


def probe_three_boundaries(timeout=0.5):
    if not 0.2 <= timeout <= 5:
        raise ValueError("invalid timeout")
    result = {"schema": "omni.three_boundary_probe.v1", "status": "BLOCKED",
              "filesystem_verified": False, "network_verified": False,
              "wall_timeout_verified": False, "process_reaped": False,
              "memory_cpu_verified": False, "execution_authorized": False}
    bwrap = shutil.which("bwrap")
    python = shutil.which("python3")
    if not bwrap or not python:
        result["status"] = "UNAVAILABLE"
        return result
    with tempfile.TemporaryDirectory(prefix="omni-three-") as directory:
        marker = Path(directory) / "host-secret"
        marker.write_text("HOST_ONLY")
        script = (
            "import os,socket,sys,time;"
            "print('PRIVATE_HIDDEN='+str(not os.path.exists(sys.argv[1])),flush=True);"
            "s=socket.socket();s.settimeout(1);"
            "\ntry:\n s.connect(('192.0.2.1',9));print('CONNECTED',flush=True)\n"
            "except OSError as e:\n print('NET_ERRNO='+str(e.errno),flush=True)\n"
            "finally:\n s.close()\n"
            "print('SLEEPING',flush=True);time.sleep(30)"
        )
        cmd = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid",
               "--unshare-net", "--unshare-ipc", "--unshare-uts",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        for mount in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(mount).exists():
                cmd += ["--ro-bind", mount, mount]
        cmd += ["--", python, "-u", "-c", script, str(marker)]
        process = None
        output = b""
        try:
            process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                out, err = process.communicate(timeout=timeout)
                output += out
                result["status"] = "EXITED_BEFORE_TIMEOUT"
            except subprocess.TimeoutExpired as error:
                output += error.stdout or b""
                os.killpg(process.pid, signal.SIGKILL)
                out, err = process.communicate(timeout=5)
                # communicate() may repeat previously captured output after timeout.
                output = out
                result["wall_timeout_verified"] = True
            lines = output.decode("utf-8", "replace").splitlines()
            result["filesystem_verified"] = "PRIVATE_HIDDEN=True" in lines
            result["network_verified"] = "NET_ERRNO=101" in lines
            result["process_reaped"] = process.poll() is not None
            if all((result["filesystem_verified"], result["network_verified"],
                    result["wall_timeout_verified"], result["process_reaped"])):
                result["status"] = "THREE_BOUNDARIES_OBSERVED"
            else:
                result["status"] = "BLOCKED_INCOMPLETE_OBSERVATION"
            result["stdout_tail"] = output.decode("utf-8", "replace")[-500:]
            result["stderr_tail"] = err.decode("utf-8", "replace")[-300:]
        except (OSError, subprocess.TimeoutExpired) as error:
            result["error"] = type(error).__name__
        finally:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        return result


if __name__ == "__main__":
    print(json.dumps(probe_three_boundaries(), indent=2, sort_keys=True))
