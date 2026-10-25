"""One-process filesystem and network boundary experiment with Bubblewrap."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def probe_integrated(timeout=15):
    result = {"schema": "omni.integrated_probe.v1", "status": "BLOCKED",
              "filesystem_boundary_verified": False, "network_boundary_verified": False,
              "resource_limits_verified": False, "execution_authorized": False}
    bwrap = shutil.which("bwrap")
    python = shutil.which("python3")
    if not bwrap or not python:
        result["status"] = "UNAVAILABLE"
        return result
    with tempfile.TemporaryDirectory(prefix="omni-integrated-") as directory:
        marker = Path(directory) / "host-private"
        marker.write_text("HOST_ONLY")
        marker.chmod(0o600)
        script = (
            "import os,socket,sys;"
            "print('PRIVATE_HIDDEN='+str(not os.path.exists(sys.argv[1])));"
            "print('NETNS='+os.readlink('/proc/self/ns/net'));"
            "s=socket.socket();s.settimeout(2);"
            "\ntry:\n s.connect(('192.0.2.1',9));print('NETWORK_CONNECTED')\n"
            "except OSError as e:\n print('NETWORK_ERRNO='+str(e.errno))\n"
            "finally:\n s.close()\n"
        )
        cmd = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid",
               "--unshare-net", "--unshare-ipc", "--unshare-uts",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        for mount in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(mount).exists():
                cmd.extend(["--ro-bind", mount, mount])
        cmd.extend(["--", python, "-c", script, str(marker)])
        try:
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                 stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            result["status"] = "TIMEOUT"
            return result
        lines = run.stdout.splitlines()
        result["filesystem_boundary_verified"] = run.returncode == 0 and "PRIVATE_HIDDEN=True" in lines
        result["network_boundary_verified"] = run.returncode == 0 and "NETWORK_ERRNO=101" in lines and any(
            line.startswith("NETNS=net:[") for line in lines
        )
        result["status"] = ("TWO_BOUNDARIES_OBSERVED"
                            if result["filesystem_boundary_verified"] and result["network_boundary_verified"]
                            else "BLOCKED")
        result["returncode"] = run.returncode
        result["stdout_tail"] = run.stdout[-500:]
        result["stderr_tail"] = run.stderr[-500:]
        return result


if __name__ == "__main__":
    print(json.dumps(probe_integrated(), indent=2, sort_keys=True))
