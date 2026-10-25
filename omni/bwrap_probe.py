"""Experimental Bubblewrap boundary probe; never runs user-supplied apps."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def probe_bubblewrap(timeout=15):
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return {"schema": "omni.bwrap_probe.v1", "status": "UNAVAILABLE",
                "private_path_hidden": False, "execution_authorized": False}
    with tempfile.TemporaryDirectory(prefix="omni-boundary-") as directory:
        marker = Path(directory) / "private-marker"
        marker.write_text("HOST_ONLY")
        marker.chmod(0o600)
        cmd = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid",
               "--unshare-net", "--unshare-ipc", "--unshare-uts",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        for mount in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(mount).exists():
                cmd.extend(["--ro-bind", mount, mount])
        cmd.extend(["--", "/bin/sh", "-c",
                    'if test -e "$1"; then echo OMNI_PRIVATE_VISIBLE; else echo OMNI_PRIVATE_HIDDEN; fi',
                    "omni-probe", str(marker)])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                    stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            return {"schema": "omni.bwrap_probe.v1", "status": "TIMEOUT",
                    "private_path_hidden": False, "execution_authorized": False}
        hidden = result.returncode == 0 and result.stdout.strip() == "OMNI_PRIVATE_HIDDEN"
        return {"schema": "omni.bwrap_probe.v1",
                "status": "BOUNDARY_OBSERVED" if hidden else "BLOCKED",
                "private_path_hidden": hidden,
                "network_namespace_requested": True,
                "network_denial_verified": False,
                "returncode": result.returncode,
                "stderr_tail": result.stderr[-500:],
                "execution_authorized": False,
                "isolation_certified": False}


if __name__ == "__main__":
    print(json.dumps(probe_bubblewrap(), indent=2, sort_keys=True))
