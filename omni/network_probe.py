"""Fixed-command Bubblewrap network namespace probe; not a general application runner."""
import json
from pathlib import Path
import shutil
import subprocess


def probe_network(timeout=15):
    bwrap = shutil.which("bwrap")
    python = shutil.which("python3")
    if not bwrap or not python:
        return {"schema": "omni.network_probe.v1", "status": "UNAVAILABLE",
                "network_denial_verified": False, "execution_authorized": False}
    # The process checks its own network namespace inode and rejects an external
    # TCP connect attempt. No destination data is sent.
    script = (
        "import os,socket;"
        "print('NETNS='+os.readlink('/proc/self/ns/net'));"
        "s=socket.socket();s.settimeout(2);"
        "\ntry:\n s.connect(('192.0.2.1', 9));print('CONNECTED')\n"
        "except OSError as e:\n print('DENIED='+str(e.errno))\n"
        "finally:\n s.close()\n"
    )
    cmd = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-net",
           "--unshare-pid", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for mount in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(mount).exists():
            cmd += ["--ro-bind", mount, mount]
    cmd += ["--", python, "-c", script]
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        return {"schema": "omni.network_probe.v1", "status": "TIMEOUT",
                "network_denial_verified": False, "execution_authorized": False}
    import re
    marker = re.search(r"^NETNS=(net:\[\d+\])$", run.stdout, re.M)
    # ENETUNREACH (101) is a specific denial signal. A timeout is not proof.
    denied = run.returncode == 0 and bool(marker) and "DENIED=101" in run.stdout.splitlines()
    return {"schema": "omni.network_probe.v1",
            "status": "NETWORK_DENIAL_OBSERVED" if denied else "BLOCKED",
            "network_denial_verified": denied,
            "namespace_observed": bool(marker),
            "returncode": run.returncode,
            "stdout_tail": run.stdout[-300:],
            "stderr_tail": run.stderr[-300:],
            "execution_authorized": False,
            "isolation_certified": False}


if __name__ == "__main__":
    print(json.dumps(probe_network(), indent=2, sort_keys=True))
