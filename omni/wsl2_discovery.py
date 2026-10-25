"""Read-only WSL2 discovery for OMNI on Windows.

Never runs a Linux program, installs a distribution or authorizes execution.
A WSL distribution is NOT an OMNI security sandbox.
"""
import platform
import re
import shutil
import subprocess


def decode_wsl_output(raw):
    """wsl.exe commonly emits UTF-16LE when output is redirected."""
    if isinstance(raw, str):
        return raw
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if b"\x00" in raw[:64]:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_wsl_list(output):
    """Parse aligned wsl.exe --list --verbose output without assuming locale."""
    rows = []
    for line in decode_wsl_output(output).replace("\x00", "").splitlines():
        # WSL uses two or more spaces between the NAME and STATE columns.
        match = re.match(r"^\s*(\*)?\s*(.+?)\s{2,}(.+?)\s+([12])\s*$", line)
        if not match:
            continue
        _, name, state, version = match.groups()
        name = name.strip()
        state = state.strip()
        if not name or not state:
            continue
        rows.append({"name": name, "state": state, "version": int(version),
                     "default": bool(match.group(1))})
    return rows


def discover_wsl2(*, host_system=None, which=shutil.which, runner=subprocess.run):
    system = host_system if host_system is not None else platform.system()
    result = {"schema": "omni.wsl2_discovery.v1", "status": "UNAVAILABLE",
              "wsl_available": False, "wsl2_distributions": [],
              "distributions": [], "execution_authorized": False,
              "execution_performed": False, "sandboxed": False}
    if system != "Windows":
        result["status"] = "NOT_WINDOWS"
        return result
    executable = which("wsl.exe")
    if not executable:
        return result
    result["wsl_available"] = True
    try:
        completed = runner([executable, "--list", "--verbose"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, check=False, timeout=6,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        result["status"] = "TIMED_OUT"
        return result
    except OSError as exc:
        result["status"] = "PROBE_ERROR"
        result["error_type"] = type(exc).__name__
        return result
    if completed.returncode != 0:
        result["status"] = "WSL_LIST_FAILED"
        result["exit_code"] = completed.returncode
        return result
    rows = parse_wsl_list(completed.stdout)
    result["distributions"] = rows
    result["wsl2_distributions"] = [row["name"] for row in rows if row["version"] == 2]
    result["status"] = ("WSL2_DETECTED" if result["wsl2_distributions"]
                        else "NO_WSL2_DISTRIBUTION")
    return result


def assess_elf_wsl(record, discovery, *, host_arch=None):
    """Show possible WSL2 candidate; launching is deliberately NOT implemented."""
    arch = host_arch if host_arch is not None else platform.machine()
    arch = {"AMD64": "x86_64", "amd64": "x86_64", "ARM64": "aarch64",
            "arm64": "aarch64"}.get(arch, arch)
    reasons = []
    if record.get("format") != "ELF":
        reasons.append("not_linux_elf")
    if record.get("architecture") != arch:
        reasons.append("host_architecture_mismatch")
    if not record.get("sha256"):
        reasons.append("missing_inspection_hash")
    if discovery.get("status") != "WSL2_DETECTED":
        reasons.append("wsl2_distribution_not_detected")
    reasons.append("wsl2_execution_adapter_not_implemented")
    return {"runtime": "wsl2", "preflight_candidate": len(reasons) == 1,
            "launch_available": False, "execution_authorized": False,
            "execution_performed": False, "sandboxed": False,
            "distributions": discovery.get("wsl2_distributions", []),
            "reasons": reasons}
