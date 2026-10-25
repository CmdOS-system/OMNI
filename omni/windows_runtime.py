"""Explicit native Windows PE launcher; not a compatibility layer or sandbox.

Only launches a user-selected .exe after a fresh inspection and affirmative
consent. The process receives normal user permissions and may spawn children.
"""
import os
from pathlib import Path
import platform
import subprocess

from omni.windows_preview import inspect_preview


def assess_native_windows(record, *, host_system=None, host_arch=None):
    system = host_system if host_system is not None else platform.system()
    machine = host_arch if host_arch is not None else platform.machine()
    machine = {"AMD64": "x86_64", "amd64": "x86_64", "ARM64": "aarch64",
               "arm64": "aarch64", "i386": "x86", "i686": "x86"}.get(machine, machine)
    reasons = []
    path = Path(record.get("path", ""))
    if system != "Windows":
        reasons.append("requires_windows_host")
    if record.get("format") != "PE":
        reasons.append("not_windows_pe")
    if path.suffix.lower() != ".exe":
        reasons.append("only_exe_launch_supported")
    if not record.get("sha256"):
        reasons.append("missing_inspection_hash")
    supported = {"x86_64": {"x86", "x86_64"}, "x86": {"x86"},
                 "aarch64": {"aarch64"}}
    if record.get("architecture") not in supported.get(machine, set()):
        reasons.append("architecture_not_supported_by_this_launcher")
    if str(path).startswith("\\\\"):
        reasons.append("network_paths_not_supported")
    return {"runtime": "windows-native", "launch_available": not reasons,
            "reasons": reasons, "sandboxed": False, "cross_os_compatibility": False,
            "requires_user_confirmation": True}


def launch_native_windows(record, *, confirmed=False, host_system=None, host_arch=None):
    """Return Popen after explicit consent; never silently launch a file."""
    if not confirmed:
        raise PermissionError("Explicit confirmation is required")
    decision = assess_native_windows(record, host_system=host_system, host_arch=host_arch)
    if not decision["launch_available"]:
        raise ValueError("Native launch blocked: " + ", ".join(decision["reasons"]))
    path = Path(record["path"])
    # Recheck content immediately before launch. A concurrent replacement is
    # still possible on Windows: this is NOT a secure sandbox or atomic launch.
    current = inspect_preview(path)
    if any(current[key] != record.get(key) for key in ("sha256", "format", "architecture")):
        raise ValueError("The file changed since inspection; re-add it to the library")
    return subprocess.Popen([str(path)], cwd=str(path.parent),
                            stdin=subprocess.DEVNULL, shell=False)
