"""Explicit WSL2 ELF launcher for OMNI on Windows (experimental).

Uses the selected, installed WSL2 distribution and its default Linux user.
NO sandboxing, resource limits, guest-process containment, or compatibility
guarantees. Never launches without an affirmative UI confirmation.
"""
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import shutil
import subprocess

from omni.windows_preview import inspect_preview
from omni.wsl2_discovery import discover_wsl2


def _architecture(name):
    return {"AMD64": "x86_64", "amd64": "x86_64",
            "ARM64": "aarch64", "arm64": "aarch64"}.get(name, name)


def assess_elf_wsl_launch(record, discovery, distribution, *, host_system=None, host_arch=None):
    """Eligibility is a preflight, NOT proof of compatibility or safety."""
    system = host_system if host_system is not None else platform.system()
    arch = _architecture(host_arch if host_arch is not None else platform.machine())
    reasons = []
    if system != "Windows":
        reasons.append("requires_windows_host")
    if record.get("format") != "ELF":
        reasons.append("not_linux_elf")
    if arch not in ("x86_64", "aarch64") or record.get("architecture") != arch:
        reasons.append("host_architecture_mismatch")
    if not record.get("sha256"):
        reasons.append("missing_inspection_hash")
    path_text = record.get("path")
    if not isinstance(path_text, str):
        reasons.append("missing_windows_path")
    else:
        win_path = PureWindowsPath(path_text)
        # Exclude UNC, device paths, relative paths and WSL \\wsl$ paths.
        if not win_path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", win_path.drive):
            reasons.append("requires_local_windows_drive_path")
        if any(ord(char) < 32 for char in path_text):
            reasons.append("invalid_path_characters")
    if (discovery.get("status") != "WSL2_DETECTED"
            or distribution not in discovery.get("wsl2_distributions", [])):
        reasons.append("selected_wsl2_distribution_unavailable")
    return {"runtime": "wsl2-elf", "launch_available": not reasons,
            "requires_user_confirmation": True, "sandboxed": False,
            "guest_process_contained": False, "compatibility_certified": False,
            "reasons": reasons}


def _validate_elf_header(path, architecture):
    """Reject obviously non-executable ELF files (not a full ELF verifier)."""
    with Path(path).open("rb") as stream:
        header = stream.read(64)
    machine = {"x86_64": 62, "aarch64": 183}.get(architecture)
    if (len(header) < 64 or header[:4] != b"\x7fELF"
            or header[4:7] != b"\x02\x01\x01"
            or int.from_bytes(header[16:18], "little") not in (2, 3)
            or int.from_bytes(header[18:20], "little") != machine):
        raise ValueError("Not a supported 64-bit Linux executable ELF")


def launch_elf_wsl(record, distribution, *, confirmed=False, host_system=None,
                   host_arch=None, which=shutil.which, runner=subprocess.run,
                   popen=subprocess.Popen):
    """Launch an inspected Windows-drive ELF using wsl.exe --exec, no shell.

    wslpath is executed first to honor the distribution's mount configuration.
    The WSL distribution has access to Windows files and networks; this is NOT
    a security boundary. Closing wsl.exe may not kill all Linux descendants.
    """
    if not confirmed:
        raise PermissionError("Explicit confirmation is required for WSL2 execution")
    system = host_system if host_system is not None else platform.system()
    arch = _architecture(host_arch if host_arch is not None else platform.machine())
    discovery = discover_wsl2(host_system=system, which=which, runner=runner)
    decision = assess_elf_wsl_launch(record, discovery, distribution,
                                     host_system=system, host_arch=arch)
    if not decision["launch_available"]:
        raise ValueError("WSL2 launch blocked: " + ", ".join(decision["reasons"]))

    # Reinspect before launching. Concurrent file replacement is still possible:
    # this hash check is NOT an atomic Windows execution security guarantee.
    path = Path(record["path"])
    current = inspect_preview(path)
    if any(current[key] != record.get(key) for key in ("sha256", "format", "architecture")):
        raise ValueError("File changed since inspection; add it to the library again")
    _validate_elf_header(path, arch)

    executable = which("wsl.exe")
    if not executable:
        raise ValueError("wsl.exe disappeared before launch")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    translated = runner(
        [executable, "--distribution", distribution, "--exec",
         "wslpath", "-a", "-u", str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=10,
        creationflags=flags)
    if translated.returncode != 0:
        raise ValueError("WSL2 could not translate the Windows file path")
    raw = translated.stdout
    linux_path = (raw.decode("utf-8-sig", errors="strict")
                  if isinstance(raw, bytes) else raw).rstrip("\r\n")
    if (not linux_path.startswith("/") or "\x00" in linux_path
            or "\n" in linux_path or "\r" in linux_path):
        raise ValueError("WSL2 returned an invalid Linux path")
    return popen(
        [executable, "--distribution", distribution, "--exec", linux_path],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, shell=False, creationflags=flags)
