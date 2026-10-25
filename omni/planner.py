"""OMNI capability planner: inspection and runtime availability, never execution.

No file contents are executed. The caller must separately authorize execution.
"""
import hashlib
import json
from pathlib import Path
import shutil
import struct

MAX_INSPECT_BYTES = 4096

def inspect_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("input must be a regular, non-symlink file")
    with path.open("rb") as stream:
        head = stream.read(MAX_INSPECT_BYTES)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    info = {"format": "UNKNOWN", "architecture": "UNKNOWN", "validated": False,
            "sha256": digest.hexdigest(), "size": path.stat().st_size}
    if len(head) >= 20 and head[:4] == b"\x7fELF":
        endian = "<" if head[5] == 1 else ">" if head[5] == 2 else None
        if head[4] in (1, 2) and endian is not None and head[6] == 1:
            machine = struct.unpack_from(endian + "H", head, 18)[0]
            info.update(format="ELF", architecture={62: "x86_64", 3: "x86",
                        183: "aarch64", 40: "arm"}.get(machine, "UNKNOWN"),
                        validated=True)
    elif len(head) >= 64 and head[:2] == b"MZ":
        offset = struct.unpack_from("<I", head, 0x3c)[0]
        if offset <= len(head) - 24 and head[offset:offset+4] == b"PE\0\0":
            machine = struct.unpack_from("<H", head, offset + 4)[0]
            optional_size = struct.unpack_from("<H", head, offset + 20)[0]
            optional_at = offset + 24
            magic = struct.unpack_from("<H", head, optional_at)[0] if optional_at + 2 <= len(head) else None
            if optional_size >= 2 and optional_at + optional_size <= len(head) and magic in (0x10b, 0x20b):
                info.update(format="PE", architecture={0x8664: "x86_64", 0x14c: "x86",
                            0xaa64: "aarch64"}.get(machine, "UNKNOWN"), validated=True)
    elif len(head) >= 8 and head[:4] == b"\0asm" and head[4:8] == b"\x01\0\0\0":
        info.update(format="WASM", architecture="wasm32", validated=True)
    return info

RUNTIME_MAP = {
    "PE": [("wine", "wine"), ("proton", "proton")],
    "ELF": [("linux-native", None), ("qemu-system-x86_64", "qemu-system-x86_64")],
    "WASM": [("wasmtime", "wasmtime")],
}

def plan(path, *, host_system=None, host_arch=None, which=shutil.which):
    import platform
    detected = inspect_file(path)
    system = host_system or platform.system()
    arch = host_arch or platform.machine()
    compatible_arch = {"amd64": "x86_64", "AMD64": "x86_64"}.get(arch, arch)
    options = []
    for name, executable in RUNTIME_MAP.get(detected["format"], []):
        found = which(executable) if executable else ("/native" if system == "Linux" else None)
        eligible = detected["validated"] and bool(found)
        reasons = []
        if not detected["validated"]:
            reasons.append("format_not_structurally_validated")
        if not found:
            reasons.append("runtime_unavailable")
        if name == "linux-native" and detected["architecture"] != compatible_arch:
            eligible = False
            reasons.append("host_architecture_mismatch")
        if name == "qemu-system-x86_64" and detected["architecture"] != "x86_64":
            eligible = False
            reasons.append("guest_architecture_not_configured")
        if name == "proton":
            eligible = False
            reasons.append("proton_requires_explicit_runtime_adapter")
        if name == "wine" and detected["architecture"] not in ("x86", "x86_64"):
            eligible = False
            reasons.append("wine_architecture_unsupported_by_current_adapter")
        options.append({"runtime": name, "available": bool(found), "eligible_for_preflight": eligible,
                        "reasons": reasons})
    return {"schema": "omni.capability_plan.v1", "input": detected,
            "host": {"system": system, "architecture": arch},
            "options": options, "execution_performed": False,
            "compatibility_certified": False, "execution_authorized": False,
            "status": "PREFLIGHT_ONLY"}

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Inspect only; never execute")
    parser.add_argument("file")
    args = parser.parse_args()
    print(json.dumps(plan(args.file), indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
