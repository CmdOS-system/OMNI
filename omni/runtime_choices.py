"""Unified, read-only runtime choices for the Windows OMNI library.

A candidate only means that the selected host adapter may attempt execution;
it is not a safety or compatibility certification and never starts processes.
"""
from omni.windows_runtime import assess_native_windows
from omni.wsl2_runtime import assess_elf_wsl_launch


def build_runtime_overview(record, discovery=None, distribution="", *,
                           host_system=None, host_arch=None):
    """Present consistent Windows/WSL2 launch eligibility to the desktop UI."""
    if not isinstance(record, dict):
        raise ValueError("An inspected application record is required")
    discovery = discovery if discovery is not None else {}
    native = assess_native_windows(record, host_system=host_system, host_arch=host_arch)
    linux = assess_elf_wsl_launch(
        record, discovery, distribution, host_system=host_system, host_arch=host_arch)
    preferred = ("windows-native" if native["launch_available"] else
                 "wsl2-elf" if linux["launch_available"] else None)
    return {"schema": "omni.runtime_choices.v1",
            "preferred_runtime": preferred,
            "native_windows": native, "linux_wsl2": linux,
            "execution_performed": False,
            "compatibility_certified": False,
            "sandboxed": False}
