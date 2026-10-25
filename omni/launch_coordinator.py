"""Single explicit launch entry point for OMNI Windows desktop.

Selection is a preflight, not proof of compatibility or safety. The actual
adapter revalidates the inspected file before executing. Never fall back to
another runtime after an attempted launch fails.
"""
from omni.runtime_choices import build_runtime_overview
from omni.windows_runtime import launch_native_windows
from omni.wsl2_runtime import launch_elf_wsl


def launch_with_recommended_runtime(record, discovery=None, distribution="", *,
                                    confirmed=False, host_system=None,
                                    host_arch=None, native_launcher=None,
                                    wsl_launcher=None):
    """Launch with one selected adapter only after explicit confirmation.

    Returns {"runtime": str, "process": subprocess.Popen-like}. The caller
    owns the process and may register it with the OMNI process manager.
    """
    if not confirmed:
        raise PermissionError("Explicit confirmation is required before launching")
    overview = build_runtime_overview(
        record, discovery, distribution, host_system=host_system, host_arch=host_arch)
    runtime = overview["preferred_runtime"]
    if runtime is None:
        native_reasons = ", ".join(overview["native_windows"]["reasons"])
        linux_reasons = ", ".join(overview["linux_wsl2"]["reasons"])
        raise ValueError(f"No available runtime (Windows: {native_reasons}; WSL2: {linux_reasons})")
    if runtime == "windows-native":
        launcher = native_launcher if native_launcher is not None else launch_native_windows
        process = launcher(record, confirmed=True, host_system=host_system,
                           host_arch=host_arch)
    elif runtime == "wsl2-elf":
        launcher = wsl_launcher if wsl_launcher is not None else launch_elf_wsl
        process = launcher(record, distribution, confirmed=True,
                           host_system=host_system, host_arch=host_arch)
    else:
        raise ValueError("Unrecognized runtime: " + str(runtime))
    return {"runtime": runtime, "process": process}
