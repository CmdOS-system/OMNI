# OMNI experimental WSL2 ELF execution from Windows

OMNI's Windows desktop can now select a detected WSL2 distribution and explicitly
start an inspected **64-bit x86_64/aarch64 Linux ELF executable** stored on a local
Windows drive. This is an experimental integration, not OMNI 1.0 compatibility.

Workflow:
1. Add the ELF file to OMNI's library.
2. Click **Detectar motor Linux (WSL2)**; select an installed WSL2 distribution.
3. Select the ELF and click **Abrir ELF en Linux (WSL2)**.
4. Read and accept the warning. Without confirmation, no execution occurs.
5. OMNI rechecks the file hash, format and architecture, rediscovers WSL2,
   uses wslpath to convert the Windows path, then launches via
   wsl.exe --distribution <name> --exec <absolute Linux path>.
6. OMNI tracks the Windows wsl.exe process in its process list.

Safety and limitations:
- WSL2 is **not** an OMNI sandbox; Linux programs can access mounted Windows
  drives and networks with their effective Linux/Windows privileges.
- No shell is used, but the Linux ELF can execute arbitrary code.
- Stopping wsl.exe does **not** guarantee Linux descendants are stopped.
- The hash recheck is not atomic against file replacement.
- File execution may fail due to missing Linux shared libraries, DrvFs
  mount options, executable permissions, or incompatible binaries.
- Programs requiring Linux GUI support need a separately configured WSLg.
- Only local drive paths (not UNC, device or WSL shares) are accepted.
- No automatic installation, file staging, root execution, or distribution
  configuration is performed.
- Tests mock wsl.exe; **real Windows + WSL2 interactive execution remains
  unverified** until run on a configured machine.

Development checks:
  python -m unittest discover -s tests -p test_wsl2_runtime.py -v

Microsoft WSL command reference:
https://learn.microsoft.com/en-us/windows/wsl/basic-commands
