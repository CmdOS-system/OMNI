# OMNI Windows native launcher (experimental)

The Windows desktop library can explicitly open inspected **Windows PE .exe**
applications. Select a file, add it to the library, select its row, and click
**Abrir .exe de Windows**. A warning requires affirmative consent.

The launcher:
- Requires Windows and a supported native architecture (x86 or x86_64 on x86_64;
  x86 on x86; ARM64 on ARM64). This is a conservative support matrix.
- Rejects DLLs, ELF, WASM, missing hashes and UNC paths.
- Reinspects the file and compares SHA-256, format and architecture before launch.
- Uses subprocess.Popen with shell=False and the application's directory as cwd.
- Displays the direct process PID and eventual exit status.

**Security warning:** This is direct Windows execution, not a sandbox or
cross-OS compatibility. Applications inherit the user's permissions, may
access files and network, and may spawn child processes that are not tracked.
Hash reinspection does not prevent a concurrent file replacement (TOCTOU).
Do not open untrusted applications. No elevated privileges are requested.
Windows native .exe launch is not evidence of Linux/macOS/Android support.

CI tests the launcher logic with a mocked process. The GUI is packaged by
PyInstaller on a Windows runner, but interactive desktop execution still
requires manual testing on a real Windows machine.
