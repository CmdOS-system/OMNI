# OMNI: anti-simulation acceptance contract

This branch isolates evidence for the **existing** Rust OmniLoader. Unit tests are not proof of cross-OS application execution.

## Prohibited certification shortcuts

- No replacement of a downloaded third-party installer with a mock, custom demo, screenshot or agent-written substitute.
- No assertion of application compatibility from exit code 0, format recognition, generated JSON, or a fabricated window.
- No reporting success when a test was skipped, timed out, or ran without the expected real application.
- No accepting agent-written summaries as sole evidence.

## Required real-app evidence

1. Official or independently authenticated distribution source and immutable SHA-256 of the installer.
2. Clean disposable VM with recorded OS build, CPU architecture, graphics backend, runtime versions and isolation policy.
3. Installer execution: original on-disk hash, PID/process tree, exit status, files produced and timestamps.
4. Launch: real installed executable hash, runtime command, PID, visible window associated with that process.
5. Functional task: automation drives the actual app to produce an output file; separate checker validates contents.
6. Logs and captures exported from the VM by a verifier separate from the development agent. Preserve failure artifacts.
7. Record result as PASS, FAIL, BLOCKED or NOT_RUN. Never collapse BLOCKED/NOT_RUN into PASS.

The first CI workflow deliberately validates only the source and Rust unit tests. **It must not be represented as proof that Windows, Android, macOS or iOS applications work.**

## First real acceptance candidate

Use an official 7-Zip Windows installer on a disposable Linux VM. Pin download URL and SHA-256 before test execution. Install with a real Wine build; launch the actual installed binary; create and extract an archive using the real program; compare file hashes. A missing display or binary is BLOCKED/FAIL, never a mock success.
