# Linux isolation preflight

`python3 -m omni.linux_isolation` checks whether the host exposes Linux namespace, cgroup v2 and seccomp-related interfaces and whether bwrap/unshare binaries are on PATH.

These checks **do not** establish that user namespaces are permitted, seccomp is active, Landlock is supported for a given ABI, cgroup limits are enforced, or a sandbox is secure. Presence is not functionality. The adapter performs no execution, no filesystem mutation, and no sandbox creation.

`assess_environment` joins this preflight to the execution-environment contract and always returns `BLOCKED_PENDING_ENFORCEMENT`. A future enforcing backend needs tests that prove namespace boundaries, mount isolation, network denial, resource limits and cleanup.
