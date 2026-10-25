# OMNI disposable overlay gate

`vm/overlay.py` checks SHA-256 of a trusted image, calls installed `qemu-img` without shell interpolation, creates a temporary QCOW2 overlay, verifies its backing file, and cleans up. It **does not boot a VM, establish a sandbox, or certify third-party software**. This operation is not safe for arbitrary untrusted disk images; image inspection must run in a separately isolated environment. A concurrent modification of the base is not prevented by before/after hashing. Unit tests use fixtures and are not real QEMU integration tests.
