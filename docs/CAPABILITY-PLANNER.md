# OMNI Capability Planner (experimental)

Run `python3 -m omni.planner /path/to/file` to inspect a local file and list detected runtime availability.

**Preflight only.** The planner never launches programs, grants execution permission, or certifies compatibility. ELF and PE checks are shallow structural checks, not full executable validation. QEMU availability does not mean a bootable guest image is configured; Proton is explicitly blocked pending an adapter. Runtime detection does not establish isolation.

Unit tests: `python3 -m unittest discover -s tests -v`.
