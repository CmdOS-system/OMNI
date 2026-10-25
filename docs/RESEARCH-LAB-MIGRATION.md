# Research Lab v0.12 migration

The first migrated component is the QEMU/KVM prerequisites gate (`vm/prerequisites.py`), adapted from `lab/omni_vm_gate.py` in Research Lab v0.12. The test fixtures are synthetic and **do not** prove real VM boot or compatibility.

Remaining Research Lab components (genome, planner, runtime, capabilities, audit, witness, lineage, execution trace, VM overlay and proof) are **not yet migrated**. Avoid declaring full v0.12 integration until each module is ported and verified in CI.

Even a successful prerequisites report is `PREREQUISITES_ONLY`, never `CERTIFIED`.
