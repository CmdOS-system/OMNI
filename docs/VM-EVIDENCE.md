# VM evidence bundles

`vm/evidence.py` saves a report and optional serial log with SHA-256 manifest in a new local directory. It refuses overwrite, detects simple tampering and never certifies boot, isolation or app compatibility. This is **not cryptographic attestation**, not append-only storage, not an independent witness, and not sufficient for proving a real VM. A malicious local actor can rewrite both files and manifest. `vm/boot.py` does not yet invoke this module automatically; integration and authentic guest evidence remain pending.
