# Integrated QEMU capture

`vm/capture.py` ties together opt-in process launch and evidence bundle persistence. It uses QEMU's disabled-network/no-host-sharing command from `vm/boot.py`, captures serial output if generated and hashes QEMU stderr. It does not currently persist stderr bytes; its hash alone is not enough to reconstruct diagnostics. Evidence is local and not independently attested. A fake executable in unit tests exercises only the harness. A real guest image, isolation and guest-side attestation are still required before claiming real VM boot.
