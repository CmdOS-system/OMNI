# Evidence + serial correlation

`vm/assessment.py` validates the saved bundle and, if it contains a serial log, checks an expected nonce via `vm/guest_marker.py`. A matching marker is reported as `SERIAL_MARKER_CORRELATED_UNATTESTED`. This is only a correlation between untrusted local artifacts; it is **not independent guest attestation**, proof of a real boot, or application compatibility certification. No real QEMU integration run is performed by unit tests.
