# OMNI Execution Environment Contract v1

The module `omni.environment` transforms a Capability Planner result into a deterministic execution-environment proposal. It **does not** launch programs, provision containers, configure namespaces, or claim sandboxing.

Fields include source SHA-256, selected runtime, explicitly requested permissions, memory/CPU/wall-time limits, blocked reasons, and a deterministic contract hash. Every result is `BLOCKED_PENDING_ISOLATION`, with `execution_authorized=false` and `isolation_verified=false`.

Future adapters must enforce policy and produce independent evidence before a separate execution authorization step can be implemented. A declared limit is not an enforced limit.

Test with `python3 -m unittest discover -s tests -v`.
