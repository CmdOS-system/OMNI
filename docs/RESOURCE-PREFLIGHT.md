OMNI resource preflight v1

Read-only checks for cgroup v2 controllers, cpu.max, memory.max and memory.events. No cgroup is created or modified, and no resource limits are enforced by OMNI. Presence of controller files does not imply delegation or write permission. Actual resource enforcement requires a dedicated cgroup, verified memory.max and cpu.max writes, process placement, measured events and cleanup. This preflight always returns execution_authorized=false.
