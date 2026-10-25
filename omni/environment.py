"""OMNI execution environment contracts. Pure planning, no sandbox creation or execution."""
import hashlib
import json

ALLOWED_RUNTIMES = frozenset({"wine", "linux-native", "qemu-system-x86_64", "wasmtime"})
ALLOWED_PERMISSIONS = frozenset({"network", "home_read", "home_write", "clipboard", "microphone", "camera"})
DEFAULT_LIMITS = {"memory_mib": 512, "cpu_seconds": 60, "wall_seconds": 120}
MAX_LIMITS = {"memory_mib": 8192, "cpu_seconds": 3600, "wall_seconds": 7200}

def build_environment(plan, runtime, *, permissions=(), limits=None):
    """Produce a deterministic, deny-by-default execution proposal.

    This contract is NOT an execution authorization or isolation guarantee.
    """
    if plan.get("schema") != "omni.capability_plan.v1" or plan.get("status") != "PREFLIGHT_ONLY":
        raise ValueError("unsupported capability plan")
    if runtime not in ALLOWED_RUNTIMES:
        raise ValueError("unsupported runtime")
    matches = [o for o in plan.get("options", []) if o.get("runtime") == runtime]
    if len(matches) != 1:
        raise ValueError("runtime is not a candidate for this file")
    requested = set(permissions)
    if len(requested) != len(tuple(permissions)) or not requested <= ALLOWED_PERMISSIONS:
        raise ValueError("duplicate or unknown permission")
    resources = dict(DEFAULT_LIMITS)
    if limits is not None:
        if not isinstance(limits, dict) or not set(limits) <= set(DEFAULT_LIMITS):
            raise ValueError("unknown resource limit")
        resources.update(limits)
    if any(type(resources[k]) is not int or not (1 <= resources[k] <= MAX_LIMITS[k]) for k in resources):
        raise ValueError("invalid resource limits")
    candidate = matches[0]
    reasons = list(candidate.get("reasons", []))
    if requested:
        reasons.append("requested_permissions_require_enforced_policy")
    reasons.append("isolation_backend_not_verified")
    payload = {
        "schema": "omni.environment.v1",
        "input_sha256": plan["input"]["sha256"],
        "input_format": plan["input"]["format"],
        "runtime": runtime,
        "runtime_available": bool(candidate["available"]),
        "requested_permissions": sorted(requested),
        "limits": resources,
        "preflight_eligible": bool(candidate["eligible_for_preflight"]),
        "reasons": sorted(set(reasons)),
        "status": "BLOCKED_PENDING_ISOLATION",
        "execution_authorized": False,
        "execution_performed": False,
        "isolation_verified": False,
    }
    payload["contract_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload
