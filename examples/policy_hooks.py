"""
ToolBoundary policy-hook examples -- run this file directly:

    python examples/policy_hooks.py

A policy hook is a plain callable ``(CallContext) -> str | None`` you pass to
``Boundary(policy_hooks=[...])``. Returning ``None`` allows the call; returning
a string denies it with that reason. Hooks are the extension point for custom
logic that doesn't fit the declarative ``Boundary`` fields.

Every example below uses only the Python standard library (or a local
dependency-free object), so they stay optional and dependency-light. The core
``toolboundary`` install already includes everything needed to run them.
"""

from __future__ import annotations

import datetime
import ipaddress

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    CallContext,
    ExecutionRecord,
    FrozenToolCall,
    LocalDecision,
    ProviderGrant,
    ProviderMode,
    ProviderReceipt,
    ToolPermission,
)


def _try(label: str, boundary: Boundary, tool: str = "read_db", **kwargs) -> None:
    print(f"\n--- {label} ---")
    try:
        boundary.check(tool, access_mode=AccessMode.READ_ONLY, **kwargs)
        print("  -> ALLOWED")
    except BoundaryViolation as exc:
        print(f"  -> DENIED: {exc}")


def _base_boundary(**overrides) -> Boundary:
    defaults = dict(
        agent_name="demo-agent",
        autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
        permissions=[
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission("send_email", access_mode=AccessMode.EXECUTE),
        ],
    )
    defaults.update(overrides)
    return Boundary(**defaults)


# ---------------------------------------------------------------------------
# 1. Time-of-day policy
# ---------------------------------------------------------------------------
def business_hours_only(ctx: CallContext, *, start_hour: int = 9, end_hour: int = 18) -> str | None:
    """Deny any governed call outside the given local hour window."""
    now = datetime.datetime.now()
    hour = now.hour
    if start_hour <= hour < end_hour:
        return None
    return (
        f"outside business hours ({start_hour:02d}:00-{end_hour:02d}:00); "
        f"current local hour is {hour:02d}"
    )


def demonstrate_time_of_day() -> None:
    boundary = _base_boundary(policy_hooks=[business_hours_only])
    # This either allows or denies depending on when you run it. The point is
    # that the hook sees the CallContext and makes the decision locally.
    _try("Time-of-day gate (result depends on the clock when you run it)", boundary)


# ---------------------------------------------------------------------------
# 2. Environment restriction via a hook
# ---------------------------------------------------------------------------
def restrict_writes_in_production(ctx: CallContext) -> str | None:
    """Deny write/execute mode calls when running in the PRODUCTION environment.

    ``Boundary`` already ships a declarative ``allowed_environments`` field; this
    hook shows how to express the same idea with finer control (only EXECUTE
    mode is blocked, READ still flows) without changing the Boundary signature.
    """
    env = ctx.metadata.get("environment", "PRODUCTION")
    write_modes = (AccessMode.WRITE, AccessMode.EXECUTE, AccessMode.ADMIN)
    if env == "PRODUCTION" and ctx.access_mode in write_modes:
        return f"{ctx.access_mode.value} operations are disabled in {env}"
    return None


def demonstrate_environment() -> None:
    boundary = _base_boundary(policy_hooks=[restrict_writes_in_production])
    _try(
        "Read in PRODUCTION (allowed -- READ is not restricted)",
        boundary,
        metadata={"environment": "PRODUCTION"},
    )
    # The EXECUTE path must pass access_mode explicitly (the hook keys off it):
    try:
        boundary.check(
            "send_email",
            access_mode=AccessMode.EXECUTE,
            metadata={"environment": "PRODUCTION"},
        )
        print("  -> unexpectedly ALLOWED")
    except BoundaryViolation as exc:
        print(f"  -> DENIED: {exc}")


# ---------------------------------------------------------------------------
# 3. Network-aware check
# ---------------------------------------------------------------------------
def deny_egress_to_private_ranges(ctx: CallContext, *, target_key: str = "remote_ip") -> str | None:
    """Deny calls whose metadata carries a destination IP in a private/loopback range.

    The agent (or the tool it is about to call) puts the target address in
    ``ctx.metadata``; the hook makes a local, dependency-free decision using
    only the standard library.
    """
    raw = ctx.metadata.get(target_key)
    if raw is None:
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return f"unparseable {target_key!r} value {raw!r}"
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
        return f"egress to {ip} is not permitted"
    return None


def demonstrate_network_aware() -> None:
    boundary = _base_boundary(policy_hooks=[deny_egress_to_private_ranges])
    _try(
        "Public destination 1.1.1.1 (allowed)",
        boundary,
        metadata={"remote_ip": "1.1.1.1"},
    )
    _try(
        "Private destination 10.0.0.5 (denied)",
        boundary,
        metadata={"remote_ip": "10.0.0.5"},
    )


# ---------------------------------------------------------------------------
# 4. External policy engine (dependency-light EvidenceProvider)
# ---------------------------------------------------------------------------
class InMemoryPolicyEngine:
    """A tiny local stand-in for an external policy engine.

    It satisfies the ``EvidenceProvider`` protocol with no third-party
    dependency: it decides on a hardcoded rule set and records decisions in
    memory. In production you would swap this for a network client to a
    real policy service; the boundary code does not change.
    """

    def __init__(self, *, name: str = "in-memory-engine") -> None:
        self.name = name
        self.records: list[ExecutionRecord] = []

    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        # Example rule: never authorize the wire_transfer tool at all.
        if call.tool_name == "wire_transfer":
            return ProviderGrant(
                allowed=False,
                provider=self.name,
                reason="wire_transfer is not authorized by external policy",
            )
        return ProviderGrant(allowed=True, provider=self.name)

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        self.records.append(execution)
        return ProviderReceipt(recorded=True, provider=self.name)


def demonstrate_external_policy_engine() -> None:
    engine = InMemoryPolicyEngine()
    boundary = _base_boundary(
        permissions=[
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE),
        ],
        provider=engine,
        provider_mode=ProviderMode.ENFORCE,
    )
    # A locally-allowed tool still has to pass the provider gate.
    try:
        boundary.authorize_call(
            tool_name="wire_transfer",
            arguments={"amount": 100},
            access_mode=AccessMode.EXECUTE,
        )
        print("  -> unexpectedly ALLOWED")
    except Exception as exc:  # ProviderAuthorizationDenied is the expected path.
        print(f"  -> DENIED by external engine: {exc}")

    # A read that the engine allows round-trips cleanly.
    ctx = boundary.authorize_call(
        tool_name="read_db",
        arguments={},
        access_mode=AccessMode.READ_ONLY,
    )
    provider_name = ctx.provider_grant.provider if ctx.provider_grant else "n/a"
    print(f"  -> read_db authorized by {provider_name}")


def main() -> None:
    print("ToolBoundary policy-hook examples")
    demonstrate_time_of_day()
    demonstrate_environment()
    demonstrate_network_aware()
    demonstrate_external_policy_engine()
    print("\nAll examples ran.")


if __name__ == "__main__":
    main()
