"""
Reproduces the performance numbers quoted in docs/API.md and the README.

    python examples/benchmark.py
"""

import time

from toolboundary import AccessMode, AutonomyLevel, Boundary, ToolPermission
from toolboundary.audit import AuditTrail
from toolboundary.tokens import TokenIssuer

N = 20_000


def bench(label: str, fn, n: int = N) -> None:
    # warm-up
    for _ in range(min(100, n)):
        fn()
    start = time.perf_counter()
    for _ in range(n):
        fn()
    elapsed = time.perf_counter() - start
    per_call_us = (elapsed / n) * 1_000_000
    print(f"{label:55s} {per_call_us:8.2f} us/call   ({n} calls in {elapsed*1000:.1f}ms)")


def main() -> None:
    print(f"ToolBoundary benchmark -- {N} iterations per test\n")

    # 1. Boundary.check() -- the core in-process decision path
    boundary = Boundary(
        agent_name="bench-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        max_actions_per_hour=10_000_000,
        audit=AuditTrail(sinks=[]),  # isolate decision-engine cost from logging I/O
    )
    bench(
        "Boundary.check() [ALLOW path]",
        lambda: boundary.check("read_db", access_mode=AccessMode.READ_ONLY),
    )

    # 2. Boundary.check() on a denial path (exception construction has a cost too)
    boundary_deny = Boundary(
        agent_name="bench-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[],
        audit=AuditTrail(sinks=[]),
    )

    def deny_call():
        try:
            boundary_deny.check("unregistered_tool", access_mode=AccessMode.READ_ONLY)
        except Exception:
            pass

    bench("Boundary.check() [DENY path, incl. exception]", deny_call)

    # 3. Token issue + verify (the network-enforcement handoff cost)
    issuer = TokenIssuer(secret="bench-secret", ttl_seconds=30)

    def issue_and_verify():
        token = issuer.issue(agent_name="agent-1", tool_name="crm_api", operation="READ")
        issuer.verify(token, expected_agent_name="agent-1", expected_tool_name="crm_api")

    bench("TokenIssuer.issue() + .verify() combined", issue_and_verify)

    # 4. check_and_authorize() -- the full path used before a network-enforced call
    boundary_with_issuer = Boundary(
        agent_name="bench-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("crm_api", access_mode=AccessMode.READ_ONLY)],
        token_issuer=TokenIssuer(secret="bench-secret-2", ttl_seconds=30),
        audit=AuditTrail(sinks=[]),
    )
    bench(
        "Boundary.check_and_authorize() [full ALLOW + token issuance]",
        lambda: boundary_with_issuer.check_and_authorize("crm_api", access_mode=AccessMode.READ_ONLY),
    )

    print(
        "\nFor context: a single network round-trip to a nearby service is "
        "typically 500-2000+ us. ToolBoundary's own overhead is a small "
        "fraction of that, even before accounting for the tool call itself."
    )


if __name__ == "__main__":
    main()
