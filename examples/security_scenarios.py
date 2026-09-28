"""
End-to-end AI-agent security scenarios with ToolBoundary -- run directly:

    python examples/security_scenarios.py

This example walks through the six controls an agent boundary should demonstrate
before it is allowed to touch anything real:

  1. read-only tools            -- may read, may never mutate
  2. destructive tool denial    -- deletes are refused even for "trusted" tools
  3. value ceilings             -- money/quantity capped per call
  4. rate limits                -- per-hour call and action budgets
  5. approval-required ops      -- sensitive calls pause for a human
  6. emergency kill switch      -- one flip halts everything, right now

Everything here is local and deterministic: no network, no provider, no DB.
"""

from toolboundary import (
    AccessMode,
    ApprovalRequired,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ToolPermission,
)

# ---------------------------------------------------------------------------
# 1. Declare the boundary once, at startup, in plain Python.
# ---------------------------------------------------------------------------
boundary = Boundary(
    agent_name="ops-assistant",
    autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
    permissions=[
        # 1. Read-only tool: can read, can never write.
        ToolPermission("get_metrics", access_mode=AccessMode.READ_ONLY),

        # 3. Value ceiling: refunds above $100 are refused outright.
        # 5. Approval: refunds at or below the ceiling still pause for a human.
        ToolPermission(
            "issue_refund",
            access_mode=AccessMode.EXECUTE,
            max_value=100.0,
            requires_approval=True,
        ),

        # 4. Rate limit: at most 30 emails per hour, 100 actions/hour overall.
        ToolPermission(
            "send_email",
            access_mode=AccessMode.EXECUTE,
            max_calls_per_hour=30,
        ),

        # A normal write tool, used to show per-hour action budgeting below.
        ToolPermission("restart_service", access_mode=AccessMode.EXECUTE),
    ],
    # 2. Destructive operations denied for EVERY tool, blocked always wins.
    blocked_operations=frozenset({"delete_user", "delete_backup", "drop_table"}),
    max_actions_per_hour=100,
    # 6. Kill switch: flip in-process, or let an operator halt via env var.
    kill_switch_env="TOOLBOUNDARY_KILL_SWITCH",
)


def attempt(label: str, fn) -> None:
    """Run one guarded call and print the verdict in a uniform way."""
    print(f"\n--- {label} ---")
    try:
        fn()
        print("  -> ALLOWED")
    except ApprovalRequired as exc:
        print(f"  -> NEEDS HUMAN APPROVAL: {exc}")
    except BoundaryViolation as exc:
        print(f"  -> DENIED: {exc}")


if __name__ == "__main__":
    # 1. Read-only ---------------------------------------------------------
    attempt(
        "[1] Read metrics (allowed)",
        lambda: boundary.check("get_metrics", access_mode=AccessMode.READ_ONLY),
    )
    attempt(
        "[1] Write through a read-only tool (denied)",
        lambda: boundary.check("get_metrics", access_mode=AccessMode.EXECUTE),
    )

    # 2. Destructive tool denial ------------------------------------------
    attempt(
        "[2] Delete a user (globally blocked)",
        lambda: boundary.check(
            "get_metrics", operation="delete_user", access_mode=AccessMode.READ_ONLY
        ),
    )
    attempt(
        "[2] Restart a service (allowed -- not destructive)",
        lambda: boundary.check("restart_service", access_mode=AccessMode.EXECUTE),
    )

    # 3. Value ceiling + 5. approval-required ------------------------------
    attempt(
        "[3/5] Refund $50 (under ceiling, still needs approval)",
        lambda: boundary.check("issue_refund", access_mode=AccessMode.EXECUTE, value=50.0),
    )
    attempt(
        "[3] Refund $500 (over ceiling, refused)",
        lambda: boundary.check("issue_refund", access_mode=AccessMode.EXECUTE, value=500.0),
    )

    # 4. Rate limits -------------------------------------------------------
    print("\n--- [4] Send 32 emails: only 30/hour are permitted ---")
    allowed = denied = 0
    for i in range(1, 33):
        try:
            boundary.check("send_email", access_mode=AccessMode.EXECUTE)
            allowed += 1
        except BoundaryViolation:
            denied += 1
    print(f"  -> ALLOWED {allowed}, DENIED {denied} (expected 30 / 2)")

    # An unregistered tool is refused by default.
    attempt(
        "[*] Call an unregistered tool (denied)",
        lambda: boundary.check("wire_transfer", access_mode=AccessMode.EXECUTE),
    )

    # 6. Emergency kill switch --------------------------------------------
    print("\n--- [6] Engaging emergency kill switch ---")
    boundary.engage_kill_switch()
    attempt(
        "[6] Read metrics after kill switch (denied)",
        lambda: boundary.check("get_metrics", access_mode=AccessMode.READ_ONLY),
    )
