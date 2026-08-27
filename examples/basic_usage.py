"""
Basic ToolBoundary usage -- run this file directly:

    python examples/basic_usage.py
"""

from toolboundary import (
    AccessMode,
    ApprovalRequired,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ToolPermission,
)

boundary = Boundary(
    agent_name="support-agent",
    autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
    permissions=[
        ToolPermission("read_ticket_db", access_mode=AccessMode.READ_ONLY),
        ToolPermission(
            "send_reply_email",
            access_mode=AccessMode.EXECUTE,
            max_calls_per_hour=30,
        ),
        ToolPermission(
            "issue_refund",
            access_mode=AccessMode.EXECUTE,
            max_value=100.0,
            requires_approval=True,
        ),
    ],
    blocked_operations=frozenset({"delete_ticket", "delete_customer"}),
    max_actions_per_hour=100,
    kill_switch_env="TOOLBOUNDARY_KILL_SWITCH",
)


def try_call(label: str, fn) -> None:
    print(f"\n--- {label} ---")
    try:
        fn()
        print("  -> ALLOWED")
    except ApprovalRequired as exc:
        print(f"  -> NEEDS HUMAN APPROVAL: {exc}")
    except BoundaryViolation as exc:
        print(f"  -> DENIED: {exc}")


if __name__ == "__main__":
    try_call(
        "Read ticket database (should be allowed)",
        lambda: boundary.check("read_ticket_db", access_mode=AccessMode.READ_ONLY),
    )

    try_call(
        "Send a reply email (should be allowed)",
        lambda: boundary.check("send_reply_email", access_mode=AccessMode.EXECUTE),
    )

    try_call(
        "Delete a ticket (globally blocked operation)",
        lambda: boundary.check(
            "read_ticket_db", operation="delete_ticket", access_mode=AccessMode.READ_ONLY
        ),
    )

    try_call(
        "Issue a $50 refund (under limit, but requires_approval=True)",
        lambda: boundary.check("issue_refund", access_mode=AccessMode.EXECUTE, value=50.0),
    )

    try_call(
        "Issue a $500 refund (over max_value)",
        lambda: boundary.check("issue_refund", access_mode=AccessMode.EXECUTE, value=500.0),
    )

    try_call(
        "Call an unregistered tool",
        lambda: boundary.check("wire_transfer", access_mode=AccessMode.EXECUTE),
    )

    print("\n--- Engaging kill switch ---")
    boundary.engage_kill_switch()
    try_call(
        "Read ticket database again (kill switch now engaged)",
        lambda: boundary.check("read_ticket_db", access_mode=AccessMode.READ_ONLY),
    )
