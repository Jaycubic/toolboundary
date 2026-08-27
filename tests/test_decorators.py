from __future__ import annotations

import pytest

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ToolPermission,
    guarded_tool,
)


def test_guarded_function_executes_when_allowed():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
    )

    @guarded_tool(boundary, tool_name="read_db", access_mode=AccessMode.READ_ONLY)
    def read_db(query: str) -> str:
        return f"result for {query}"

    assert read_db(query="select 1") == "result for select 1"


def test_guarded_function_blocks_before_body_executes():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[],  # nothing permitted
    )
    calls = []

    @guarded_tool(boundary, tool_name="dangerous_action", access_mode=AccessMode.EXECUTE)
    def dangerous_action() -> str:
        calls.append("executed")
        return "done"

    with pytest.raises(BoundaryViolation):
        dangerous_action()

    # the real function body must never have run
    assert calls == []


def test_value_arg_is_enforced_from_call_kwargs():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE, max_value=1000.0)
        ],
    )

    @guarded_tool(
        boundary,
        tool_name="wire_transfer",
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )
    def wire_transfer(account_id: str, amount: float) -> str:
        return f"sent {amount} to {account_id}"

    assert wire_transfer(account_id="acct_1", amount=500) == "sent 500 to acct_1"

    with pytest.raises(BoundaryViolation):
        wire_transfer(account_id="acct_1", amount=50_000)
