from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import BaseTool

from toolboundary import AccessMode, AutonomyLevel, Boundary, BoundaryViolation, ToolPermission
from toolboundary.integrations.langchain import guard_tool, guard_tools


class _ReadDBTool(BaseTool):
    name: str = "read_db"
    description: str = "Reads from the database"

    def _run(self, query: str) -> str:
        return f"rows for {query}"


class _WireTransferTool(BaseTool):
    name: str = "wire_transfer"
    description: str = "Transfers money"

    def _run(self, account_id: str, amount: float) -> str:
        return f"sent {amount} to {account_id}"


def make_boundary(**overrides) -> Boundary:
    defaults = dict(
        agent_name="lc-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE, max_value=1000.0),
        ],
    )
    defaults.update(overrides)
    return Boundary(**defaults)


def test_guard_tool_allows_permitted_call():
    boundary = make_boundary()
    guarded = guard_tool(_ReadDBTool(), boundary, access_mode=AccessMode.READ_ONLY)
    result = guarded.run({"query": "select * from tickets"})
    assert "rows for" in result


def test_guard_tool_blocks_before_real_tool_runs():
    boundary = Boundary(agent_name="lc-agent", autonomy=AutonomyLevel.AUTONOMOUS, permissions=[])
    guarded = guard_tool(_ReadDBTool(), boundary, access_mode=AccessMode.READ_ONLY)
    with pytest.raises(BoundaryViolation):
        guarded.run({"query": "select * from tickets"})


def test_guard_tool_enforces_value_arg():
    boundary = make_boundary()
    guarded = guard_tool(
        _WireTransferTool(),
        boundary,
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )
    # under the limit -- allowed
    result = guarded.run({"account_id": "acct_1", "amount": 500})
    assert "sent" in result

    # over the limit -- denied, and the real _run must not execute
    with pytest.raises(BoundaryViolation):
        guarded.run({"account_id": "acct_1", "amount": 50_000})


def test_guard_tools_bulk_wrapping_with_overrides():
    boundary = make_boundary()
    tools = guard_tools(
        [_ReadDBTool(), _WireTransferTool()],
        boundary,
        default_access_mode=AccessMode.READ_ONLY,
        overrides={
            "wire_transfer": {"access_mode": AccessMode.EXECUTE, "value_arg": "amount"},
        },
    )
    names = {t.name for t in tools}
    assert names == {"read_db", "wire_transfer"}

    read_tool = next(t for t in tools if t.name == "read_db")
    transfer_tool = next(t for t in tools if t.name == "wire_transfer")

    assert "rows for" in read_tool.run({"query": "x"})
    assert "sent" in transfer_tool.run({"account_id": "a", "amount": 100})
    with pytest.raises(BoundaryViolation):
        transfer_tool.run({"account_id": "a", "amount": 999_999})
