from __future__ import annotations

import pytest
from crewai.tools import BaseTool

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ToolPermission,
)
from toolboundary.integrations.crewai import guard_tool, guard_tools


class ReadDBTool(BaseTool):
    name: str = "read_db"
    description: str = "Read data from the database."

    executed: bool = False

    def _run(self, query: str) -> str:
        self.executed = True
        return f"results for: {query}"


class WireTransferTool(BaseTool):
    name: str = "wire_transfer"
    description: str = "Transfer money."

    executed: bool = False

    def _run(self, account_id: str, amount: float) -> str:
        self.executed = True
        return f"transferred {amount} to {account_id}"


class AsyncTool(BaseTool):
    name: str = "async_tool"
    description: str = "An async test tool."

    executed: bool = False

    def _run(self, value: str) -> str:
        self.executed = True
        return f"sync:{value}"

    async def _arun(self, value: str) -> str:
        self.executed = True
        return f"async:{value}"


def make_boundary() -> Boundary:
    return Boundary(
        agent_name="crewai-test-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission(
                tool_name="read_db",
                access_mode=AccessMode.READ_ONLY,
            ),
            ToolPermission(
                tool_name="wire_transfer",
                access_mode=AccessMode.EXECUTE,
                max_value=1000,
            ),
            ToolPermission(
                tool_name="async_tool",
                access_mode=AccessMode.READ_ONLY,
            ),
        ]
    )


def test_allowed_call_reaches_real_crewai_tool():
    boundary = make_boundary()
    tool = ReadDBTool()

    guarded = guard_tool(tool, boundary)

    result = guarded.run(query="SELECT * FROM users")

    assert result == "results for: SELECT * FROM users"
    assert tool.executed is True


def test_denied_call_is_blocked_before_real_tool_runs():
    boundary = make_boundary()
    tool = WireTransferTool()

    guarded = guard_tool(
        tool,
        boundary,
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )

    with pytest.raises(BoundaryViolation):
        guarded.run(account_id="acct-123", amount=5000)

    assert tool.executed is False


def test_value_limit_allows_valid_transfer():
    boundary = make_boundary()
    tool = WireTransferTool()

    guarded = guard_tool(
        tool,
        boundary,
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )

    result = guarded.run(account_id="acct-123", amount=500)

    assert result == "transferred 500.0 to acct-123"
    assert tool.executed is True


@pytest.mark.asyncio
async def test_async_execution():
    boundary = make_boundary()
    tool = AsyncTool()

    guarded = guard_tool(tool, boundary)

    result = await guarded.arun(value="hello")

    assert result == "async:hello"
    assert tool.executed is True


def test_guard_tools_wraps_multiple_tools():
    boundary = make_boundary()

    read_tool = ReadDBTool()
    transfer_tool = WireTransferTool()

    guarded = guard_tools(
        [read_tool, transfer_tool],
        boundary,
        access_mode=AccessMode.READ_ONLY,
        overrides={
            "wire_transfer": {
                "access_mode": AccessMode.EXECUTE,
                "value_arg": "amount",
            }
        },
    )

    assert len(guarded) == 2
    assert guarded[0].name == "read_db"
    assert guarded[1].name == "wire_transfer"

    result = guarded[1].run(account_id="acct-123", amount=500)

    assert result == "transferred 500.0 to acct-123"
    assert transfer_tool.executed is True