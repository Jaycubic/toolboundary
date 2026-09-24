from __future__ import annotations

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, MessagesState, StateGraph

from toolboundary import AccessMode, AutonomyLevel, Boundary, BoundaryViolation, ToolPermission
from toolboundary.integrations.langgraph import guard_tool_node


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
        agent_name="lg-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE, max_value=1000.0),
        ],
    )
    defaults.update(overrides)
    return Boundary(**defaults)


def _tool_call_graph(node):
    """Wire a single guarded ToolNode into a minimal compiled graph.

    `ToolNode` relies on LangGraph runtime context (a config key it reads
    off the running graph), so it can't be invoked standalone -- it must be
    exercised through a compiled graph, same as it would be in real usage.
    """
    graph = StateGraph(MessagesState)
    graph.add_node("tools", node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


def _ai_message(name: str, args: dict) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": "call_1"}])


def test_guard_tool_node_allows_permitted_call():
    boundary = make_boundary()
    node = guard_tool_node([_ReadDBTool()], boundary)
    app = _tool_call_graph(node)

    result = app.invoke({"messages": [_ai_message("read_db", {"query": "select * from tickets"})]})

    assert "rows for" in result["messages"][-1].content


def test_guard_tool_node_blocks_before_real_tool_runs():
    boundary = Boundary(agent_name="lg-agent", autonomy=AutonomyLevel.AUTONOMOUS, permissions=[])
    node = guard_tool_node([_ReadDBTool()], boundary)
    app = _tool_call_graph(node)

    with pytest.raises(BoundaryViolation):
        app.invoke({"messages": [_ai_message("read_db", {"query": "select * from tickets"})]})


def test_guard_tool_node_enforces_value_arg_override():
    boundary = make_boundary()
    node = guard_tool_node(
        [_WireTransferTool()],
        boundary,
        default_access_mode=AccessMode.READ_ONLY,
        overrides={"wire_transfer": {"access_mode": AccessMode.EXECUTE, "value_arg": "amount"}},
    )
    app = _tool_call_graph(node)

    # under the limit -- allowed
    result = app.invoke(
        {"messages": [_ai_message("wire_transfer", {"account_id": "acct_1", "amount": 500})]}
    )
    assert "sent" in result["messages"][-1].content

    # over the limit -- denied, and the real _run must not execute
    with pytest.raises(BoundaryViolation):
        app.invoke(
            {"messages": [_ai_message("wire_transfer", {"account_id": "acct_1", "amount": 50_000})]}
        )


def test_guard_tool_node_wraps_multiple_tools():
    boundary = make_boundary()
    node = guard_tool_node(
        [_ReadDBTool(), _WireTransferTool()],
        boundary,
        default_access_mode=AccessMode.READ_ONLY,
        overrides={"wire_transfer": {"access_mode": AccessMode.EXECUTE, "value_arg": "amount"}},
    )
    app = _tool_call_graph(node)

    read_result = app.invoke({"messages": [_ai_message("read_db", {"query": "x"})]})
    assert "rows for" in read_result["messages"][-1].content

    transfer_result = app.invoke(
        {"messages": [_ai_message("wire_transfer", {"account_id": "a", "amount": 100})]}
    )
    assert "sent" in transfer_result["messages"][-1].content
