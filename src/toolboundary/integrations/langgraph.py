"""
toolboundary.integrations.langgraph
-------------------------------------
Wraps LangGraph tools so that ToolBoundary's boundary check runs inside
LangGraph's own tool-execution path -- the `ToolNode` a compiled graph
actually calls when the model requests a tool call -- not as a step the
graph author has to remember to call.

Why this matters (the "bypass" problem)
----------------------------------------
If ToolBoundary were only a decorator you *could* apply to your own tool
functions, a compromised or carelessly-written graph node could still
import the underlying tool and call it directly, skipping ToolBoundary
entirely.

LangGraph tools are the same `langchain_core.tools.BaseTool` objects that
`toolboundary.integrations.langchain` already wraps, and LangGraph's
prebuilt `ToolNode` invokes them through `.invoke()` / `.ainvoke()` --
the exact call site that wrapping already covers. This module reuses that
wrapping (`guard_tool` / `guard_tools`) and adds one LangGraph-specific
convenience, `guard_tool_node`, which returns an already-guarded `ToolNode`
so the *wrapped* tools -- not the raw ones -- are what gets compiled into
the graph.

This does not solve every bypass vector (see the "Known Limitations"
section in the README -- e.g. a graph node with independent network access
that ignores the tool list entirely is out of scope for an in-process
library). It closes the most common one: the graph's own tool-calling node
invoking a permitted-looking tool for an unpermitted action.
"""

from __future__ import annotations

from typing import Any

from ..boundary import Boundary
from ..enums import AccessMode
from ..exceptions import ApprovalRequired, BoundaryViolation
from .langchain import guard_tool, guard_tools

try:
    from langchain_core.tools import BaseTool
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "toolboundary.integrations.langgraph requires the 'langchain-core' package. "
        "Install it with: pip install toolboundary[langgraph]"
    ) from exc

try:
    from langgraph.prebuilt import ToolNode
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "toolboundary.integrations.langgraph requires the 'langgraph' package. "
        "Install it with: pip install toolboundary[langgraph]"
    ) from exc


def guard_tool_node(
    tools: list[BaseTool],
    boundary: Boundary,
    *,
    default_access_mode: AccessMode = AccessMode.READ_ONLY,
    overrides: dict[str, dict[str, Any]] | None = None,
    **tool_node_kwargs: Any,
) -> ToolNode:
    """
    Build a LangGraph `ToolNode` whose tools are already guarded by `boundary`.

    This is the LangGraph equivalent of
    `toolboundary.integrations.langchain.guard_tools`: every tool is wrapped
    so the boundary check runs -- and can raise `BoundaryViolation` or
    `ApprovalRequired` -- before the tool's real implementation executes.
    Add the returned node to your graph in place of a plain `ToolNode`.

    `overrides` lets you specify per-tool kwargs (by tool.name), same as
    `guard_tools`; any extra keyword arguments are forwarded to `ToolNode`
    itself (e.g. `handle_tool_errors`).

    >>> from langgraph.graph import StateGraph, MessagesState
    >>> from toolboundary.integrations.langgraph import guard_tool_node
    >>>
    >>> tool_node = guard_tool_node(
    ...     [read_db_tool, send_email_tool, wire_transfer_tool],
    ...     boundary,
    ...     default_access_mode=AccessMode.READ_ONLY,
    ...     overrides={
    ...         "send_email_tool": {"access_mode": AccessMode.EXECUTE},
    ...         "wire_transfer_tool": {"access_mode": AccessMode.EXECUTE, "value_arg": "amount"},
    ...     },
    ... )
    >>> graph = StateGraph(MessagesState)
    >>> graph.add_node("tools", tool_node)

    A denied call raises out of the node -- the graph is expected to route
    that exception the same way it would any other node failure (e.g. via
    a wrapping try/except in a custom node, or a graph-level error branch).
    ToolBoundary intentionally does not swallow denials into a tool
    message: a `BoundaryViolation` should be loud, not a string the model
    can rationalize its way around.
    """
    guarded_tools = guard_tools(
        tools,
        boundary,
        default_access_mode=default_access_mode,
        overrides=overrides,
    )
    return ToolNode(guarded_tools, **tool_node_kwargs)


__all__ = [
    "guard_tool",
    "guard_tools",
    "guard_tool_node",
    "ApprovalRequired",
    "BoundaryViolation",
]
