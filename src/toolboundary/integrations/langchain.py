"""
toolboundary.integrations.langchain
------------------------------------
Wraps LangChain tools so that ToolBoundary's boundary check runs inside
LangChain's own tool-execution path (`_run` / `_arun`), not as a step the
agent's reasoning loop has to remember to call.

Why this matters (the "bypass" problem)
----------------------------------------
If ToolBoundary were only a decorator you *could* apply to your own tool
functions, a compromised or carelessly-written agent could still import
the underlying tool and call it directly, skipping ToolBoundary entirely.

By wrapping the LangChain `Tool` / `BaseTool` object itself -- the object
the AgentExecutor actually invokes when the LLM decides to call a tool --
the boundary check becomes part of the tool's identity, not a convention
the calling code has to opt into. As long as the agent is given the
*wrapped* tool (instead of the raw one) when it is constructed, every
invocation the LLM triggers passes through ToolBoundary first.

This does not solve every bypass vector (see the "Known Limitations"
section in the README -- e.g. an agent with independent network access
that ignores its LangChain tool list entirely is out of scope for an
in-process library). It closes the most common one: the agent's own
tool-calling loop invoking a permitted-looking tool for an
unpermitted action.
"""

from __future__ import annotations

from typing import Any, Optional, Type  # noqa: UP035

from ..boundary import Boundary
from ..enums import AccessMode
from ..exceptions import ApprovalRequired, BoundaryViolation

try:
    from langchain_core.tools import BaseTool
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "toolboundary.integrations.langchain requires the 'langchain-core' package. "
        "Install it with: pip install toolboundary[langchain]"
    ) from exc


def guard_tool(
    tool: BaseTool,
    boundary: Boundary,
    *,
    tool_name: str | None = None,
    operation: str | None = None,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    value_arg: str | None = None,
    record_count_arg: str | None = None,
) -> BaseTool:
    """
    Return a new BaseTool that enforces `boundary` before delegating to `tool`.

    Use this on every tool before handing the tool list to your
    AgentExecutor / LangGraph node, e.g.:

    >>> raw_tools = [read_db_tool, send_email_tool, wire_transfer_tool]
    >>> guarded_tools = [
    ...     guard_tool(read_db_tool, boundary, access_mode=AccessMode.READ_ONLY),
    ...     guard_tool(send_email_tool, boundary, access_mode=AccessMode.EXECUTE),
    ...     guard_tool(
    ...         wire_transfer_tool, boundary,
    ...         access_mode=AccessMode.EXECUTE, value_arg="amount",
    ...     ),
    ... ]
    >>> agent_executor = AgentExecutor(agent=agent, tools=guarded_tools)
    """
    resolved_name = tool_name or tool.name

    class _GuardedTool(BaseTool):
        name: str = tool.name
        description: str = tool.description
        args_schema: Optional[Type[Any]] = getattr(tool, "args_schema", None)  # noqa: UP006, UP045
        return_direct: bool = getattr(tool, "return_direct", False)

        def _evaluate(self, kwargs: dict[str, Any]) -> None:
            resolved_value = kwargs.get(value_arg) if value_arg else None
            resolved_records = kwargs.get(record_count_arg) if record_count_arg else None
            boundary.check(
                resolved_name,
                operation=operation,
                access_mode=access_mode,
                value=resolved_value,
                record_count=resolved_records,
                metadata={"langchain_tool": tool.name},
            )

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            self._evaluate(kwargs)
            return tool._run(*args, **kwargs)  # noqa: SLF001

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            self._evaluate(kwargs)
            arun = getattr(tool, "_arun", None)
            if arun is not None:
                return await arun(*args, **kwargs)
            # Fall back to sync _run if the wrapped tool has no async implementation
            return tool._run(*args, **kwargs)  # noqa: SLF001

    return _GuardedTool()


def guard_tools(
    tools: list[BaseTool],
    boundary: Boundary,
    *,
    default_access_mode: AccessMode = AccessMode.READ_ONLY,
    overrides: dict[str, dict[str, Any]] | None = None,
) -> list[BaseTool]:
    """
    Convenience wrapper to guard an entire tool list at once.

    `overrides` lets you specify per-tool kwargs (by tool.name) that get
    passed to `guard_tool`, e.g.:

    >>> guard_tools(
    ...     [read_tool, write_tool, transfer_tool],
    ...     boundary,
    ...     overrides={
    ...         "write_tool": {"access_mode": AccessMode.WRITE},
    ...         "transfer_tool": {"access_mode": AccessMode.EXECUTE, "value_arg": "amount"},
    ...     },
    ... )
    """
    overrides = overrides or {}
    result: list[BaseTool] = []
    for tool in tools:
        kwargs: dict[str, Any] = {"access_mode": default_access_mode}
        kwargs.update(overrides.get(tool.name, {}))
        result.append(guard_tool(tool, boundary, **kwargs))
    return result


__all__ = ["guard_tool", "guard_tools", "ApprovalRequired", "BoundaryViolation"]
