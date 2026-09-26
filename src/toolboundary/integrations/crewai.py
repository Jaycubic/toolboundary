"""
CrewAI integration for ToolBoundary.

The integration wraps a CrewAI BaseTool and enforces the ToolBoundary
authorization immediately before CrewAI executes the underlying tool.
"""

from __future__ import annotations

import time
from typing import Any

try:
    from crewai.tools import BaseTool
except ImportError as exc:  # pragma: no cover - depends on optional dependency
    raise ImportError(
        "CrewAI integration requires CrewAI. "
        "Install it with `pip install toolboundary[crewai]`."
    ) from exc

from toolboundary import AccessMode, Boundary


def guard_tool(
    tool: BaseTool,
    boundary: Boundary,
    *,
    tool_name: str | None = None,
    operation: str | None = None,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    value_arg: str | None = None,
    record_count_arg: str | None = None,
    resource: str | None = None,
    tool_version: str | None = None,
    schema_hash: str | None = None,
    manifest_hash: str | None = None,
) -> BaseTool:
    """Wrap a CrewAI tool with ToolBoundary authorization."""

    resolved_name = tool_name or tool.name

    class _GuardedTool(BaseTool):
        name: str = tool.name
        description: str = tool.description
        args_schema: Any = tool.args_schema
        result_schema: Any = tool.result_schema
        env_vars: Any = tool.env_vars
        cache_function: Any = tool.cache_function
        result_as_answer: bool = tool.result_as_answer
        max_usage_count: int | None = tool.max_usage_count
        tool_failure_policy: Any = tool.tool_failure_policy

        def _evaluate(self, kwargs: dict[str, Any]) -> None:
            resolved_value = kwargs.get(value_arg) if value_arg else None
            resolved_records = (
                kwargs.get(record_count_arg) if record_count_arg else None
            )

            boundary.check(
                resolved_name,
                operation=operation,
                access_mode=access_mode,
                value=resolved_value,
                record_count=resolved_records,
                metadata={"crewai_tool": tool.name},
            )

        def _authorize(self, kwargs: dict[str, Any]) -> Any:
            resolved_value = kwargs.get(value_arg) if value_arg else None
            resolved_records = (
                kwargs.get(record_count_arg) if record_count_arg else None
            )

            return boundary.authorize_call(
                tool_name=resolved_name,
                operation=operation,
                access_mode=access_mode,
                arguments=dict(kwargs),
                value=resolved_value,
                record_count=resolved_records,
                metadata={"crewai_tool": tool.name},
                resource=resource,
                tool_version=tool_version,
                schema_hash=schema_hash,
                manifest_hash=manifest_hash,
            )

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            """Delegate execution to the original CrewAI tool."""
            return tool._run(*args, **kwargs)  # noqa: SLF001

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            """Delegate async execution to the original CrewAI tool."""
            return await tool._arun(*args, **kwargs)  # noqa: SLF001

        def run(self, *args: Any, **kwargs: Any) -> Any:
            """Authorize immediately before executing the wrapped tool."""
            if boundary._provider is not None:  # noqa: SLF001
                authorization = self._authorize(kwargs)
                started_at = time.time()
                error: BaseException | None = None
                result: Any = None

                try:
                    result = tool.run(*args, **kwargs)
                except BaseException as exc:
                    error = exc
                    raise
                finally:
                    finished_at = time.time()
                    boundary.record_execution(
                        authorization,
                        result=result,
                        error=error,
                        started_at=started_at,
                        finished_at=finished_at,
                    )

                return result

            self._evaluate(kwargs)
            return tool.run(*args, **kwargs)

        async def arun(self, *args: Any, **kwargs: Any) -> Any:
            """Authorize immediately before async execution."""
            if boundary._provider is not None:  # noqa: SLF001
                authorization = self._authorize(kwargs)
                started_at = time.time()
                error: BaseException | None = None
                result: Any = None

                try:
                    result = await tool.arun(*args, **kwargs)
                except BaseException as exc:
                    error = exc
                    raise
                finally:
                    finished_at = time.time()
                    boundary.record_execution(
                        authorization,
                        result=result,
                        error=error,
                        started_at=started_at,
                        finished_at=finished_at,
                    )

                return result

            self._evaluate(kwargs)
            return await tool.arun(*args, **kwargs)

    return _GuardedTool()


def guard_tools(
    tools: list[BaseTool],
    boundary: Boundary,
    *,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    overrides: dict[str, dict[str, Any]] | None = None,
) -> list[BaseTool]:
    """Wrap multiple CrewAI tools with optional per-tool overrides."""

    overrides = overrides or {}

    return [
        guard_tool(
            tool,
            boundary,
            access_mode=overrides.get(tool.name, {}).get(
                "access_mode", access_mode
            ),
            **{
                key: value
                for key, value in overrides.get(tool.name, {}).items()
                if key != "access_mode"
            },
        )
        for tool in tools
    ]


__all__ = ["guard_tool", "guard_tools"]