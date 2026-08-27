"""
toolboundary.decorators
------------------------
`@guarded_tool` wraps a plain Python function so that ToolBoundary's
Boundary.check() runs automatically before the function body executes,
and cannot be skipped by forgetting to call it manually.

This is the mechanism that closes the "agent forgets to check permission"
gap: once a function is decorated, calling it *is* calling through
ToolBoundary -- there is no code path to the real implementation that
doesn't pass through the boundary check first.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

from .boundary import Boundary
from .enums import AccessMode

F = TypeVar("F", bound=Callable[..., Any])


def guarded_tool(
    boundary: Boundary,
    *,
    tool_name: str | None = None,
    operation: str | None = None,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    value_arg: str | None = None,
    record_count_arg: str | None = None,
    correlation_id_arg: str | None = None,
) -> Callable[[F], F]:
    """
    Decorate a function so every call is evaluated against `boundary` first.

    Parameters
    ----------
    boundary:
        The Boundary this function's calls should be checked against.
    tool_name:
        Name ToolBoundary will match against ToolPermission.tool_name.
        Defaults to the decorated function's __name__.
    operation:
        Optional operation label (e.g. "DELETE", "UPDATE_PRICE"). If the
        decorated function is called with a keyword argument named
        "operation", that value takes precedence over this default.
    access_mode:
        The access mode this call represents. READ_ONLY by default.
    value_arg / record_count_arg / correlation_id_arg:
        Names of keyword arguments on the decorated function whose runtime
        values should be forwarded into the boundary check as `value`,
        `record_count`, and `correlation_id` respectively. This lets you
        write, e.g., `@guarded_tool(boundary, value_arg="amount")` and have
        ToolBoundary automatically enforce max_value against whatever
        `amount` is passed at call time.

    Example
    -------
    >>> @guarded_tool(boundary, access_mode=AccessMode.EXECUTE, value_arg="amount")
    ... def wire_transfer(account_id: str, amount: float) -> str:
    ...     return f"transferred {amount} to {account_id}"
    >>>
    >>> wire_transfer(account_id="acct_1", amount=250_000)
    # raises BoundaryViolation if 250_000 > the permission's max_value
    """

    def decorator(func: F) -> F:
        resolved_tool_name = tool_name or func.__name__
        sig = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            call_kwargs = bound.arguments

            resolved_operation = call_kwargs.get("operation", operation)
            resolved_value = call_kwargs.get(value_arg) if value_arg else None
            resolved_record_count = (
                call_kwargs.get(record_count_arg) if record_count_arg else None
            )
            resolved_correlation_id = (
                call_kwargs.get(correlation_id_arg) if correlation_id_arg else None
            )

            boundary.check(
                resolved_tool_name,
                operation=resolved_operation,
                access_mode=access_mode,
                value=resolved_value,
                record_count=resolved_record_count,
                correlation_id=resolved_correlation_id,
                metadata={"args": _safe_repr(kwargs)},
            )

            return func(*args, **kwargs)

        wrapper.__toolboundary_boundary__ = boundary  # type: ignore[attr-defined]
        wrapper.__toolboundary_tool_name__ = resolved_tool_name  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


def _safe_repr(kwargs: dict[str, Any], max_len: int = 200) -> dict[str, str]:
    """Best-effort stringification of call args for audit metadata, truncated for safety."""
    out: dict[str, str] = {}
    for k, v in kwargs.items():
        try:
            s = repr(v)
        except Exception:  # noqa: BLE001
            s = "<unrepresentable>"
        out[k] = s if len(s) <= max_len else s[:max_len] + "...(truncated)"
    return out
