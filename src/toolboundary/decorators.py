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

When a provider is configured on the boundary, `@guarded_tool` uses the
``authorize_call()`` / ``record_execution()`` orchestration so that:
- The exact resolved arguments used for authorization are the same ones
  used for execution.
- Execution evidence is recorded after dispatch (success or failure).
- Provider semantics (observe/enforce) are respected transparently.
"""

from __future__ import annotations

import functools
import inspect
import time
from typing import Any, Callable, TypeVar

from ._arguments import normalize_call_arguments
from ._redact import redact_args
from .boundary import Boundary
from .enums import AccessMode
from .permissions import resolve_declared_access_mode

F = TypeVar("F", bound=Callable[..., Any])


def guarded_tool(
    boundary: Boundary,
    *,
    tool_name: str | None = None,
    operation: str | None = None,
    access_mode: AccessMode | None = None,
    value_arg: str | None = None,
    record_count_arg: str | None = None,
    correlation_id_arg: str | None = None,
    resource: str | None = None,
    tool_version: str | None = None,
    schema_hash: str | None = None,
    manifest_hash: str | None = None,
    sensitive_args: frozenset[str] = frozenset(),
    log_arg_values: bool = True,
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
        The access mode this call represents. Omitting it warns and falls back
        to READ_ONLY; it will be required in ToolBoundary 2.0.
    value_arg / record_count_arg / correlation_id_arg:
        Names of keyword arguments on the decorated function whose runtime
        values should be forwarded into the boundary check as `value`,
        `record_count`, and `correlation_id` respectively. This lets you
        write, e.g., `@guarded_tool(boundary, value_arg="amount")` and have
        ToolBoundary automatically enforce max_value against whatever
        `amount` is passed at call time.
    resource / tool_version / schema_hash / manifest_hash:
        Optional provider-binding fields included in the FrozenToolCall
        when a provider is configured.
    sensitive_args:
        Argument names that must be redacted from audit metadata.
    log_arg_values:
        If False, log argument types instead of their values.

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
        declared_access_mode = resolve_declared_access_mode(access_mode, resolved_tool_name)

        def authorize(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[Any, str | None]:
            """Evaluate the call; returns (authorization or None, correlation id)."""
            call_kwargs = normalize_call_arguments(func, args, kwargs)
            resolved_operation = call_kwargs.get("operation") or operation
            resolved_value = call_kwargs.get(value_arg) if value_arg else None
            resolved_record_count = (
                call_kwargs.get(record_count_arg) if record_count_arg else None
            )
            resolved_correlation_id = (
                call_kwargs.get(correlation_id_arg) if correlation_id_arg else None
            )
            metadata = {
                "args": redact_args(
                    call_kwargs,
                    extra_names=sensitive_args,
                    log_values=log_arg_values,
                )
            }

            # Use the full authorize_call path when a provider is configured,
            # otherwise fall back to the simple check() for backward compat.
            if boundary._provider is None:  # noqa: SLF001
                boundary.check(
                    resolved_tool_name,
                    operation=resolved_operation,
                    access_mode=declared_access_mode,
                    value=resolved_value,
                    record_count=resolved_record_count,
                    correlation_id=resolved_correlation_id,
                    metadata=metadata,
                )
                return None, resolved_correlation_id

            authorization = boundary.authorize_call(
                tool_name=resolved_tool_name,
                operation=resolved_operation,
                access_mode=declared_access_mode,
                arguments=dict(call_kwargs),
                value=resolved_value,
                record_count=resolved_record_count,
                correlation_id=resolved_correlation_id,
                metadata=metadata,
                resource=resource,
                tool_version=tool_version,
                schema_hash=schema_hash,
                manifest_hash=manifest_hash,
                sensitive_args=sensitive_args,
            )
            return authorization, resolved_correlation_id

        def record(
            authorization: Any,
            result: Any,
            error: BaseException | None,
            started_at: float,
            correlation_id: str | None,
        ) -> None:
            boundary.record_execution(
                authorization,
                result=result,
                error=error,
                started_at=started_at,
                finished_at=time.time(),
                correlation_id=correlation_id,
            )

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            authorization, correlation_id = authorize(args, kwargs)
            if authorization is None:
                return func(*args, **kwargs)

            started_at = time.time()
            error: BaseException | None = None
            result: Any = None
            try:
                result = func(*args, **kwargs)
            except BaseException as exc:
                error = exc
                raise
            finally:
                record(authorization, result, error, started_at, correlation_id)
            return result

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            authorization, correlation_id = authorize(args, kwargs)
            if authorization is None:
                return await func(*args, **kwargs)

            started_at = time.time()
            error: BaseException | None = None
            result: Any = None
            try:
                result = await func(*args, **kwargs)
            except BaseException as exc:
                error = exc
                raise
            finally:
                record(authorization, result, error, started_at, correlation_id)
            return result

        guarded: Any = async_wrapper if inspect.iscoroutinefunction(func) else wrapper
        guarded.__toolboundary_boundary__ = boundary
        guarded.__toolboundary_tool_name__ = resolved_tool_name
        return guarded  # type: ignore[no-any-return]

    return decorator


def _safe_repr(kwargs: dict[str, Any], max_len: int = 200) -> dict[str, str]:
    """Best-effort stringification of call args for audit metadata, truncated for safety."""
    return redact_args(kwargs, max_len=max_len)
