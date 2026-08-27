"""
toolboundary.exceptions
----------------------
All exceptions raised by ToolBoundary when a governed action is denied,
requires approval, or cannot be evaluated safely (fail-closed).
"""

from __future__ import annotations

from typing import Any


class ToolBoundaryError(Exception):
    """Base class for all ToolBoundary errors."""


class BoundaryViolation(ToolBoundaryError):
    """
    Raised when an agent attempts an action outside its declared boundary.

    This is the primary exception ToolBoundary raises. It is intentionally
    loud (an exception, not a silent False) so that a violation cannot be
    accidentally ignored by agent code that forgets to check a return value.
    """

    def __init__(
        self,
        message: str,
        *,
        agent_name: str,
        tool_name: str | None = None,
        operation: str | None = None,
        rule: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.agent_name = agent_name
        self.tool_name = tool_name
        self.operation = operation
        self.rule = rule
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        base = super().__str__()
        ctx = f"agent={self.agent_name!r}"
        if self.tool_name:
            ctx += f" tool={self.tool_name!r}"
        if self.operation:
            ctx += f" operation={self.operation!r}"
        if self.rule:
            ctx += f" rule={self.rule!r}"
        return f"{base} ({ctx})"


class KillSwitchActive(BoundaryViolation):
    """Raised when an agent's kill switch is engaged. Always fail-closed."""


class RateLimitExceeded(BoundaryViolation):
    """Raised when an agent exceeds its max_actions_per_hour (or similar) limit."""


class ApprovalRequired(ToolBoundaryError):
    """
    Raised when an action is not outright denied, but requires human
    approval before it may proceed. Unlike BoundaryViolation, this is not
    necessarily a security failure -- it is a control-flow signal that the
    calling application should catch and route to a human reviewer.
    """

    def __init__(
        self,
        message: str,
        *,
        agent_name: str,
        tool_name: str,
        operation: str | None = None,
        approval_id: str | None = None,
    ) -> None:
        self.agent_name = agent_name
        self.tool_name = tool_name
        self.operation = operation
        self.approval_id = approval_id
        super().__init__(message)


class ConfigurationError(ToolBoundaryError):
    """Raised when a Boundary or Policy is misconfigured (fails fast at setup time)."""
