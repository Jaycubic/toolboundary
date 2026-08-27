"""
toolboundary.permissions
------------------------
Operation-level tool permissions.

Mirrors the "tool permission is operation-level, not merely tool-level"
principle: an agent might be allowed to READ a tool but not WRITE or
EXECUTE through it, and specific operations can be explicitly blocked
even if the general access_mode would otherwise allow them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import AccessMode


@dataclass(frozen=True)
class ToolPermission:
    """
    Declares what an agent may do with one named tool.

    Parameters
    ----------
    tool_name:
        The name ToolBoundary will match against (case-sensitive) when the
        agent attempts to call a tool. Should match the `name` the tool is
        registered under in your framework (e.g. a LangChain Tool's `.name`).
    access_mode:
        The maximum access this permission grants. READ_ONLY < WRITE < EXECUTE < ADMIN
        is not a strict hierarchy ToolBoundary assumes automatically -- each
        mode is checked explicitly against what the tool call declares it needs.
    allowed_operations:
        If set, only these operation names are allowed for this tool. If
        None, all operations are allowed by default (subject to
        blocked_operations and access_mode).
    blocked_operations:
        Operation names that are always denied for this tool, regardless of
        allowed_operations or access_mode. Blocked always wins.
    max_calls_per_hour:
        Optional per-tool rate limit, independent of the agent-level limit.
    max_value:
        Optional numeric ceiling checked against a `value` kwarg passed at
        call time (e.g. transaction amount). None disables the check.
    max_records:
        Optional ceiling checked against a `record_count` kwarg passed at
        call time. None disables the check.
    requires_approval:
        If True, calls matching this permission are never auto-allowed --
        they always raise ApprovalRequired so the host application can
        route them to a human.
    """

    tool_name: str
    access_mode: AccessMode = AccessMode.READ_ONLY
    allowed_operations: frozenset[str] | None = None
    blocked_operations: frozenset[str] = field(default_factory=frozenset)
    max_calls_per_hour: int | None = None
    max_value: float | None = None
    max_records: int | None = None
    requires_approval: bool = False

    def operation_allowed(self, operation: str | None) -> bool:
        if operation is None:
            return True
        if operation in self.blocked_operations:
            return False
        if self.allowed_operations is not None and operation not in self.allowed_operations:
            return False
        return True
