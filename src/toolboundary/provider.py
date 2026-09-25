"""
toolboundary.provider
---------------------
Provider-neutral contract for external authorization and evidence providers.

This module defines the data models and protocol that any external provider
(e.g. AgentKey, or a future alternative) must implement to integrate with
ToolBoundary's execution orchestration.

**No external dependencies.** This module is pure Python stdlib + dataclasses.

Core invariant: ToolBoundary remains the local enforcement authority. An
external provider can add a stricter gate or external evidence, but it can
never turn a local deny into an allow.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class ProviderMode(str, Enum):
    """How the provider's decision affects tool execution.

    OBSERVE: provider failures or denials are logged but do not block
             a locally-allowed action.
    ENFORCE: provider must explicitly allow the action; failures or
             denials block execution before dispatch.
    """

    OBSERVE = "observe"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class FrozenToolCall:
    """Immutable snapshot of a tool call, capturing every parameter that
    was resolved at the moment the call was authorized.

    The ``call_digest`` field is populated by the evidence module after
    deterministic canonicalization and hashing. All other fields are set
    by the boundary's authorization flow.
    """

    agent_name: str
    tool_name: str
    operation: str | None
    arguments: dict[str, Any]
    resource: str | None = None
    tool_version: str | None = None
    schema_hash: str | None = None
    manifest_hash: str | None = None
    approval_id: str | None = None
    approval_state: str | None = None
    call_digest: str = ""


@dataclass(frozen=True)
class LocalDecision:
    """Structured result of ToolBoundary's local policy evaluation.

    This replaces the implicit "returns None on allow / raises on deny"
    contract with an explicit object, while preserving backward compatibility
    through the existing ``check()`` method.
    """

    decision: str  # "ALLOW" | "DENY" | "APPROVAL_REQUIRED"
    decision_id: str
    agent_name: str
    tool_name: str
    operation: str | None
    reason_code: str | None = None
    approval_id: str | None = None
    policy_version: str | None = None


@dataclass(frozen=True)
class ProviderGrant:
    """Result of an external provider's authorization decision."""

    allowed: bool
    provider: str
    authorization_id: str | None = None
    attempt_id: str | None = None
    expires_at: float | None = None
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionRecord:
    """Evidence of what happened when the tool was actually dispatched."""

    call_digest: str
    status: str  # "success" | "error" | "unknown"
    started_at: float
    finished_at: float
    result_digest: str | None = None
    error_type: str | None = None
    error_message: str | None = None
    observed_by: str = "runtime"


@dataclass(frozen=True)
class ProviderReceipt:
    """Acknowledgement from the provider that it recorded execution evidence."""

    recorded: bool
    provider: str
    evidence_id: str | None = None
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationContext:
    """Bundles the local decision, frozen call, and optional provider grant
    into a single object that the execution path can use to verify binding
    and record evidence.

    The ``consumed`` flag ensures a single authorization cannot be reused
    for a second dispatch.
    """

    local_decision: LocalDecision
    frozen_call: FrozenToolCall
    provider_grant: ProviderGrant | None = None
    consumed: bool = False
    authorization_id: str = ""

    def __post_init__(self) -> None:
        if not self.authorization_id:
            self.authorization_id = str(uuid.uuid4())

    def mark_consumed(self) -> None:
        """Mark this authorization as consumed. Prevents reuse."""
        self.consumed = True


class EvidenceProvider(Protocol):
    """Protocol that any external authorization/evidence provider must satisfy.

    Implementations should be placed under ``toolboundary.integrations``.
    """

    def authorize(
        self,
        call: FrozenToolCall,
        local: LocalDecision,
    ) -> ProviderGrant:
        """Ask the provider whether the frozen call is authorized.

        Called only after a local ALLOW decision. The provider may deny
        (returning ``ProviderGrant(allowed=False, ...)``), allow, or raise
        an exception (treated as unavailability).
        """
        ...

    def record(
        self,
        grant: ProviderGrant,
        execution: ExecutionRecord,
    ) -> ProviderReceipt:
        """Record execution evidence with the provider.

        Called after tool dispatch (both success and failure). A failure here
        must never erase the local execution record.
        """
        ...
