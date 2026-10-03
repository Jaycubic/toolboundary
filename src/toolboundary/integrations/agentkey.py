"""
toolboundary.integrations.agentkey
----------------------------------
AgentKey reference integration provider for ToolBoundary.

Implements the ``EvidenceProvider`` protocol against AgentKey's external
authorization and evidence service.

Field Mapping:
- call.tool_name -> tool
- call.operation -> action
- call.resource -> resource
- call.arguments -> arguments
- call.call_digest -> metadata["toolboundary_call_digest"]
- local.decision_id -> metadata["toolboundary_decision_id"]
- local.policy_version -> metadata["toolboundary_policy_version"]
- schema_hash / manifest_hash -> metadata["schema_hash"] / metadata["manifest_hash"]
- AgentKey event_id -> ProviderGrant.authorization_id (never request_id)
- AgentKey attempt_id -> ProviderGrant.attempt_id
- AgentKey allowed -> ProviderGrant.allowed
- AgentKey reason -> ProviderGrant.reason
- AgentKey session_id -> ProviderGrant.metadata["session_id"]
- AgentKey approval_required -> ProviderGrant.metadata["approval_required"]
- AgentKey approval_id -> ProviderGrant.metadata["approval_id"]

ProviderReceipt Mapping:
- AgentKey evidence_recorded -> ProviderReceipt.recorded
- AgentKey execution event_id -> ProviderReceipt.evidence_id
- ProviderReceipt.signature = None (session-level signing occurs after export)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from toolboundary.provider import (
    ExecutionRecord,
    FrozenToolCall,
    LocalDecision,
    ProviderGrant,
    ProviderReceipt,
)

_logger = logging.getLogger("toolboundary.integrations.agentkey")


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Extract a value from a dict or object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class AgentKeyProvider:
    """AgentKey authorization and evidence provider for ToolBoundary.

    Implements ``EvidenceProvider``. Connects ToolBoundary's local policy
    enforcement with AgentKey's external policy evaluation and cryptographic
    audit session evidence.
    """

    def __init__(
        self,
        client: Any = None,
        *,
        session_id: str | None = None,
        api_key: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        """Initialize the AgentKey provider.

        Parameters
        ----------
        client:
            Optional AgentKey client instance (or mock client for testing).
            If omitted, a simulated in-process provider is used for local
            demos without requiring network access or external credentials.
        session_id:
            AgentKey session ID. If not supplied, an in-memory session ID is
            generated and shared between authorize() and record() calls.
        api_key:
            Optional AgentKey API key for client configuration.
        endpoint:
            Optional AgentKey API endpoint.
        """
        self._client = client
        self._session_id = session_id or f"ak-session-{uuid.uuid4().hex[:12]}"
        self._api_key = api_key
        self._endpoint = endpoint
        # Short-lived state to correlate authorize() call arguments with record()
        self._pending_calls: dict[str, tuple[FrozenToolCall, str]] = {}

    @property
    def session_id(self) -> str:
        """The active AgentKey session identifier."""
        return self._session_id

    @property
    def pending_calls(self) -> dict[str, tuple[FrozenToolCall, str]]:
        """Pending calls waiting for execution recording."""
        return self._pending_calls

    def authorize(
        self,
        call: FrozenToolCall,
        local: LocalDecision,
    ) -> ProviderGrant:
        """Authorize a prospective tool call with AgentKey.

        Maps ToolBoundary's frozen call parameters and local decision into
        AgentKey's authorization schema.
        """
        # Build metadata linkage
        metadata: dict[str, Any] = {
            "toolboundary_call_digest": call.call_digest,
            "toolboundary_decision_id": local.decision_id,
        }
        if local.policy_version is not None:
            metadata["toolboundary_policy_version"] = local.policy_version
        if call.schema_hash is not None:
            metadata["schema_hash"] = call.schema_hash
        if call.manifest_hash is not None:
            metadata["manifest_hash"] = call.manifest_hash

        auth_payload = {
            "session_id": self._session_id,
            "tool": call.tool_name,
            "action": call.operation,
            "resource": call.resource,
            "arguments": call.arguments,
            "metadata": metadata,
        }

        if self._client is not None and hasattr(self._client, "authorize"):
            # Call external or mock client
            try:
                res = self._client.authorize(auth_payload)
            except TypeError:
                res = self._client.authorize(**auth_payload)

            event_id = _get_val(res, "event_id") or f"ak-evt-{uuid.uuid4().hex[:12]}"
            attempt_id = _get_val(res, "attempt_id") or f"ak-att-{uuid.uuid4().hex[:12]}"
            allowed = bool(_get_val(res, "allowed", False))
            reason = _get_val(res, "reason")
            approval_required = bool(_get_val(res, "approval_required", False))
            approval_id = _get_val(res, "approval_id")
            res_metadata = _get_val(res, "metadata") or {}
        else:
            # Simulated standalone / demo mode
            event_id = f"ak-evt-{uuid.uuid4().hex[:12]}"
            attempt_id = f"ak-att-{uuid.uuid4().hex[:12]}"
            allowed = True
            reason = "Authorized by AgentKey (demo)"
            approval_required = False
            approval_id = None
            res_metadata = {}

        # Retain short-lived state for record() reconstruction
        self._pending_calls[attempt_id] = (call, self._session_id)
        self._pending_calls[event_id] = (call, self._session_id)

        grant_metadata: dict[str, Any] = {
            "session_id": self._session_id,
        }
        if approval_required:
            grant_metadata["approval_required"] = True
        if approval_id is not None:
            grant_metadata["approval_id"] = approval_id
        if isinstance(res_metadata, dict):
            for k, v in res_metadata.items():
                grant_metadata.setdefault(k, v)

        return ProviderGrant(
            allowed=allowed,
            provider="agentkey",
            authorization_id=event_id,
            attempt_id=attempt_id,
            reason=reason,
            metadata=grant_metadata,
        )

    def record(
        self,
        grant: ProviderGrant,
        execution: ExecutionRecord,
    ) -> ProviderReceipt:
        """Record execution outcome with AgentKey.

        Reconstructs the full call payload using stored state, linking post-dispatch
        evidence to the authorization event and attempt ID.
        """
        # Look up pending call state
        stored = None
        if grant.attempt_id and grant.attempt_id in self._pending_calls:
            stored = self._pending_calls.pop(grant.attempt_id)
            if grant.authorization_id:
                self._pending_calls.pop(grant.authorization_id, None)
        elif grant.authorization_id and grant.authorization_id in self._pending_calls:
            stored = self._pending_calls.pop(grant.authorization_id)

        if stored is not None:
            pending_call, sess_id = stored
        else:
            pending_call = None
            sess_id = grant.metadata.get("session_id", self._session_id)

        record_payload = {
            "session_id": sess_id,
            "authorization_event_id": grant.authorization_id,
            "attempt_id": grant.attempt_id,
            "tool": pending_call.tool_name if pending_call else None,
            "action": pending_call.operation if pending_call else None,
            "resource": pending_call.resource if pending_call else None,
            "arguments": pending_call.arguments if pending_call else {},
            "status": execution.status,
            "call_digest": execution.call_digest,
            "result_digest": execution.result_digest,
            "error_type": execution.error_type,
            "error_message": execution.error_message,
            "started_at": execution.started_at,
            "finished_at": execution.finished_at,
        }

        if self._client is not None and hasattr(self._client, "record"):
            try:
                try:
                    res = self._client.record(record_payload)
                except TypeError:
                    res = self._client.record(**record_payload)

                rec_val = _get_val(res, "evidence_recorded")
                if rec_val is None:
                    rec_val = _get_val(res, "recorded", True)
                evidence_id = _get_val(res, "event_id") or _get_val(res, "evidence_id")
                res_metadata = _get_val(res, "metadata") or {}
                if not isinstance(res_metadata, dict):
                    res_metadata = {}
                res_metadata.setdefault("session_id", sess_id)

                return ProviderReceipt(
                    recorded=bool(rec_val),
                    provider="agentkey",
                    evidence_id=evidence_id,
                    signature=None,
                    metadata=res_metadata,
                )
            except Exception as exc:  # noqa: BLE001
                _logger.warning("AgentKey client record failed: %s", exc)
                return ProviderReceipt(
                    recorded=False,
                    provider="agentkey",
                    signature=None,
                    metadata={"error": str(exc), "session_id": sess_id},
                )

        # Simulated standalone / demo mode
        evidence_id = f"ak-rec-{uuid.uuid4().hex[:12]}"
        return ProviderReceipt(
            recorded=True,
            provider="agentkey",
            evidence_id=evidence_id,
            signature=None,
            metadata={"session_id": sess_id},
        )
