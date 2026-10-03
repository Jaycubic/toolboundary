"""
tests/test_agentkey_integration.py
----------------------------------
End-to-end integration test suite for ToolBoundary × AgentKey integration.

Verifies:
1. Test A: Allowed call (single dispatch, record_execution, full correlation)
2. Test B: Provider denial in ENFORCE mode (blocked before dispatch, no record)
3. Test C: Consumed-grant replay prevention (single-use token)
4. Test D: Post-dispatch reporting (success, error, failure preserves audit)
5. Core invariant: Local deny never consults AgentKey
6. Exact argument binding between authorize() and record()
7. Session ID consistency across lifecycle
8. Approval-required behavior
9. ProviderReceipt semantics (evidence_recorded, evidence_id, signature=None)
10. OBSERVE vs ENFORCE modes
11. @guarded_tool decorator end-to-end with AgentKeyProvider
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest

from toolboundary import (
    AccessMode,
    AuthorizationConsumed,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    KillSwitchActive,
    ProviderAuthorizationDenied,
    ProviderMode,
    ProviderUnavailable,
    ToolPermission,
    guarded_tool,
)
from toolboundary.audit import AuditTrail
from toolboundary.integrations.agentkey import AgentKeyProvider


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# Deterministic Fake AgentKey Client
# ---------------------------------------------------------------------------


class FakeAgentKeyClient:
    """Deterministic fake AgentKey client for CI testing."""

    def __init__(
        self,
        *,
        allowed: bool = True,
        reason: str | None = None,
        approval_required: bool = False,
        approval_id: str | None = None,
        record_success: bool = True,
        raise_on_authorize: Exception | None = None,
        raise_on_record: Exception | None = None,
    ) -> None:
        self.allowed = allowed
        self.reason = reason
        self.approval_required = approval_required
        self.approval_id = approval_id
        self.record_success = record_success
        self.raise_on_authorize = raise_on_authorize
        self.raise_on_record = raise_on_record

        self.authorize_calls: list[dict[str, Any]] = []
        self.record_calls: list[dict[str, Any]] = []

    def authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.authorize_calls.append(payload)
        if self.raise_on_authorize is not None:
            raise self.raise_on_authorize
        return {
            "event_id": f"evt-{uuid.uuid4().hex[:8]}",
            "attempt_id": f"att-{uuid.uuid4().hex[:8]}",
            "request_id": f"req-distinct-{uuid.uuid4().hex[:8]}",  # NOT event_id
            "allowed": self.allowed,
            "reason": self.reason or ("Authorized" if self.allowed else "Denied by AgentKey"),
            "approval_required": self.approval_required,
            "approval_id": self.approval_id,
            "metadata": {"test_client": True},
        }

    def record(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.record_calls.append(payload)
        if self.raise_on_record is not None:
            raise self.raise_on_record
        return {
            "evidence_recorded": self.record_success,
            "event_id": f"rec-evt-{uuid.uuid4().hex[:8]}",
            "metadata": {"recorded_by": "fake-agentkey"},
        }


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


class TestAgentKeyAllowedCall:
    """Test A: Allowed call workflow."""

    def test_allowed_call_full_lifecycle(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client, session_id="test-session-001")

        boundary = Boundary(
            agent_name="support-agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[
                ToolPermission(
                    "read_ticket",
                    access_mode=AccessMode.READ_ONLY,
                ),
            ],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
            policy_version="v1.0",
        )

        dispatch_count = 0

        @guarded_tool(
            boundary,
            tool_name="read_ticket",
            access_mode=AccessMode.READ_ONLY,
        )
        def read_ticket(ticket_id: str) -> str:
            nonlocal dispatch_count
            dispatch_count += 1
            return f"ticket={ticket_id}"

        result = read_ticket("INC-1001")

        # Assert: tool executed exactly once
        assert dispatch_count == 1
        assert result == "ticket=INC-1001"

        # Assert: authorize() called once
        assert len(client.authorize_calls) == 1
        auth_call = client.authorize_calls[0]
        assert auth_call["tool"] == "read_ticket"
        assert auth_call["arguments"] == {"ticket_id": "INC-1001"}
        assert auth_call["session_id"] == "test-session-001"
        assert "toolboundary_call_digest" in auth_call["metadata"]
        assert auth_call["metadata"]["toolboundary_policy_version"] == "v1.0"

        # Assert: record() called once
        assert len(client.record_calls) == 1
        rec_call = client.record_calls[0]
        assert rec_call["tool"] == "read_ticket"
        assert rec_call["arguments"] == {"ticket_id": "INC-1001"}
        assert rec_call["session_id"] == "test-session-001"
        assert rec_call["status"] == "success"

        # Assert: correlation preserved
        assert rec_call["call_digest"] == auth_call["metadata"]["toolboundary_call_digest"]
        assert rec_call["session_id"] == auth_call["session_id"]


class TestAgentKeyProviderDenial:
    """Test B: Provider denial in ENFORCE mode."""

    def test_provider_denial_blocks_before_dispatch(self) -> None:
        client = FakeAgentKeyClient(allowed=False, reason="Security policy violation")
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="support-agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[
                ToolPermission(
                    "delete_ticket",
                    access_mode=AccessMode.EXECUTE,
                ),
            ],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        dispatch_count = 0

        @guarded_tool(
            boundary,
            tool_name="delete_ticket",
            access_mode=AccessMode.EXECUTE,
        )
        def delete_ticket(ticket_id: str) -> str:
            nonlocal dispatch_count
            dispatch_count += 1
            return f"deleted {ticket_id}"

        with pytest.raises(ProviderAuthorizationDenied) as exc_info:
            delete_ticket("INC-9999")

        assert "Security policy violation" in str(exc_info.value)
        assert exc_info.value.provider == "agentkey"

        # Assert: tool never executed
        assert dispatch_count == 0

        # Assert: authorize() called once, record() never called
        assert len(client.authorize_calls) == 1
        assert len(client.record_calls) == 0


class TestAgentKeyConsumedGrantReplay:
    """Test C: Consumed-grant replay prevention."""

    def test_consumed_grant_cannot_be_reused(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="support-agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[
                ToolPermission("run_job", access_mode=AccessMode.EXECUTE),
            ],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        # Authorize prospective call
        ctx = boundary.authorize_call(
            tool_name="run_job",
            access_mode=AccessMode.EXECUTE,
            arguments={"job_id": 42},
        )
        assert ctx.consumed is False
        assert ctx.provider_grant is not None
        assert ctx.provider_grant.allowed is True
        attempt_id = ctx.provider_grant.attempt_id

        # First recording consumes authorization
        t0 = time.time()
        receipt = boundary.record_execution(
            ctx,
            result={"status": "completed"},
            started_at=t0,
            finished_at=t0 + 0.1,
        )
        assert ctx.consumed is True
        assert receipt is not None
        assert receipt.recorded is True

        # Second recording with the same context must raise AuthorizationConsumed
        with pytest.raises(AuthorizationConsumed):
            boundary.record_execution(
                ctx,
                result={"status": "duplicated"},
                started_at=t0,
                finished_at=t0 + 0.2,
            )

        # Provider-side attempt_id remains correlated and recorded once
        assert len(client.record_calls) == 1
        assert client.record_calls[0]["attempt_id"] == attempt_id


class TestAgentKeyPostDispatchReporting:
    """Test D: Post-dispatch reporting outcomes and failure isolation."""

    def test_successful_execution_reporting(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("fetch", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        ctx = boundary.authorize_call(
            tool_name="fetch",
            access_mode=AccessMode.READ_ONLY,
            arguments={"url": "https://example.com"},
        )

        t0 = time.time()
        receipt = boundary.record_execution(
            ctx,
            result={"bytes": 1024},
            started_at=t0,
            finished_at=t0 + 0.05,
        )

        assert receipt is not None
        assert receipt.recorded is True
        assert len(client.record_calls) == 1
        rec = client.record_calls[0]
        assert rec["status"] == "success"
        assert rec["result_digest"] is not None
        assert rec["error_type"] is None

    def test_error_execution_reporting(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("fetch", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        ctx = boundary.authorize_call(
            tool_name="fetch",
            access_mode=AccessMode.READ_ONLY,
            arguments={"url": "https://example.com"},
        )

        t0 = time.time()
        error = ConnectionResetError("connection reset by peer")
        receipt = boundary.record_execution(
            ctx,
            error=error,
            started_at=t0,
            finished_at=t0 + 0.05,
        )

        assert receipt is not None
        assert len(client.record_calls) == 1
        rec = client.record_calls[0]
        assert rec["status"] == "error"
        assert rec["error_type"] == "ConnectionResetError"
        assert "connection reset by peer" in rec["error_message"]

    def test_provider_record_failure_preserves_local_evidence(self) -> None:
        # Client raises error on record()
        client = FakeAgentKeyClient(
            allowed=True,
            raise_on_record=RuntimeError("AgentKey audit cluster timeout"),
        )
        provider = AgentKeyProvider(client=client)

        sink = RecordingSink()
        audit = AuditTrail(sinks=[sink])
        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("fetch", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
            audit=audit,
        )

        ctx = boundary.authorize_call(
            tool_name="fetch",
            access_mode=AccessMode.READ_ONLY,
            arguments={"url": "https://example.com"},
        )

        t0 = time.time()
        receipt = boundary.record_execution(
            ctx,
            result={"status": "ok"},
            started_at=t0,
            finished_at=t0 + 0.05,
        )

        # Provider receipt indicates failure, but no uncaught crash
        assert receipt is not None
        assert receipt.recorded is False

        # Local audit log preserved execution entry
        last_event = sink.events[-1]
        assert last_event.decision == "ALLOW"
        assert "Execution recorded: success" in last_event.message
        assert last_event.metadata["execution_status"] == "success"


class TestAgentKeySecurityInvariants:
    """Security invariant assertions."""

    def test_local_deny_never_consults_agentkey(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("read_only_tool", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        # 1. Denied tool not in permissions
        with pytest.raises(BoundaryViolation):
            boundary.authorize_call(
                tool_name="unregistered_tool",
                access_mode=AccessMode.READ_ONLY,
                arguments={},
            )

        # 2. Denied access mode exceeded
        with pytest.raises(BoundaryViolation):
            boundary.authorize_call(
                tool_name="read_only_tool",
                access_mode=AccessMode.WRITE,
                arguments={},
            )

        # 3. Kill switch active
        boundary.engage_kill_switch()
        with pytest.raises(KillSwitchActive):
            boundary.authorize_call(
                tool_name="read_only_tool",
                access_mode=AccessMode.READ_ONLY,
                arguments={},
            )

        # Invariant: Provider authorize was NEVER called for any of these
        assert len(client.authorize_calls) == 0

    def test_exact_arguments_stay_bound_to_recording(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("transfer", access_mode=AccessMode.EXECUTE)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        args = {"recipient": "alice", "amount": 100.0, "currency": "USD"}
        ctx = boundary.authorize_call(
            tool_name="transfer",
            access_mode=AccessMode.EXECUTE,
            arguments=args,
        )

        t0 = time.time()
        boundary.record_execution(
            ctx,
            result={"tx_id": "0xabc"},
            started_at=t0,
            finished_at=t0 + 0.1,
        )

        assert len(client.authorize_calls) == 1
        assert len(client.record_calls) == 1

        authorized_args = client.authorize_calls[0]["arguments"]
        recorded_args = client.record_calls[0]["arguments"]
        assert authorized_args == args
        assert recorded_args == args
        assert authorized_args == recorded_args

        # State cleaned up from provider pending cache
        assert len(provider.pending_calls) == 0


class TestAgentKeyFieldMappingAndReceipt:
    """Field mapping, session handling, and receipt semantics."""

    def test_field_mapping_and_event_id_not_request_id(self) -> None:
        client = FakeAgentKeyClient(allowed=True)
        provider = AgentKeyProvider(client=client, session_id="fixed-sess-99")

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("sql", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
            policy_version="v2.1",
        )

        ctx = boundary.authorize_call(
            tool_name="sql",
            operation="SELECT",
            resource="customers_table",
            arguments={"query": "SELECT * FROM customers"},
            schema_hash="schema-hash-abc",
            manifest_hash="manifest-hash-xyz",
        )

        grant = ctx.provider_grant
        assert grant is not None
        assert grant.allowed is True
        assert grant.provider == "agentkey"
        # event_id is mapped to authorization_id, NOT request_id
        assert grant.authorization_id.startswith("evt-")
        assert not grant.authorization_id.startswith("req-")
        assert grant.attempt_id.startswith("att-")
        assert grant.metadata["session_id"] == "fixed-sess-99"

        # Check payload delivered to client
        auth_call = client.authorize_calls[0]
        assert auth_call["tool"] == "sql"
        assert auth_call["action"] == "SELECT"
        assert auth_call["resource"] == "customers_table"
        assert auth_call["arguments"] == {"query": "SELECT * FROM customers"}
        assert auth_call["metadata"]["schema_hash"] == "schema-hash-abc"
        assert auth_call["metadata"]["manifest_hash"] == "manifest-hash-xyz"
        assert auth_call["metadata"]["toolboundary_policy_version"] == "v2.1"
        assert auth_call["metadata"]["toolboundary_call_digest"] == ctx.frozen_call.call_digest

        # Record receipt semantics
        t0 = time.time()
        receipt = boundary.record_execution(
            ctx,
            result={"rows": 10},
            started_at=t0,
            finished_at=t0 + 0.05,
        )
        assert receipt is not None
        assert receipt.recorded is True
        assert receipt.provider == "agentkey"
        assert receipt.evidence_id.startswith("rec-evt-")
        assert receipt.signature is None  # Session-level signature, not per-record
        assert receipt.metadata["session_id"] == "fixed-sess-99"

    def test_approval_required_mapping(self) -> None:
        client = FakeAgentKeyClient(
            allowed=False,
            approval_required=True,
            approval_id="apr-9876",
            reason="Requires senior approval",
        )
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("wipe_db", access_mode=AccessMode.ADMIN)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        with pytest.raises(ProviderAuthorizationDenied) as exc_info:
            boundary.authorize_call(
                tool_name="wipe_db",
                access_mode=AccessMode.ADMIN,
                arguments={"confirm": True},
            )

        assert "Requires senior approval" in str(exc_info.value)


class TestAgentKeyObserveMode:
    """Observe mode behavior with AgentKey."""

    def test_observe_mode_proceeds_on_denial(self) -> None:
        client = FakeAgentKeyClient(allowed=False, reason="AgentKey observe deny")
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("search", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.OBSERVE,
        )

        # In observe mode, local allow proceeds despite provider denial
        ctx = boundary.authorize_call(
            tool_name="search",
            access_mode=AccessMode.READ_ONLY,
            arguments={"q": "cats"},
        )
        assert ctx.local_decision.decision == "ALLOW"
        assert ctx.provider_grant is not None
        assert ctx.provider_grant.allowed is False

        # Can execute and record
        t0 = time.time()
        receipt = boundary.record_execution(
            ctx,
            result={"hits": 5},
            started_at=t0,
            finished_at=t0 + 0.05,
        )
        assert receipt is not None
        assert len(client.record_calls) == 1

    def test_observe_mode_proceeds_on_provider_unavailable(self) -> None:
        client = FakeAgentKeyClient(
            raise_on_authorize=ConnectionError("AgentKey host unreachable"),
        )
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("search", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.OBSERVE,
        )

        # In observe mode, connection error does not crash execution
        ctx = boundary.authorize_call(
            tool_name="search",
            access_mode=AccessMode.READ_ONLY,
            arguments={"q": "dogs"},
        )
        assert ctx.local_decision.decision == "ALLOW"
        assert ctx.provider_grant is not None
        assert ctx.provider_grant.provider == "unavailable"
        assert ctx.provider_grant.metadata.get("evidence_degraded") is True

    def test_enforce_mode_raises_provider_unavailable(self) -> None:
        client = FakeAgentKeyClient(
            raise_on_authorize=ConnectionError("AgentKey host unreachable"),
        )
        provider = AgentKeyProvider(client=client)

        boundary = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[ToolPermission("search", access_mode=AccessMode.READ_ONLY)],
            provider=provider,
            provider_mode=ProviderMode.ENFORCE,
        )

        with pytest.raises(ProviderUnavailable):
            boundary.authorize_call(
                tool_name="search",
                access_mode=AccessMode.READ_ONLY,
                arguments={"q": "dogs"},
            )
