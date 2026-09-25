"""
tests/test_provider.py
-----------------------
Provider contract test suite.

Tests the provider-neutral authorization and evidence flow defined in
the implementation plan, covering:

1. Provider disabled — current behavior unchanged
2. Local deny cannot be overridden by provider
3. Provider allow — function executes
4. Observe provider timeout — function executes, evidence degraded
5. Enforce provider timeout — DO NOT EXECUTE
6. Provider deny (enforce) — DO NOT EXECUTE
7. Argument mutation — reject / invalid execution binding
8. Deterministic canonicalization — identical digests for equivalent dicts
9. Replay — consumed authorization cannot be reused
10. Post-dispatch provider failure — local record preserved
"""

from __future__ import annotations

import time

import pytest

from toolboundary import (
    AccessMode,
    AuthorizationConsumed,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ProviderAuthorizationDenied,
    ProviderUnavailable,
    ToolPermission,
)
from toolboundary.evidence import call_digest, canonicalize, freeze_with_digest, sha256
from toolboundary.provider import (
    AuthorizationContext,
    ExecutionRecord,
    FrozenToolCall,
    LocalDecision,
    ProviderGrant,
    ProviderMode,
    ProviderReceipt,
)


# ---------------------------------------------------------------------------
# Mock providers
# ---------------------------------------------------------------------------


class AllowingProvider:
    """A provider that always allows."""

    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        return ProviderGrant(
            allowed=True,
            provider="mock-allow",
            authorization_id="auth-123",
            attempt_id="att-001",
        )

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        return ProviderReceipt(
            recorded=True,
            provider="mock-allow",
            evidence_id="ev-001",
        )


class DenyingProvider:
    """A provider that always denies."""

    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        return ProviderGrant(
            allowed=False,
            provider="mock-deny",
            reason="policy violation detected",
        )

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        return ProviderReceipt(recorded=True, provider="mock-deny")


class UnavailableProvider:
    """A provider that raises on authorize (simulates timeout/network failure)."""

    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        raise ConnectionError("provider unreachable")

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        return ProviderReceipt(recorded=True, provider="mock-unavailable")


class RecordFailingProvider:
    """A provider that allows but fails to record execution evidence."""

    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        return ProviderGrant(
            allowed=True,
            provider="mock-record-fail",
            authorization_id="auth-456",
        )

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        raise ConnectionError("failed to record evidence")


class SpyProvider:
    """A provider that records all calls for inspection."""

    def __init__(self, *, allow: bool = True):
        self._allow = allow
        self.authorize_calls: list[tuple[FrozenToolCall, LocalDecision]] = []
        self.record_calls: list[tuple[ProviderGrant, ExecutionRecord]] = []

    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        self.authorize_calls.append((call, local))
        return ProviderGrant(
            allowed=self._allow,
            provider="spy",
            authorization_id="spy-auth",
            attempt_id="spy-att",
        )

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        self.record_calls.append((grant, execution))
        return ProviderReceipt(recorded=True, provider="spy", evidence_id="spy-ev")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_boundary(
    *,
    provider=None,
    provider_mode: ProviderMode = ProviderMode.OBSERVE,
    **overrides,
) -> Boundary:
    defaults = dict(
        agent_name="test-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission("send_email", access_mode=AccessMode.EXECUTE),
            ToolPermission(
                "wire_transfer",
                access_mode=AccessMode.EXECUTE,
                max_value=1000.0,
            ),
        ],
        provider=provider,
        provider_mode=provider_mode,
    )
    defaults.update(overrides)
    return Boundary(**defaults)


# ---------------------------------------------------------------------------
# Test 1 — Provider disabled: current ToolBoundary behavior unchanged
# ---------------------------------------------------------------------------


class TestProviderDisabled:
    def test_no_provider_allow_works(self):
        b = make_boundary()
        b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_no_provider_deny_works(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation):
            b.check("unknown_tool", access_mode=AccessMode.EXECUTE)

    def test_authorize_call_no_provider_returns_context(self):
        b = make_boundary()
        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )
        assert ctx.local_decision.decision == "ALLOW"
        assert ctx.provider_grant is None
        assert ctx.frozen_call.call_digest != ""
        assert not ctx.consumed


# ---------------------------------------------------------------------------
# Test 2 — Local deny cannot be overridden by provider
# ---------------------------------------------------------------------------


class TestLocalDenyCannotBeOverridden:
    def test_local_deny_with_allowing_provider(self):
        """Even if the provider says ALLOW, a local DENY must remain DENY."""
        b = make_boundary(
            provider=AllowingProvider(),
            provider_mode=ProviderMode.ENFORCE,
        )
        with pytest.raises(BoundaryViolation):
            b.authorize_call(
                tool_name="unknown_tool",  # not in permissions → local DENY
                access_mode=AccessMode.EXECUTE,
                arguments={},
            )

    def test_local_deny_provider_never_called(self):
        """The provider should never even be consulted on a local deny."""
        spy = SpyProvider()
        b = make_boundary(
            provider=spy,
            provider_mode=ProviderMode.ENFORCE,
        )
        with pytest.raises(BoundaryViolation):
            b.authorize_call(
                tool_name="unknown_tool",
                access_mode=AccessMode.EXECUTE,
                arguments={},
            )
        assert len(spy.authorize_calls) == 0


# ---------------------------------------------------------------------------
# Test 3 — Provider allow: function executes
# ---------------------------------------------------------------------------


class TestProviderAllow:
    def test_local_allow_provider_allow_succeeds(self):
        b = make_boundary(
            provider=AllowingProvider(),
            provider_mode=ProviderMode.ENFORCE,
        )
        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )
        assert ctx.local_decision.decision == "ALLOW"
        assert ctx.provider_grant is not None
        assert ctx.provider_grant.allowed is True
        assert ctx.provider_grant.provider == "mock-allow"
        assert ctx.frozen_call.call_digest != ""


# ---------------------------------------------------------------------------
# Test 4 — Observe provider timeout: function executes, evidence degraded
# ---------------------------------------------------------------------------


class TestObserveProviderTimeout:
    def test_observe_mode_proceeds_on_provider_failure(self):
        b = make_boundary(
            provider=UnavailableProvider(),
            provider_mode=ProviderMode.OBSERVE,
        )
        # Should NOT raise — observe mode allows execution despite provider failure.
        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )
        assert ctx.local_decision.decision == "ALLOW"
        assert ctx.provider_grant is not None
        assert ctx.provider_grant.metadata.get("evidence_degraded") is True


# ---------------------------------------------------------------------------
# Test 5 — Enforce provider timeout: DO NOT EXECUTE
# ---------------------------------------------------------------------------


class TestEnforceProviderTimeout:
    def test_enforce_mode_blocks_on_provider_failure(self):
        b = make_boundary(
            provider=UnavailableProvider(),
            provider_mode=ProviderMode.ENFORCE,
        )
        with pytest.raises(ProviderUnavailable):
            b.authorize_call(
                tool_name="read_db",
                access_mode=AccessMode.READ_ONLY,
                arguments={"query": "select 1"},
            )


# ---------------------------------------------------------------------------
# Test 6 — Provider deny (enforce): DO NOT EXECUTE
# ---------------------------------------------------------------------------


class TestProviderDenyEnforce:
    def test_enforce_mode_blocks_on_provider_deny(self):
        b = make_boundary(
            provider=DenyingProvider(),
            provider_mode=ProviderMode.ENFORCE,
        )
        with pytest.raises(ProviderAuthorizationDenied) as exc_info:
            b.authorize_call(
                tool_name="read_db",
                access_mode=AccessMode.READ_ONLY,
                arguments={"query": "select 1"},
            )
        assert "policy violation detected" in str(exc_info.value)

    def test_observe_mode_proceeds_on_provider_deny(self):
        """In observe mode, provider deny is logged but does not block."""
        b = make_boundary(
            provider=DenyingProvider(),
            provider_mode=ProviderMode.OBSERVE,
        )
        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )
        assert ctx.local_decision.decision == "ALLOW"
        # The provider grant is not None — it records the deny for audit.
        assert ctx.provider_grant is not None
        assert ctx.provider_grant.allowed is False


# ---------------------------------------------------------------------------
# Test 7 — Argument mutation: reject / invalid execution binding
# ---------------------------------------------------------------------------


class TestArgumentMutation:
    def test_different_arguments_produce_different_digests(self):
        """If arguments are mutated between authorization and execution,
        the digests won't match — this is how the binding is enforced."""
        call_a = FrozenToolCall(
            agent_name="agent",
            tool_name="wire_transfer",
            operation=None,
            arguments={"amount": 100},
        )
        call_b = FrozenToolCall(
            agent_name="agent",
            tool_name="wire_transfer",
            operation=None,
            arguments={"amount": 1000},
        )
        digest_a = call_digest(call_a)
        digest_b = call_digest(call_b)
        assert digest_a != digest_b

    def test_frozen_call_is_immutable(self):
        """FrozenToolCall is a frozen dataclass — arguments cannot be
        mutated after creation."""
        call = FrozenToolCall(
            agent_name="agent",
            tool_name="read_db",
            operation=None,
            arguments={"query": "select 1"},
        )
        with pytest.raises(AttributeError):
            call.tool_name = "hacked_tool"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 8 — Deterministic canonicalization
# ---------------------------------------------------------------------------


class TestDeterministicCanonicalization:
    def test_equivalent_dicts_produce_identical_digest(self):
        """{"a": 1, "b": 2} and {"b": 2, "a": 1} must produce the same digest."""
        call_1 = FrozenToolCall(
            agent_name="agent",
            tool_name="tool",
            operation=None,
            arguments={"a": 1, "b": 2},
        )
        call_2 = FrozenToolCall(
            agent_name="agent",
            tool_name="tool",
            operation=None,
            arguments={"b": 2, "a": 1},
        )
        assert call_digest(call_1) == call_digest(call_2)

    def test_nested_dict_order_irrelevant(self):
        call_1 = FrozenToolCall(
            agent_name="agent",
            tool_name="tool",
            operation=None,
            arguments={"outer": {"x": 1, "y": 2}, "z": 3},
        )
        call_2 = FrozenToolCall(
            agent_name="agent",
            tool_name="tool",
            operation=None,
            arguments={"z": 3, "outer": {"y": 2, "x": 1}},
        )
        assert call_digest(call_1) == call_digest(call_2)

    def test_canonicalize_is_deterministic(self):
        val = {"c": 3, "a": 1, "b": {"z": 26, "a": 1}}
        assert canonicalize(val) == canonicalize(val)
        # Verify sorting
        canon = canonicalize(val)
        assert canon == '{"a":1,"b":{"a":1,"z":26},"c":3}'

    def test_sha256_produces_hex_string(self):
        result = sha256("hello")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_freeze_with_digest_populates_call_digest(self):
        call = FrozenToolCall(
            agent_name="agent",
            tool_name="tool",
            operation=None,
            arguments={"key": "value"},
        )
        assert call.call_digest == ""
        frozen = freeze_with_digest(call)
        assert frozen.call_digest != ""
        assert len(frozen.call_digest) == 64


# ---------------------------------------------------------------------------
# Test 9 — Replay: consumed authorization cannot be reused
# ---------------------------------------------------------------------------


class TestReplay:
    def test_consumed_authorization_cannot_be_reused(self):
        b = make_boundary(provider=AllowingProvider(), provider_mode=ProviderMode.ENFORCE)
        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )

        # First execution — succeeds and consumes the authorization.
        b.record_execution(
            ctx,
            result="rows",
            started_at=time.time(),
            finished_at=time.time(),
        )
        assert ctx.consumed is True

        # Second execution — must be rejected.
        with pytest.raises(AuthorizationConsumed):
            b.record_execution(
                ctx,
                result="rows again",
                started_at=time.time(),
                finished_at=time.time(),
            )


# ---------------------------------------------------------------------------
# Test 10 — Post-dispatch provider failure: local record preserved
# ---------------------------------------------------------------------------


class TestPostDispatchProviderFailure:
    def test_provider_record_failure_preserves_local_record(self):
        b = make_boundary(
            provider=RecordFailingProvider(),
            provider_mode=ProviderMode.ENFORCE,
        )
        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )

        # The tool executed successfully, but the provider fails to record.
        receipt = b.record_execution(
            ctx,
            result="rows",
            started_at=time.time(),
            finished_at=time.time(),
        )

        # The receipt should indicate recording failed.
        assert receipt is not None
        assert receipt.recorded is False
        assert "error" in receipt.metadata

        # The authorization is still consumed (cannot be reused).
        assert ctx.consumed is True


# ---------------------------------------------------------------------------
# Additional: evaluate() returns structured LocalDecision
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_evaluate_returns_allow(self):
        b = make_boundary()
        decision = b.evaluate("read_db", access_mode=AccessMode.READ_ONLY)
        assert decision.decision == "ALLOW"
        assert decision.agent_name == "test-agent"
        assert decision.tool_name == "read_db"

    def test_evaluate_returns_deny(self):
        b = make_boundary()
        decision = b.evaluate("unknown_tool", access_mode=AccessMode.EXECUTE)
        assert decision.decision == "DENY"
        assert decision.reason_code == "TOOL_NOT_ALLOWED"

    def test_evaluate_does_not_raise(self):
        """Unlike check(), evaluate() never raises — it returns the decision."""
        b = make_boundary()
        # This would raise BoundaryViolation with check(), but evaluate() returns.
        decision = b.evaluate("unknown_tool", access_mode=AccessMode.EXECUTE)
        assert decision.decision == "DENY"


# ---------------------------------------------------------------------------
# Integration: authorize_call → record_execution full path
# ---------------------------------------------------------------------------


class TestFullOrchestratedPath:
    def test_full_path_with_spy_provider(self):
        spy = SpyProvider()
        b = make_boundary(provider=spy, provider_mode=ProviderMode.ENFORCE)

        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )

        # Provider was consulted.
        assert len(spy.authorize_calls) == 1
        frozen_call, local_dec = spy.authorize_calls[0]
        assert frozen_call.tool_name == "read_db"
        assert frozen_call.arguments == {"query": "select 1"}
        assert frozen_call.call_digest != ""
        assert local_dec.decision == "ALLOW"

        # Simulate execution.
        started = time.time()
        receipt = b.record_execution(
            ctx,
            result="query results",
            started_at=started,
            finished_at=time.time(),
        )

        # Provider recorded the execution.
        assert len(spy.record_calls) == 1
        grant, execution = spy.record_calls[0]
        assert execution.status == "success"
        assert execution.result_digest is not None
        assert execution.call_digest == frozen_call.call_digest
        assert receipt is not None
        assert receipt.recorded is True

    def test_full_path_error_recording(self):
        spy = SpyProvider()
        b = make_boundary(provider=spy, provider_mode=ProviderMode.ENFORCE)

        ctx = b.authorize_call(
            tool_name="read_db",
            access_mode=AccessMode.READ_ONLY,
            arguments={"query": "select 1"},
        )

        # Simulate failed execution.
        error = ValueError("database connection failed")
        receipt = b.record_execution(
            ctx,
            error=error,
            started_at=time.time(),
            finished_at=time.time(),
        )

        assert len(spy.record_calls) == 1
        _, execution = spy.record_calls[0]
        assert execution.status == "error"
        assert execution.error_type == "ValueError"
        assert "database connection failed" in execution.error_message
