from __future__ import annotations

import pytest

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ToolPermission,
    guarded_tool,
)
from toolboundary.audit import AuditTrail
from toolboundary.provider import (
    ProviderGrant,
    ProviderMode,
    ProviderReceipt,
)


def test_guarded_function_executes_when_allowed():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
    )

    @guarded_tool(boundary, tool_name="read_db", access_mode=AccessMode.READ_ONLY)
    def read_db(query: str) -> str:
        return f"result for {query}"

    assert read_db(query="select 1") == "result for select 1"


def test_guarded_function_blocks_before_body_executes():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[],  # nothing permitted
    )
    calls = []

    @guarded_tool(boundary, tool_name="dangerous_action", access_mode=AccessMode.EXECUTE)
    def dangerous_action() -> str:
        calls.append("executed")
        return "done"

    with pytest.raises(BoundaryViolation):
        dangerous_action()

    # the real function body must never have run
    assert calls == []


def test_value_arg_is_enforced_from_call_kwargs():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE, max_value=1000.0)
        ],
    )

    @guarded_tool(
        boundary,
        tool_name="wire_transfer",
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )
    def wire_transfer(account_id: str, amount: float) -> str:
        return f"sent {amount} to {account_id}"

    assert wire_transfer(account_id="acct_1", amount=500) == "sent 500 to acct_1"

    with pytest.raises(BoundaryViolation):
        wire_transfer(account_id="acct_1", amount=50_000)


def test_numeric_string_ceiling_blocks_decorated_tool_before_dispatch():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE, max_value=1000.0)
        ],
    )
    calls = []

    @guarded_tool(
        boundary,
        tool_name="wire_transfer",
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )
    def wire_transfer(amount):
        calls.append(amount)

    with pytest.raises(BoundaryViolation):
        wire_transfer("999999")
    assert calls == []


def test_decorator_operation_default_is_not_overridden_by_none_argument():
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission(
                "tool",
                access_mode=AccessMode.READ_ONLY,
                allowed_operations=frozenset({"read"}),
            )
        ],
    )

    @guarded_tool(boundary, tool_name="tool", operation="delete")
    def tool(operation=None):
        return "executed"

    with pytest.raises(BoundaryViolation) as exc_info:
        tool()
    assert exc_info.value.rule == "OPERATION_BLOCKED"


def test_guarded_tool_redacts_sensitive_bound_arguments_from_audit():
    class RecordingSink:
        def __init__(self):
            self.events = []

        def emit(self, event):
            self.events.append(event)

    sink = RecordingSink()
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("tool", access_mode=AccessMode.READ_ONLY)],
        audit=AuditTrail(sinks=[sink]),
    )

    @guarded_tool(boundary, tool_name="tool")
    def tool(password, api_key, ordinary):
        return "ok"

    tool("secret-value", "key-value", "visible")
    metadata = sink.events[-1].metadata["args"]
    assert metadata == {
        "password": "<redacted>",
        "api_key": "<redacted>",
        "ordinary": "'visible'",
    }


def test_guarded_tool_supports_custom_redaction_and_value_suppression():
    class RecordingSink:
        def __init__(self):
            self.events = []

        def emit(self, event):
            self.events.append(event)

    sink = RecordingSink()
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("tool", access_mode=AccessMode.READ_ONLY)],
        audit=AuditTrail(sinks=[sink]),
    )

    @guarded_tool(
        boundary,
        tool_name="tool",
        sensitive_args=frozenset({"ssn"}),
        log_arg_values=False,
    )
    def tool(ssn, count):
        return "ok"

    tool("123-45-6789", 7)
    metadata = sink.events[-1].metadata["args"]
    assert metadata == {"ssn": "<redacted>", "count": "<int>"}


# ---------------------------------------------------------------------------
# Provider-aware decorator tests
# ---------------------------------------------------------------------------


class _SpyProvider:
    """Records authorize and record calls for inspection."""

    def __init__(self, *, allow=True):
        self._allow = allow
        self.authorize_calls = []
        self.record_calls = []

    def authorize(self, call, local):
        self.authorize_calls.append((call, local))
        return ProviderGrant(allowed=self._allow, provider="spy")

    def record(self, grant, execution):
        self.record_calls.append((grant, execution))
        return ProviderReceipt(recorded=True, provider="spy")


def test_guarded_tool_with_provider_allow_executes():
    spy = _SpyProvider()
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        provider=spy,
        provider_mode=ProviderMode.ENFORCE,
    )

    @guarded_tool(boundary, tool_name="read_db", access_mode=AccessMode.READ_ONLY)
    def read_db(query: str) -> str:
        return f"result for {query}"

    result = read_db(query="select 1")
    assert result == "result for select 1"
    assert len(spy.authorize_calls) == 1
    assert len(spy.record_calls) == 1
    _, execution = spy.record_calls[0]
    assert execution.status == "success"


def test_guarded_tool_with_provider_deny_blocks():
    spy = _SpyProvider(allow=False)
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        provider=spy,
        provider_mode=ProviderMode.ENFORCE,
    )
    calls = []

    @guarded_tool(boundary, tool_name="read_db", access_mode=AccessMode.READ_ONLY)
    def read_db(query: str) -> str:
        calls.append("executed")
        return f"result for {query}"

    from toolboundary import ProviderAuthorizationDenied

    with pytest.raises(ProviderAuthorizationDenied):
        read_db(query="select 1")
    assert calls == []


def test_guarded_tool_with_provider_observe_timeout_executes():
    """In observe mode, provider unavailability doesn't block execution."""

    class _UnavailableProvider:
        def authorize(self, call, local):
            raise ConnectionError("unreachable")

        def record(self, grant, execution):
            return ProviderReceipt(recorded=True, provider="unavailable")

    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        provider=_UnavailableProvider(),
        provider_mode=ProviderMode.OBSERVE,
    )

    @guarded_tool(boundary, tool_name="read_db", access_mode=AccessMode.READ_ONLY)
    def read_db(query: str) -> str:
        return f"result for {query}"

    assert read_db(query="select 1") == "result for select 1"


def test_guarded_tool_with_provider_enforce_timeout_blocks():
    """In enforce mode, provider unavailability blocks execution."""

    class _UnavailableProvider:
        def authorize(self, call, local):
            raise ConnectionError("unreachable")

        def record(self, grant, execution):
            return ProviderReceipt(recorded=True, provider="unavailable")

    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        provider=_UnavailableProvider(),
        provider_mode=ProviderMode.ENFORCE,
    )
    calls = []

    @guarded_tool(boundary, tool_name="read_db", access_mode=AccessMode.READ_ONLY)
    def read_db(query: str) -> str:
        calls.append("executed")
        return f"result for {query}"

    from toolboundary import ProviderUnavailable

    with pytest.raises(ProviderUnavailable):
        read_db(query="select 1")
    assert calls == []


def test_guarded_tool_arguments_match_authorization():
    """The exact same resolved arguments used for authorization must be
    the ones used for function execution."""
    spy = _SpyProvider()
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[
            ToolPermission("wire_transfer", access_mode=AccessMode.EXECUTE, max_value=1000.0)
        ],
        provider=spy,
        provider_mode=ProviderMode.ENFORCE,
    )

    @guarded_tool(
        boundary,
        tool_name="wire_transfer",
        access_mode=AccessMode.EXECUTE,
        value_arg="amount",
    )
    def wire_transfer(account_id: str, amount: float) -> str:
        return f"sent {amount} to {account_id}"

    wire_transfer(account_id="acct_1", amount=500)

    assert len(spy.authorize_calls) == 1
    frozen_call, _ = spy.authorize_calls[0]
    assert frozen_call.arguments["account_id"] == "acct_1"
    assert frozen_call.arguments["amount"] == 500
