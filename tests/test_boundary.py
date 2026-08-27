from __future__ import annotations

import time

import pytest

from toolboundary import (
    AccessMode,
    ApprovalRequired,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    KillSwitchActive,
    RateLimitExceeded,
    ToolPermission,
)


def make_boundary(**overrides) -> Boundary:
    defaults = dict(
        agent_name="test-agent",
        autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
        permissions=[
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission(
                "send_email",
                access_mode=AccessMode.EXECUTE,
                blocked_operations=frozenset({"send_bulk"}),
            ),
            ToolPermission(
                "wire_transfer",
                access_mode=AccessMode.EXECUTE,
                max_value=1000.0,
                max_records=5,
            ),
        ],
        blocked_operations=frozenset({"delete_everything"}),
    )
    defaults.update(overrides)
    return Boundary(**defaults)


class TestBasicAllow:
    def test_allowed_call_does_not_raise(self):
        b = make_boundary()
        b.check("read_db", access_mode=AccessMode.READ_ONLY)  # should not raise

    def test_allowed_execute_call(self):
        b = make_boundary()
        b.check("send_email", access_mode=AccessMode.EXECUTE)


class TestToolNotAllowed:
    def test_unregistered_tool_denied(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("delete_database", access_mode=AccessMode.EXECUTE)
        assert exc_info.value.rule == "TOOL_NOT_ALLOWED"


class TestAccessMode:
    def test_exceeding_access_mode_denied(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", access_mode=AccessMode.WRITE)
        assert exc_info.value.rule == "ACCESS_MODE_EXCEEDED"

    def test_lower_access_mode_allowed(self):
        b = make_boundary()
        # send_email is granted EXECUTE; requesting READ_ONLY use of it should be fine
        b.check("send_email", access_mode=AccessMode.READ_ONLY)


class TestBlockedOperations:
    def test_globally_blocked_operation_denied_even_on_allowed_tool(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", operation="delete_everything", access_mode=AccessMode.READ_ONLY)
        assert exc_info.value.rule == "OPERATION_BLOCKED"

    def test_tool_specific_blocked_operation(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("send_email", operation="send_bulk", access_mode=AccessMode.EXECUTE)
        assert exc_info.value.rule == "OPERATION_BLOCKED"

    def test_non_blocked_operation_on_same_tool_allowed(self):
        b = make_boundary()
        b.check("send_email", operation="send_single", access_mode=AccessMode.EXECUTE)


class TestValueAndRecordLimits:
    def test_value_under_limit_allowed(self):
        b = make_boundary()
        b.check("wire_transfer", access_mode=AccessMode.EXECUTE, value=500.0)

    def test_value_over_limit_denied(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("wire_transfer", access_mode=AccessMode.EXECUTE, value=5000.0)
        assert exc_info.value.rule == "MAX_VALUE_EXCEEDED"

    def test_record_count_over_limit_denied(self):
        b = make_boundary()
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("wire_transfer", access_mode=AccessMode.EXECUTE, value=1.0, record_count=100)
        assert exc_info.value.rule == "MAX_RECORDS_EXCEEDED"


class TestKillSwitch:
    def test_kill_switch_flag_blocks_everything(self):
        b = make_boundary(kill_switch=True)
        with pytest.raises(KillSwitchActive):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_kill_switch_env_var_blocks_everything(self, monkeypatch):
        monkeypatch.setenv("TEST_KILL_SWITCH", "true")
        b = make_boundary(kill_switch_env="TEST_KILL_SWITCH")
        with pytest.raises(KillSwitchActive):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_kill_switch_env_var_off_allows_calls(self, monkeypatch):
        monkeypatch.setenv("TEST_KILL_SWITCH", "0")
        b = make_boundary(kill_switch_env="TEST_KILL_SWITCH")
        b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_programmatic_engage_disengage(self):
        b = make_boundary()
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        b.engage_kill_switch()
        with pytest.raises(KillSwitchActive):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)
        b.disengage_kill_switch()
        b.check("read_db", access_mode=AccessMode.READ_ONLY)


class TestQuarantine:
    def test_quarantined_agent_denies_all(self):
        b = make_boundary(autonomy=AutonomyLevel.QUARANTINED)
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", access_mode=AccessMode.READ_ONLY)
        assert exc_info.value.rule == "AGENT_QUARANTINED"


class TestAutonomyApproval:
    def test_human_approval_required_autonomy_always_needs_approval(self):
        b = make_boundary(autonomy=AutonomyLevel.HUMAN_APPROVAL_REQUIRED)
        with pytest.raises(ApprovalRequired):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_recommend_only_allows_read_but_not_write(self):
        b = make_boundary(autonomy=AutonomyLevel.RECOMMEND_ONLY)
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        with pytest.raises(ApprovalRequired):
            b.check("send_email", access_mode=AccessMode.EXECUTE)

    def test_permission_level_requires_approval_flag(self):
        b = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[
                ToolPermission("send_email", access_mode=AccessMode.EXECUTE, requires_approval=True)
            ],
        )
        with pytest.raises(ApprovalRequired):
            b.check("send_email", access_mode=AccessMode.EXECUTE)


class TestRateLimiting:
    def test_global_rate_limit_enforced(self):
        b = make_boundary(max_actions_per_hour=2)
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        with pytest.raises(RateLimitExceeded):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_per_tool_rate_limit_enforced(self):
        b = Boundary(
            agent_name="agent",
            autonomy=AutonomyLevel.AUTONOMOUS,
            permissions=[
                ToolPermission("read_db", access_mode=AccessMode.READ_ONLY, max_calls_per_hour=1)
            ],
        )
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        with pytest.raises(RateLimitExceeded):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)


class TestValidityWindow:
    def test_not_yet_valid(self):
        b = make_boundary(valid_from=time.time() + 3600)
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", access_mode=AccessMode.READ_ONLY)
        assert exc_info.value.rule == "OUTSIDE_VALID_PERIOD"

    def test_expired(self):
        b = make_boundary(valid_to=time.time() - 3600)
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", access_mode=AccessMode.READ_ONLY)
        assert exc_info.value.rule == "OUTSIDE_VALID_PERIOD"


class TestEnvironment:
    def test_disallowed_environment(self):
        b = make_boundary(
            environment="PRODUCTION",
            allowed_environments=frozenset({"DEV", "TEST"}),
        )
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", access_mode=AccessMode.READ_ONLY)
        assert exc_info.value.rule == "ENVIRONMENT_NOT_ALLOWED"


class TestPolicyHooks:
    def test_custom_hook_can_deny(self):
        def deny_after_hours(ctx):
            return "denied by custom policy hook" if ctx.tool_name == "read_db" else None

        b = make_boundary(policy_hooks=[deny_after_hours])
        with pytest.raises(BoundaryViolation) as exc_info:
            b.check("read_db", access_mode=AccessMode.READ_ONLY)
        assert "custom policy hook" in str(exc_info.value)

    def test_hook_error_fails_closed_by_default(self):
        def broken_hook(ctx):
            raise RuntimeError("boom")

        b = make_boundary(policy_hooks=[broken_hook])
        with pytest.raises(BoundaryViolation):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_hook_error_can_fail_open_if_configured(self):
        def broken_hook(ctx):
            raise RuntimeError("boom")

        b = make_boundary(policy_hooks=[broken_hook], fail_closed_on_hook_error=False)
        b.check("read_db", access_mode=AccessMode.READ_ONLY)  # should not raise
