from __future__ import annotations

import pytest

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ConfigurationError,
    ToolPermission,
)
from toolboundary.tokens import TokenIssuer


def make_boundary_with_issuer(**overrides) -> Boundary:
    defaults = dict(
        agent_name="agent-1",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("crm_api", access_mode=AccessMode.READ_ONLY)],
        token_issuer=TokenIssuer(secret="test-secret", ttl_seconds=30),
    )
    defaults.update(overrides)
    return Boundary(**defaults)


def test_check_and_authorize_returns_valid_token_on_allow():
    boundary = make_boundary_with_issuer()
    token = boundary.check_and_authorize("crm_api", access_mode=AccessMode.READ_ONLY)
    assert token.agent_name == "agent-1"
    assert token.tool_name == "crm_api"


def test_check_and_authorize_raises_same_as_check_on_deny():
    boundary = make_boundary_with_issuer()
    with pytest.raises(BoundaryViolation):
        boundary.check_and_authorize("unregistered_tool", access_mode=AccessMode.READ_ONLY)


def test_check_and_authorize_without_issuer_configured_raises_configuration_error():
    boundary = Boundary(
        agent_name="agent-1",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("crm_api", access_mode=AccessMode.READ_ONLY)],
        # no token_issuer passed
    )
    with pytest.raises(ConfigurationError):
        boundary.check_and_authorize("crm_api", access_mode=AccessMode.READ_ONLY)


def test_plain_check_still_works_when_issuer_is_configured():
    """Configuring a token_issuer must not change the behavior of plain check()."""
    boundary = make_boundary_with_issuer()
    # should not raise -- no token involved for plain check()
    boundary.check("crm_api", access_mode=AccessMode.READ_ONLY)
