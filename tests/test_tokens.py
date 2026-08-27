from __future__ import annotations

import time

import pytest

from toolboundary.tokens import (
    AuthorizationToken,
    InMemoryTokenStore,
    TokenExpired,
    TokenInvalid,
    TokenIssuer,
)


def test_issue_and_verify_roundtrip():
    issuer = TokenIssuer(secret="test-secret", ttl_seconds=30)
    token = issuer.issue(agent_name="agent-1", tool_name="crm_api", operation="READ")
    issuer.verify(token, expected_agent_name="agent-1", expected_tool_name="crm_api")


def test_wire_serialization_roundtrip():
    issuer = TokenIssuer(secret="test-secret")
    token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
    wire = token.to_wire()
    restored = AuthorizationToken.from_wire(wire)
    issuer.verify(restored, expected_agent_name="agent-1", expected_tool_name="crm_api")


def test_tampered_token_rejected():
    issuer = TokenIssuer(secret="test-secret")
    token = issuer.issue(agent_name="agent-1", tool_name="crm_api")

    # Flip the tool_name by re-encoding a tampered payload with the original signature
    tampered = AuthorizationToken(
        token_id=token.token_id,
        agent_name=token.agent_name,
        tool_name="different_tool",  # tampered
        operation=token.operation,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        signature=token.signature,  # stale signature, won't match tampered payload
    )
    with pytest.raises(TokenInvalid):
        issuer.verify(tampered, expected_tool_name="different_tool")


def test_wrong_secret_rejected():
    issuer_a = TokenIssuer(secret="secret-a")
    issuer_b = TokenIssuer(secret="secret-b")
    token = issuer_a.issue(agent_name="agent-1", tool_name="crm_api")
    with pytest.raises(TokenInvalid):
        issuer_b.verify(token)


def test_expired_token_rejected():
    issuer = TokenIssuer(secret="test-secret", ttl_seconds=0.01)
    token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
    time.sleep(0.05)
    with pytest.raises(TokenExpired):
        issuer.verify(token)


def test_wrong_scope_rejected():
    issuer = TokenIssuer(secret="test-secret")
    token = issuer.issue(agent_name="agent-1", tool_name="crm_api", operation="READ")

    with pytest.raises(TokenInvalid):
        issuer.verify(token, expected_agent_name="agent-2")

    with pytest.raises(TokenInvalid):
        issuer.verify(token, expected_tool_name="other_tool")

    with pytest.raises(TokenInvalid):
        issuer.verify(token, expected_operation="WRITE")


class TestTokenStoreSingleUse:
    def test_first_use_succeeds_second_fails(self):
        store = InMemoryTokenStore()
        assert store.mark_used("tok-1", expires_at=time.time() + 30) is True
        assert store.mark_used("tok-1", expires_at=time.time() + 30) is False

    def test_is_used_reflects_state(self):
        store = InMemoryTokenStore()
        assert store.is_used("tok-1") is False
        store.mark_used("tok-1", expires_at=time.time() + 30)
        assert store.is_used("tok-1") is True

    def test_gc_removes_expired_entries(self):
        store = InMemoryTokenStore()
        store.mark_used("tok-old", expires_at=time.time() - 1)  # already expired
        store.mark_used("tok-new", expires_at=time.time() + 30)
        # trigger gc via another call
        store.mark_used("tok-trigger", expires_at=time.time() + 30)
        assert store.is_used("tok-old") is False
        assert store.is_used("tok-new") is True
