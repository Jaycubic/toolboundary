"""
toolboundary.tokens
--------------------
Short-lived, single-use, HMAC-signed authorization tokens.

Purpose
-------
`Boundary.check()` proves that a call *was* allowed at the moment it was
evaluated. On its own, that is an in-process guarantee only -- nothing
stops the calling code from ignoring the result, or from a completely
different code path calling the tool's real network endpoint directly.

An AuthorizationToken closes that gap by turning "this call is allowed"
into a physical artifact: a signed, time-boxed, single-use credential
tied to the *exact* agent/tool/operation/nonce combination that was
approved. The optional network enforcement layer (`toolboundary.network`)
then requires a valid token in every proxied request and refuses to
forward anything else -- so even a compromised or rewritten agent cannot
reach the real tool endpoint without first passing through
`Boundary.check()` to obtain a fresh token.

This module has zero third-party dependencies (uses stdlib `hmac`,
`hashlib`, `secrets`) so it imposes no cost on users who never enable
network enforcement.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any


class TokenError(Exception):
    """Base class for authorization-token failures."""


class TokenExpired(TokenError):
    pass


class TokenInvalid(TokenError):
    pass


class TokenAlreadyUsed(TokenError):
    pass


@dataclass(frozen=True)
class AuthorizationToken:
    """
    A signed claim that one specific call was approved by a Boundary.

    Tokens are deliberately narrow: they authorize exactly one
    (agent_name, tool_name, operation) tuple, expire quickly (default 30s
    -- long enough for the immediate network hop, short enough that a
    leaked token is nearly worthless), and are single-use when checked
    against a TokenStore.
    """

    token_id: str
    agent_name: str
    tool_name: str
    operation: str | None
    issued_at: float
    expires_at: float
    signature: str

    def to_wire(self) -> str:
        """Serialize to a compact string suitable for an HTTP header."""
        payload = {
            "token_id": self.token_id,
            "agent_name": self.agent_name,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).decode("ascii")
        return f"{encoded}.{self.signature}"

    @staticmethod
    def from_wire(wire: str) -> AuthorizationToken:
        try:
            encoded, signature = wire.rsplit(".", 1)
            raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
            payload = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            raise TokenInvalid(f"Malformed token: {exc}") from exc
        return AuthorizationToken(
            token_id=payload["token_id"],
            agent_name=payload["agent_name"],
            tool_name=payload["tool_name"],
            operation=payload.get("operation"),
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            signature=signature,
        )


class TokenIssuer:
    """
    Issues and verifies AuthorizationTokens using a shared HMAC secret.

    The secret must be shared between whatever process calls
    `Boundary.check()` (which issues tokens) and whatever process runs the
    enforcement proxy (which verifies them). In a single-process
    deployment these are the same process and the secret never leaves
    memory. In a multi-process deployment, supply the same `secret` value
    to both via an environment variable or secrets manager.
    """

    def __init__(self, secret: str | None = None, ttl_seconds: float = 30.0) -> None:
        self._secret = (secret or secrets.token_hex(32)).encode("utf-8")
        self.ttl_seconds = ttl_seconds

    def issue(
        self,
        *,
        agent_name: str,
        tool_name: str,
        operation: str | None = None,
    ) -> AuthorizationToken:
        now = time.time()
        token_id = secrets.token_urlsafe(16)
        payload = {
            "token_id": token_id,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "operation": operation,
            "issued_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        signature = self._sign(payload)
        return AuthorizationToken(signature=signature, **payload)

    def verify(
        self,
        token: AuthorizationToken,
        *,
        expected_agent_name: str | None = None,
        expected_tool_name: str | None = None,
        expected_operation: str | None = None,
    ) -> None:
        """Raises TokenInvalid / TokenExpired if the token does not check out."""
        payload = {
            "token_id": token.token_id,
            "agent_name": token.agent_name,
            "tool_name": token.tool_name,
            "operation": token.operation,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
        }
        expected_sig = self._sign(payload)
        if not hmac.compare_digest(expected_sig, token.signature):
            raise TokenInvalid("Token signature does not match; token may be forged or corrupted.")

        if time.time() > token.expires_at:
            raise TokenExpired(
                f"Token expired at {token.expires_at}, current time {time.time()}."
            )

        if expected_agent_name is not None and token.agent_name != expected_agent_name:
            raise TokenInvalid("Token was not issued for this agent.")
        if expected_tool_name is not None and token.tool_name != expected_tool_name:
            raise TokenInvalid("Token was not issued for this tool.")
        if expected_operation is not None and token.operation != expected_operation:
            raise TokenInvalid("Token was not issued for this operation.")

    def _sign(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._secret, raw, hashlib.sha256).hexdigest()


class InMemoryTokenStore:
    """
    Tracks which token_ids have already been consumed, to enforce
    single-use semantics and defeat TOCTOU replay (an attacker capturing
    a valid token and reusing it for a second call after the first one
    already executed).

    In-memory by design for the zero-infrastructure default. For
    multi-process deployments, implement the same two-method interface
    (`mark_used`, `is_used`) backed by Redis (SETNX with TTL is a natural
    fit) and pass it to `NetworkEnforcer` -- swapping the store does not
    require changing anything else.
    """

    def __init__(self) -> None:
        self._used: dict[str, float] = {}

    def mark_used(self, token_id: str, expires_at: float) -> bool:
        """Returns True if this is the first use, False if already used."""
        self._gc()
        if token_id in self._used:
            return False
        self._used[token_id] = expires_at
        return True

    def is_used(self, token_id: str) -> bool:
        return token_id in self._used

    def _gc(self) -> None:
        """Drop expired entries so memory doesn't grow unbounded."""
        now = time.time()
        expired = [tid for tid, exp in self._used.items() if exp < now]
        for tid in expired:
            del self._used[tid]
