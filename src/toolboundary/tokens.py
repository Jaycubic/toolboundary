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
forward anything else -- so an agent without the signing secret cannot
reach the real tool endpoint through the proxy without first passing
through `Boundary.check()` to obtain a fresh token.

Trust model: HMAC is symmetric, so any process holding the secret can mint
tokens. Code running inside an agent process that also holds the issuer can
therefore create a token without calling `Boundary.check()`. To defend
against a compromised agent, run the Boundary, issuer and enforcement proxy
in a separate process and never give the agent the secret.

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
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from .enums import AccessMode

_OPTIONAL_CLAIMS = ("access_mode", "method", "path", "body_sha256")


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
    access_mode: str | None = None
    method: str | None = None
    path: str | None = None
    body_sha256: str | None = None

    def claims(self) -> dict[str, Any]:
        """The signed fields. Optional claims are present only when set."""
        payload: dict[str, Any] = {
            "token_id": self.token_id,
            "agent_name": self.agent_name,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        for name in _OPTIONAL_CLAIMS:
            claim = getattr(self, name)
            if claim is not None:
                payload[name] = claim
        return payload

    def to_wire(self) -> str:
        """Serialize to a compact string suitable for an HTTP header."""
        raw = json.dumps(self.claims(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).decode("ascii")
        return f"{encoded}.{self.signature}"

    @staticmethod
    def from_wire(wire: str) -> AuthorizationToken:
        try:
            encoded, signature = wire.rsplit(".", 1)
            raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
            payload = json.loads(raw)
            token = AuthorizationToken(
                token_id=payload["token_id"],
                agent_name=payload["agent_name"],
                tool_name=payload["tool_name"],
                operation=payload.get("operation"),
                issued_at=payload["issued_at"],
                expires_at=payload["expires_at"],
                signature=signature,
                **{name: payload.get(name) for name in _OPTIONAL_CLAIMS},
            )
        except Exception as exc:  # noqa: BLE001
            raise TokenInvalid(f"Malformed token: {exc}") from exc

        required_text = (token.token_id, token.agent_name, token.tool_name)
        optional_text = (token.operation, *(getattr(token, n) for n in _OPTIONAL_CLAIMS))
        timestamps = (token.issued_at, token.expires_at)
        if (
            not all(isinstance(item, str) for item in required_text)
            or not all(item is None or isinstance(item, str) for item in optional_text)
            or any(isinstance(t, bool) or not isinstance(t, (int, float)) for t in timestamps)
        ):
            raise TokenInvalid("Malformed token: a claim has the wrong type.")
        return token


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
        access_mode: AccessMode | str | None = None,
        request_method: str | None = None,
        request_path: str | None = None,
        request_body: bytes | None = None,
    ) -> AuthorizationToken:
        """Issue a token, optionally bound to one exact HTTP request.

        ``access_mode`` limits which HTTP methods the proxy accepts. The
        ``request_*`` values, when given, must match the proxied request:
        ``request_path`` is the path after ``/<tool_name>/``, including any
        query string.
        """
        now = time.time()
        unsigned = AuthorizationToken(
            token_id=secrets.token_urlsafe(16),
            agent_name=agent_name,
            tool_name=tool_name,
            operation=operation,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            signature="",
            access_mode=access_mode.value if isinstance(access_mode, AccessMode) else access_mode,
            method=request_method.upper() if request_method is not None else None,
            path=request_path.lstrip("/") if request_path is not None else None,
            body_sha256=hashlib.sha256(request_body).hexdigest()
            if request_body is not None
            else None,
        )
        return replace(unsigned, signature=self._sign(unsigned.claims()))

    def verify(
        self,
        token: AuthorizationToken,
        *,
        expected_agent_name: str | None = None,
        expected_tool_name: str | None = None,
        expected_operation: str | None = None,
    ) -> None:
        """Raises TokenInvalid / TokenExpired if the token does not check out."""
        expected_sig = self._sign(token.claims())
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input.
        if not hmac.compare_digest(
            expected_sig.encode("ascii"), str(token.signature).encode("utf-8", "replace")
        ):
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
        self._lock = threading.Lock()

    def mark_used(self, token_id: str, expires_at: float) -> bool:
        """Returns True if this is the first use, False if already used."""
        with self._lock:
            self._gc()
            if token_id in self._used:
                return False
            self._used[token_id] = expires_at
            return True

    def is_used(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._used

    def _gc(self) -> None:
        """Drop expired entries so memory doesn't grow unbounded. Caller holds the lock."""
        now = time.time()
        expired = [tid for tid, exp in self._used.items() if exp < now]
        for tid in expired:
            del self._used[tid]
