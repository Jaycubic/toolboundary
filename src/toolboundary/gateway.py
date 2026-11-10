"""
toolboundary.gateway
--------------------
A policy gateway that runs outside the agent's process.

The in-process APIs and the token proxy trust the process that calls them. A
compromised agent can read a signing secret held in its own memory, or declare
a small ``value`` and then send a large one. The gateway removes that trust:

- The ``Boundary`` lives in the gateway. An agent only holds a key that
  identifies it, and has nothing it can use to issue an approval.
- Every allowed request must match an operator-written ``GatewayRule``.
  Anything else is denied.
- Operation, access mode, value and record count come from that rule and from
  the request the gateway will actually forward, never from agent claims.
- Upstream credentials are added by the gateway, so the agent never holds them.

This only protects a real deployment if the gateway runs as a different OS
user or in a different container, the agent has no direct network route to the
tools, and the agent doesn't hold the tools' credentials. See docs/GATEWAY.md.

Like ``toolboundary.network``, this module is stdlib-only and is never imported
by the core package.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import importlib
import ipaddress
import json
import logging
import os
import re
import socketserver
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from .boundary import Boundary
from .enums import AccessMode, ViolationReason
from .exceptions import (
    ApprovalRequired,
    BoundaryViolation,
    ConfigurationError,
    ProviderAuthorizationDenied,
    ProviderUnavailable,
    RateLimitExceeded,
)
from .network import _HOP_BY_HOP_HEADERS, _NoRedirectHandler, _resolve_target

_logger = logging.getLogger("toolboundary.gateway")

AGENT_KEY_HEADER = "X-ToolBoundary-Agent-Key"
DENIED_HEADER = "X-ToolBoundary-Denied"

_MIN_AGENT_KEY_LENGTH = 32
_BASE_FORWARDED_HEADERS = frozenset(
    {"accept", "accept-language", "content-type", "if-match", "if-none-match", "user-agent"}
)
_BLOCKED_RESPONSE_HEADERS = _HOP_BY_HOP_HEADERS | {
    "content-length",
    "set-cookie",
    DENIED_HEADER.lower(),
}
_REFUSED_PATH_ESCAPES = ("%2f", "%5c", "%25", "%3b", "%23", "%3f")
_TEMPLATE_PARAMETER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")

_upstream_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirectHandler
)


class ExtractionError(ValueError):
    """A rule could not read a required value from the request. The request is denied."""


class _RequestDenied(Exception):
    def __init__(self, status: int, reason: str) -> None:
        self.status = status
        self.reason = reason
        super().__init__(reason)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExtractionError("JSON body has a duplicate key.")
        result[key] = value
    return result


def _reject_constant(name: str) -> None:
    raise ExtractionError(f"JSON body contains {name}.")


class GatewayRequest:
    """The request as the gateway will forward it. Passed to value extractors."""

    def __init__(
        self,
        method: str,
        path: str,
        query: Mapping[str, str],
        headers: Mapping[str, str],
        body: bytes,
    ) -> None:
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self._parsed: Any = None
        self._is_parsed = False

    def json(self) -> Any:
        """Parse the body as strict JSON, refusing input parsers may read differently."""
        if self._is_parsed:
            return self._parsed
        media_type, _, parameters = self.headers.get("content-type", "").partition(";")
        if media_type.strip().lower() != "application/json":
            raise ExtractionError("Content-Type must be application/json.")
        for parameter in parameters.split(";"):
            name, _, value = parameter.partition("=")
            if name.strip().lower() == "charset" and value.strip(' "').lower() != "utf-8":
                raise ExtractionError("JSON body must be UTF-8.")
        try:
            text = self.body.decode("utf-8")
            if text.startswith("﻿"):
                raise ExtractionError("JSON body must not start with a byte-order mark.")
            self._parsed = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (ValueError, RecursionError) as exc:
            raise ExtractionError("Request body is not valid JSON.") from exc
        self._is_parsed = True
        return self._parsed


Extractor = Callable[[GatewayRequest], Any]


def _walk_json(request: GatewayRequest, path: str) -> Any:
    current = request.json()
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ExtractionError(f"JSON field {path!r} is missing.")
        current = current[part]
    return current


def json_field(path: str) -> Extractor:
    """Read a required value from the JSON body, for example ``payment.amount``."""

    def extract(request: GatewayRequest) -> Any:
        return _walk_json(request, path)

    return extract


def json_array_length(path: str) -> Extractor:
    """Use the length of a required JSON array as the value, for example a record count."""

    def extract(request: GatewayRequest) -> int:
        value = _walk_json(request, path)
        if not isinstance(value, list):
            raise ExtractionError(f"JSON field {path!r} is not an array.")
        return len(value)

    return extract


def query_param(name: str) -> Extractor:
    """Read a required query parameter. It must also be in ``allowed_query``."""

    def extract(request: GatewayRequest) -> str:
        if name not in request.query:
            raise ExtractionError(f"Query parameter {name!r} is missing.")
        return request.query[name]

    return extract


def constant(value: Any) -> Extractor:
    """Use a fixed value, for endpoints with a known cost or record count."""

    def extract(_request: GatewayRequest) -> Any:
        return value

    return extract


def _compile_template(template: str) -> re.Pattern[str]:
    if template.startswith("/"):
        raise ConfigurationError("GatewayRule paths are written without a leading slash.")
    pattern = ""
    position = 0
    for match in _TEMPLATE_PARAMETER.finditer(template):
        pattern += re.escape(template[position : match.start()]) + "[^/]+"
        position = match.end()
    return re.compile(pattern + re.escape(template[position:]))


@dataclass(frozen=True)
class GatewayRule:
    """One request shape an agent may make. Requests matching no rule are denied.

    ``path`` is literal apart from ``{name}`` placeholders, which each match one
    path segment. Query parameters are denied unless listed in ``allowed_query``.
    """

    method: str
    path: str
    access_mode: AccessMode
    operation: str | None = None
    value: Extractor | None = None
    record_count: Extractor | None = None
    allowed_query: frozenset[str] = frozenset()
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ConfigurationError(f"Unsupported GatewayRule method: {self.method!r}")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "_pattern", _compile_template(self.path))

    def matches(self, method: str, path: str) -> bool:
        return method == self.method and self._pattern.fullmatch(path) is not None


CredentialSource = Union[Mapping[str, str], Callable[[], Mapping[str, str]]]


def _is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class GatewayRoute:
    """A tool the gateway can reach, its allowed requests, and its credentials."""

    tool_name: str
    upstream_base_url: str
    rules: tuple[GatewayRule, ...]
    credential_headers: CredentialSource | None = field(default=None, repr=False)
    forwarded_headers: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.tool_name or "/" in self.tool_name:
            raise ConfigurationError("GatewayRoute tool_name must be one non-empty path segment.")
        if not self.rules:
            raise ConfigurationError(f"GatewayRoute {self.tool_name!r} needs at least one rule.")
        parts = urlsplit(self.upstream_base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigurationError("upstream_base_url must be an http(s) URL with a host.")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConfigurationError(
                "upstream_base_url must not contain credentials, a query, or a fragment."
            )
        if (
            self.credential_headers is not None
            and parts.scheme != "https"
            and not _is_loopback(parts.hostname)
        ):
            raise ConfigurationError(
                "Credentials can only be sent to an https or loopback upstream."
            )

    def credentials(self) -> dict[str, str]:
        source = self.credential_headers
        if source is None:
            return {}
        return dict(source() if callable(source) else source)


class GatewayAgent:
    """An agent's identity at the gateway. Only a hash of its key is kept."""

    def __init__(self, boundary: Boundary, key: str) -> None:
        if len(key) < _MIN_AGENT_KEY_LENGTH:
            raise ConfigurationError(
                f"Agent keys must be at least {_MIN_AGENT_KEY_LENGTH} characters. "
                "Use generate_agent_key()."
            )
        if not boundary.strict_limits:
            raise ConfigurationError(
                f"Boundary {boundary.agent_name!r} needs strict_limits=True to be used "
                "with a gateway, so a rule without a value can't skip a limit."
            )
        self.boundary = boundary
        self.key_digest = _digest_key(key)

    @property
    def name(self) -> str:
        return self.boundary.agent_name


def _digest_key(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8", "surrogateescape")).digest()


def generate_agent_key() -> str:
    """Create a random key suitable for ``GatewayAgent``."""
    import secrets

    return secrets.token_urlsafe(32)


def _parse_target(target: str) -> tuple[str, str, str, str] | None:
    """Split a request target, refusing paths that parsers may read differently.

    Returns (tool_name, raw_rest, decoded_path, raw_query), or None if refused.
    """
    if not target.startswith("/") or "#" in target or ";" in target or "\\" in target:
        return None
    path, _, query = target[1:].partition("?")
    tool_name, _, rest = path.partition("/")
    lowered = rest.lower()
    if not tool_name or any(token in lowered for token in _REFUSED_PATH_ESCAPES):
        return None
    decoded = unquote(rest, errors="replace")
    if "�" in decoded or any(ord(char) < 0x20 or ord(char) == 0x7f for char in decoded):
        return None
    if rest and any(segment in {"", ".", ".."} for segment in decoded.split("/")):
        return None
    raw_rest = f"{rest}?{query}" if query else rest
    return tool_name, raw_rest, decoded, query


def _parse_query(raw_query: str, allowed: frozenset[str]) -> dict[str, str]:
    if not raw_query:
        return {}
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise _RequestDenied(400, "INVALID_QUERY") from exc
    result: dict[str, str] = {}
    for name, value in pairs:
        if name not in allowed or name in result:
            raise _RequestDenied(403, "QUERY_NOT_ALLOWED")
        result[name] = value
    return result


class _GatewayServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: Any, max_connections: int) -> None:
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def verify_request(self, request: Any, client_address: Any) -> bool:
        return self._slots.acquire(blocking=False)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class PolicyGateway:
    """Authenticates agents, applies policy, and forwards allowed requests."""

    def __init__(
        self,
        agents: list[GatewayAgent],
        routes: list[GatewayRoute],
        *,
        max_body_bytes: int = 10 * 1024 * 1024,
        max_response_bytes: int = 50 * 1024 * 1024,
        socket_timeout: float = 30.0,
        upstream_timeout: float = 30.0,
        max_connections: int = 128,
        ssl_context: ssl.SSLContext | None = None,
        allow_insecure_bind: bool = False,
    ) -> None:
        if not agents:
            raise ConfigurationError("PolicyGateway needs at least one agent.")
        if len({agent.name for agent in agents}) != len(agents):
            raise ConfigurationError("Each gateway agent needs a unique boundary agent_name.")
        if len({agent.key_digest for agent in agents}) != len(agents):
            raise ConfigurationError("Each gateway agent needs its own key.")
        if len({route.tool_name for route in routes}) != len(routes):
            raise ConfigurationError("Each gateway route needs a unique tool_name.")
        if min(max_body_bytes, max_response_bytes) < 0:
            raise ConfigurationError("Size limits must be non-negative.")
        if min(socket_timeout, upstream_timeout, max_connections) <= 0:
            raise ConfigurationError("Timeouts and max_connections must be positive.")
        self._agents = list(agents)
        self._routes = {route.tool_name: route for route in routes}
        self._max_body_bytes = max_body_bytes
        self._max_response_bytes = max_response_bytes
        self._socket_timeout = socket_timeout
        self._upstream_timeout = upstream_timeout
        self._max_connections = max_connections
        self._ssl_context = ssl_context
        self._allow_insecure_bind = allow_insecure_bind
        self._server: _GatewayServer | None = None
        self._thread: threading.Thread | None = None

    def _bind(self, host: str, port: int) -> _GatewayServer:
        if self._ssl_context is None and not self._allow_insecure_bind and not _is_loopback(host):
            raise ConfigurationError(
                "Binding to a non-loopback address needs ssl_context, because agent keys "
                "would otherwise cross the network unencrypted."
            )
        server = _GatewayServer((host, port), _make_handler(self), self._max_connections)
        if self._ssl_context is not None:
            server.socket = self._ssl_context.wrap_socket(
                server.socket, server_side=True, do_handshake_on_connect=False
            )
        return server

    @property
    def port(self) -> int:
        if self._server is None:
            raise ConfigurationError("The gateway is not running.")
        return int(self._server.server_address[1])

    def start(self, host: str = "127.0.0.1", port: int = 8780) -> None:
        """Serve from a background thread. Use ``serve_forever`` for a dedicated process."""
        self._server = self._bind(host, port)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        _logger.info("toolboundary.gateway: listening on %s:%s", host, self.port)

    def serve_forever(self, host: str = "127.0.0.1", port: int = 8780) -> None:
        """Serve from the current thread until interrupted."""
        self._server = self._bind(host, port)
        _logger.info("toolboundary.gateway: listening on %s:%s", host, self.port)
        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()
            self._server = None

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None

    def _authenticate(self, key: str | None) -> GatewayAgent | None:
        supplied = _digest_key(key or "")
        found: GatewayAgent | None = None
        for agent in self._agents:  # Check every agent, so timing doesn't reveal a match.
            if hmac.compare_digest(supplied, agent.key_digest):
                found = agent
        return found if key else None


def _audit_gateway_denial(
    agent: GatewayAgent, tool_name: str, reason: str, method: str, path: str
) -> None:
    agent.boundary.audit.record(
        agent_name=agent.name,
        decision="DENY",
        message=f"Gateway denied {method} request: {reason}",
        tool_name=tool_name,
        reason_code=ViolationReason.GATEWAY_REQUEST_DENIED.value,
        metadata={"gateway_reason": reason, "method": method, "path": path[:200]},
    )


def _evaluate(
    agent: GatewayAgent,
    tool_name: str,
    rule: GatewayRule,
    request: GatewayRequest,
) -> Any:
    """Apply policy to the real request. Returns a provider authorization, if any."""
    try:
        value = rule.value(request) if rule.value is not None else None
        record_count = rule.record_count(request) if rule.record_count is not None else None
    except Exception as exc:  # noqa: BLE001 - an extractor failure must deny the request.
        _logger.info("toolboundary.gateway: extraction failed: %s", type(exc).__name__)
        raise _RequestDenied(403, "REQUEST_VALUE_UNREADABLE") from exc

    body_digest = hashlib.sha256(request.body).hexdigest()
    metadata = {"method": request.method, "path": request.path[:200], "body_sha256": body_digest}
    boundary = agent.boundary
    try:
        if boundary._provider is None:  # noqa: SLF001
            boundary.check(
                tool_name,
                operation=rule.operation,
                access_mode=rule.access_mode,
                value=value,
                record_count=record_count,
                metadata=metadata,
            )
            return None
        return boundary.authorize_call(
            tool_name=tool_name,
            operation=rule.operation,
            access_mode=rule.access_mode,
            arguments=dict(metadata, query=dict(request.query)),
            value=value,
            record_count=record_count,
            metadata=metadata,
        )
    except RateLimitExceeded as exc:
        raise _RequestDenied(429, exc.rule or "RATE_LIMIT_EXCEEDED") from exc
    except BoundaryViolation as exc:
        raise _RequestDenied(403, exc.rule or "DENIED") from exc
    except ApprovalRequired as exc:
        raise _RequestDenied(403, ViolationReason.APPROVAL_REQUIRED.value) from exc
    except ProviderAuthorizationDenied as exc:
        raise _RequestDenied(403, ViolationReason.PROVIDER_DENIED.value) from exc
    except ProviderUnavailable as exc:
        raise _RequestDenied(503, ViolationReason.PROVIDER_UNAVAILABLE.value) from exc
    except Exception as exc:  # noqa: BLE001 - never allow on an unexpected policy error.
        _logger.exception("toolboundary.gateway: policy evaluation failed")
        raise _RequestDenied(403, "POLICY_ERROR") from exc


def _make_handler(gateway: PolicyGateway) -> type[http.server.BaseHTTPRequestHandler]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = gateway._socket_timeout  # noqa: SLF001
        server_version = "ToolBoundaryGateway"
        sys_version = ""

        def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
            _logger.debug("toolboundary.gateway: " + fmt, *args)

        def _send_denied(self, status: int, reason: str) -> None:
            body = json.dumps({"error": "denied", "reason": reason}).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(DENIED_HEADER, reason)
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes:
            if self.headers.get("Transfer-Encoding") is not None:
                raise _RequestDenied(400, "UNSUPPORTED_TRANSFER_ENCODING")
            values = self.headers.get_all("Content-Length") or ["0"]
            raw = values[0].strip()
            if len(values) > 1 or len(raw) > 20 or not (raw.isascii() and raw.isdigit()):
                raise _RequestDenied(400, "INVALID_CONTENT_LENGTH")
            length = int(raw)
            if length > gateway._max_body_bytes:  # noqa: SLF001
                raise _RequestDenied(413, "BODY_TOO_LARGE")
            body = self.rfile.read(length) if length else b""
            if len(body) != length:
                raise _RequestDenied(400, "INCOMPLETE_BODY")
            return body

        def _relay(self, status: int, headers: Any, source: Any) -> None:
            limit = gateway._max_response_bytes  # noqa: SLF001
            data = source.read(limit + 1)
            if len(data) > limit:
                raise _RequestDenied(502, "UPSTREAM_RESPONSE_TOO_LARGE")
            self.send_response(status)
            for name, value in headers:
                if name.lower() not in _BLOCKED_RESPONSE_HEADERS:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _forward(
            self,
            route: GatewayRoute,
            target_url: str,
            request: GatewayRequest,
        ) -> tuple[str, str | None]:
            """Send the request upstream. Returns (status text, error type name)."""
            try:
                outgoing = dict(request.headers)
                for name, value in route.credentials().items():
                    outgoing = {k: v for k, v in outgoing.items() if k != name.lower()}
                    outgoing[name] = value
            except Exception as exc:  # noqa: BLE001
                _logger.error("toolboundary.gateway: credential source failed")
                raise _RequestDenied(502, "UPSTREAM_CREDENTIALS_UNAVAILABLE") from exc

            has_body = request.method != "GET" or bool(request.body)
            upstream = urllib.request.Request(  # noqa: S310 - URL comes from the operator's route.
                target_url,
                data=request.body if has_body else None,
                headers=outgoing,
                method=request.method,
            )
            timeout = gateway._upstream_timeout  # noqa: SLF001
            try:
                with _upstream_opener.open(upstream, timeout=timeout) as response:
                    self._relay(response.status, response.getheaders(), response)
                    return str(response.status), None
            except urllib.error.HTTPError as exc:
                self._relay(exc.code, exc.headers.items(), exc)
                return str(exc.code), None
            except _RequestDenied:
                raise
            except Exception as exc:  # noqa: BLE001
                _logger.warning("toolboundary.gateway: upstream failed: %s", type(exc).__name__)
                raise _RequestDenied(502, "UPSTREAM_UNREACHABLE") from exc

        def _process(self, agent: GatewayAgent) -> None:
            parsed = _parse_target(self.path)
            if parsed is None:
                raise _RequestDenied(400, "BAD_PATH")
            tool_name, raw_rest, decoded_path, raw_query = parsed

            body = self._read_body()

            route = gateway._routes.get(tool_name)  # noqa: SLF001
            if route is None:
                raise _RequestDenied(403, "UNKNOWN_ROUTE")
            rule = next((r for r in route.rules if r.matches(self.command, decoded_path)), None)
            if rule is None:
                raise _RequestDenied(403, "REQUEST_NOT_ALLOWED")
            query = _parse_query(raw_query, rule.allowed_query)

            allowed_headers = _BASE_FORWARDED_HEADERS | {
                name.lower() for name in route.forwarded_headers
            }
            headers = {
                name.lower(): value
                for name, value in self.headers.items()
                if name.lower() in allowed_headers
            }
            request = GatewayRequest(self.command, decoded_path, query, headers, body)

            target_url = _resolve_target(route.upstream_base_url.rstrip("/") + "/", raw_rest)
            if target_url is None:
                raise _RequestDenied(400, "BAD_PATH")

            authorization = _evaluate(agent, tool_name, rule, request)
            if authorization is None:
                self._forward(route, target_url, request)
                return

            started_at = time.time()
            error: BaseException | None = None
            result: Any = None
            try:
                status, _ = self._forward(route, target_url, request)
                result = {"status": status}
            except BaseException as exc:
                error = exc
                raise
            finally:
                agent.boundary.record_execution(
                    authorization,
                    result=result,
                    error=error,
                    started_at=started_at,
                    finished_at=time.time(),
                )

        def _handle(self) -> None:
            agent = gateway._authenticate(self.headers.get(AGENT_KEY_HEADER))  # noqa: SLF001
            if agent is None:
                self._send_denied(401, "UNAUTHENTICATED")
                return
            try:
                self._process(agent)
            except _RequestDenied as denied:
                tool_name = self.path.lstrip("/").partition("/")[0].partition("?")[0]
                if denied.reason not in _POLICY_AUDITED_REASONS:
                    _audit_gateway_denial(
                        agent, tool_name[:100], denied.reason, self.command, self.path
                    )
                self._send_denied(denied.status, denied.reason)
            except OSError:
                self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            self._handle()

        def do_PUT(self) -> None:  # noqa: N802
            self._handle()

        def do_PATCH(self) -> None:  # noqa: N802
            self._handle()

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle()

    return _Handler


# Boundary has already written these denials to the audit trail.
_POLICY_AUDITED_REASONS = frozenset(reason.value for reason in ViolationReason) - {
    ViolationReason.GATEWAY_REQUEST_DENIED.value
}


@dataclass(frozen=True)
class GatewayResponse:
    """What the gateway returned. ``denied_reason`` is set only for gateway denials."""

    status: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def denied_reason(self) -> str | None:
        return self.headers.get(DENIED_HEADER.lower())

    def json(self) -> Any:
        return json.loads(self.body)


class GatewayClient:
    """The agent's side of the gateway. It holds an agent key and nothing else."""

    def __init__(
        self,
        base_url: str,
        agent_key: str,
        *,
        timeout: float = 60.0,
        ssl_context: ssl.SSLContext | None = None,
        allow_insecure: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigurationError("base_url must be an http(s) URL with a host.")
        if parts.scheme != "https" and not allow_insecure and not _is_loopback(parts.hostname):
            raise ConfigurationError("Agent keys can only be sent over https or to loopback.")
        self._base_url = base_url.rstrip("/")
        self._agent_key = agent_key
        self._timeout = timeout
        handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirectHandler]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._opener = urllib.request.build_opener(*handlers)

    def request(
        self,
        tool_name: str,
        method: str,
        path: str = "",
        *,
        query: Mapping[str, str] | None = None,
        json_body: Any = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> GatewayResponse:
        """Send one tool request through the gateway."""
        if json_body is not None and body is not None:
            raise ValueError("Pass either json_body or body, not both.")
        outgoing = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            outgoing.setdefault("Content-Type", "application/json")
        outgoing[AGENT_KEY_HEADER] = self._agent_key

        url = f"{self._base_url}/{quote(tool_name, safe='')}/{quote(path.lstrip('/'), safe='/')}"
        if query:
            url += "?" + urlencode(query)
        upstream = urllib.request.Request(  # noqa: S310 - URL comes from the client's config.
            url, data=body, headers=outgoing, method=method.upper()
        )
        try:
            with self._opener.open(upstream, timeout=self._timeout) as response:
                return self._response(response.status, response.getheaders(), response.read())
        except urllib.error.HTTPError as exc:
            return self._response(exc.code, exc.headers.items(), exc.read())

    @staticmethod
    def _response(status: int, headers: Any, body: bytes) -> GatewayResponse:
        return GatewayResponse(status, {name.lower(): value for name, value in headers}, body)


def _load_gateway(reference: str) -> Any:
    module_name, separator, attribute = reference.partition(":")
    if not separator or not module_name or not attribute:
        raise ConfigurationError("--app must look like package.module:name")
    sys.path.insert(0, os.getcwd())
    target = getattr(importlib.import_module(module_name), attribute)
    return target() if callable(target) else target


def main(argv: Optional[list[str]] = None) -> int:  # noqa: UP045
    """Run a gateway in its own process: ``python -m toolboundary.gateway --app mod:build``."""
    from toolboundary.gateway import PolicyGateway as LoadedGateway

    parser = argparse.ArgumentParser(description="Run a ToolBoundary policy gateway.")
    parser.add_argument("--app", required=True, help="module:name of a PolicyGateway or factory")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    options = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    gateway = _load_gateway(options.app)
    if not isinstance(gateway, LoadedGateway):
        parser.error("--app must resolve to a PolicyGateway")
    try:
        gateway.serve_forever(options.host, options.port)
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        parser.exit(1, f"Could not start the gateway: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
