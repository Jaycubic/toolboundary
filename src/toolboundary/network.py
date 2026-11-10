"""
toolboundary.network
---------------------
Optional network-layer enforcement.

Everything in this module is **off by default** and adds zero cost if you
never import it: the core `toolboundary` package does not import this
module, and this module has zero third-party dependencies (stdlib
`http.server` + `urllib` only), so enabling it never pulls in extra
dependencies or slows down the common in-process-only case.

What problem this solves
-------------------------
`Boundary.check()` and the decorator/LangChain wrappers are an
**application-layer** control: they work as long as the agent's code
actually calls through ToolBoundary. If a compromised or carelessly written
agent has *any* code path that reaches a tool's real network endpoint
directly, those wrappers cannot see or stop it.

`NetworkEnforcer` closes that gap for HTTP-based tools by making the
tool's real endpoint reachable *only* through a local proxy that demands
a valid, unexpired, single-use `AuthorizationToken` (see
`toolboundary.tokens`) on every request. The token is only obtainable by
calling `Boundary.check()` first, provided the agent cannot read the
signing secret (see `toolboundary.tokens`). An agent that tries to call the real
endpoint directly either can't reach it (if you've also restricted
network egress to force traffic through the proxy -- recommended for a
genuine guarantee) or gets rejected by the proxy for lacking a valid
token.

Design goals
------------
- **Optional**: importing `toolboundary` never imports this module.
- **Lightweight**: stdlib only, no event loop framework, minimal memory.
- **Fast**: token verification is a single HMAC comparison (microseconds);
  the proxy adds effectively no latency beyond the network hop that would
  have happened anyway.
- **Fail closed**: any missing, malformed, expired, wrong-scope, or
  already-used token results in an immediate 403, before any bytes are
  forwarded to the upstream tool.

This is deliberately scoped to HTTP(S) tool calls, the overwhelmingly
common case for AI agent tool-calling (REST APIs, internal microservices,
SaaS connectors). It is not a general-purpose firewall or a replacement
for real network segmentation -- see the README's "Known Limitations"
section.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import logging
import posixpath
import socketserver
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from .enums import AccessMode
from .tokens import AuthorizationToken, InMemoryTokenStore, TokenExpired, TokenInvalid, TokenIssuer

_logger = logging.getLogger("toolboundary.network")

AUTH_HEADER = "X-ToolBoundary-Token"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ACCESS_RANK = {
    AccessMode.READ_ONLY.value: 0,
    AccessMode.WRITE.value: 1,
    AccessMode.EXECUTE.value: 2,
    AccessMode.ADMIN.value: 3,
}
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 3xx responses to the client instead of following them off-route."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_upstream_opener = urllib.request.build_opener(_NoRedirectHandler)


def _method_allowed(access_mode: str | None, method: str) -> bool:
    """A token without a write-capable access mode may only use safe methods."""
    if method.upper() in _SAFE_METHODS:
        return True
    return _ACCESS_RANK.get(access_mode or "", 0) >= _ACCESS_RANK[AccessMode.WRITE.value]


def _resolve_target(base: str | None, rest: str) -> str | None:
    """Join a client path to an operator-configured base without changing authority."""
    if base is None:
        return None
    base_parts = urlsplit(base)
    path, separator, query = rest.partition("?")
    decoded_path = unquote(path)
    if "\\" in decoded_path or "\x00" in decoded_path:
        return None
    if any(segment == ".." for segment in decoded_path.split("/")):
        return None

    clean_path = posixpath.join(base_parts.path or "/", path.lstrip("/"))
    target = f"{base_parts.scheme}://{base_parts.netloc}{clean_path}"
    if separator:
        target += f"?{query}"
    if urlsplit(target).netloc != base_parts.netloc:
        return None
    return target


@dataclass(frozen=True)
class UpstreamRoute:
    """Maps a tool_name to the real upstream base URL it should proxy to.

    ``required_agent`` restricts the route to tokens issued for one agent.
    ``require_request_binding`` rejects tokens not bound to the exact method,
    path and body; use it whenever limits depend on the request contents.
    """

    tool_name: str
    upstream_base_url: str
    required_operation: str | None = None
    required_agent: str | None = None
    require_request_binding: bool = False


class NetworkEnforcer:
    """
    A local HTTP proxy that only forwards requests carrying a valid,
    unexpired, single-use ToolBoundary authorization token.

    Typical usage
    -------------
    >>> from toolboundary.tokens import TokenIssuer
    >>> from toolboundary.network import NetworkEnforcer, UpstreamRoute
    >>>
    >>> issuer = TokenIssuer(secret="shared-secret-also-used-by-boundary")
    >>> enforcer = NetworkEnforcer(
    ...     issuer=issuer,
    ...     routes=[
    ...         UpstreamRoute("crm_api", "https://internal-crm.example.com"),
    ...     ],
    ... )
    >>> enforcer.start(host="127.0.0.1", port=8765)  # runs in a background thread
    >>>
    >>> # Agent code now calls http://127.0.0.1:8765/crm_api/... with the
    >>> # X-ToolBoundary-Token header set to a token obtained from
    >>> # boundary.check(..., issue_network_token=True)
    >>>
    >>> enforcer.stop()

    This is intentionally a *thin* reverse proxy: it validates the token,
    strips it, and forwards the request byte-for-byte to the mapped
    upstream. It does not parse or transform tool-specific payloads.
    """

    def __init__(
        self,
        issuer: TokenIssuer,
        routes: list[UpstreamRoute],
        *,
        token_store: InMemoryTokenStore | None = None,
        on_denied: Callable[[str, str], None] | None = None,
        max_body_bytes: int = 10 * 1024 * 1024,
        max_response_bytes: int = 50 * 1024 * 1024,
        socket_timeout: float = 30.0,
    ) -> None:
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes must be non-negative.")
        if max_response_bytes < 0:
            raise ValueError("max_response_bytes must be non-negative.")
        if socket_timeout <= 0:
            raise ValueError("socket_timeout must be positive.")
        self._max_response_bytes = max_response_bytes
        self._socket_timeout = socket_timeout
        self._issuer = issuer
        self._routes = {r.tool_name: r for r in routes}
        self._token_store = token_store or InMemoryTokenStore()
        self._on_denied = on_denied
        self._max_body_bytes = max_body_bytes
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def add_route(self, route: UpstreamRoute) -> None:
        self._routes[route.tool_name] = route

    # -- lifecycle ---------------------------------------------------------

    def start(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        handler_cls = _make_handler(self)
        self._server = socketserver.ThreadingTCPServer((host, port), handler_cls)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        _logger.info("toolboundary.network: enforcer listening on %s:%s", host, port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None

    @property
    def is_running(self) -> bool:
        return self._server is not None

    # -- core decision -------------------------------------------------------

    def authorize_and_resolve(
        self,
        tool_name: str,
        token_wire: str | None,
        *,
        method: str = "GET",
        path: str = "",
    ) -> tuple[bool, str, str | None]:
        """
        Returns (allowed, reason, upstream_base_url).

        `reason` is a short machine-readable string useful for logs/audit,
        always populated whether allowed or denied. `method` and `path`
        describe the request the token is being spent on.
        """
        allowed, reason, base, _token = self._authorize_request(
            tool_name, token_wire, method, path
        )
        return allowed, reason, base

    def _authorize_request(
        self, tool_name: str, token_wire: str | None, method: str, path: str
    ) -> tuple[bool, str, str | None, AuthorizationToken | None]:
        route = self._routes.get(tool_name)
        if route is None:
            return False, "UNKNOWN_ROUTE", None, None

        if not token_wire:
            return False, "MISSING_TOKEN", None, None

        try:
            token = AuthorizationToken.from_wire(token_wire)
        except Exception:  # noqa: BLE001
            return False, "MALFORMED_TOKEN", None, None

        try:
            self._issuer.verify(
                token,
                expected_agent_name=route.required_agent,
                expected_tool_name=tool_name,
                expected_operation=route.required_operation,
            )
        except TokenExpired:
            return False, "TOKEN_EXPIRED", None, None
        except TokenInvalid:
            return False, "TOKEN_INVALID", None, None
        except Exception:  # noqa: BLE001
            return False, "MALFORMED_TOKEN", None, None

        if not _method_allowed(token.access_mode, method):
            return False, "TOKEN_METHOD_NOT_ALLOWED", None, None
        if route.require_request_binding and None in (token.method, token.path, token.body_sha256):
            return False, "TOKEN_NOT_REQUEST_BOUND", None, None
        if token.method is not None and token.method != method.upper():
            return False, "TOKEN_REQUEST_MISMATCH", None, None
        if token.path is not None and token.path != path:
            return False, "TOKEN_REQUEST_MISMATCH", None, None

        first_use = self._token_store.mark_used(token.token_id, token.expires_at)
        if not first_use:
            return False, "TOKEN_ALREADY_USED", None, None

        return True, "ALLOWED", route.upstream_base_url, token


def _make_handler(enforcer: NetworkEnforcer) -> type[http.server.BaseHTTPRequestHandler]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = enforcer._socket_timeout  # noqa: SLF001

        def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
            _logger.debug("toolboundary.network: " + fmt, *args)

        def _notify_denied(self, tool_name: str, reason: str) -> None:
            if enforcer._on_denied:  # noqa: SLF001
                try:
                    enforcer._on_denied(tool_name, reason)  # noqa: SLF001
                except Exception:  # noqa: BLE001
                    _logger.debug(
                        "toolboundary.network: on_denied callback raised", exc_info=True
                    )

        def _reject(self, status: int, body: bytes) -> None:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _deny(self, tool_name: str, reason: str) -> None:
            self._notify_denied(tool_name, reason)
            self._reject(403, f'{{"error":"denied","reason":"{reason}"}}'.encode())

        def _relay(self, status: int, headers: Any, source: Any) -> None:
            limit = enforcer._max_response_bytes  # noqa: SLF001
            response_body = source.read(limit + 1)
            if len(response_body) > limit:
                self._reject(502, b'{"error":"upstream_response_too_large"}')
                return
            self.send_response(status)
            for key, value in headers:
                if key.lower() not in _HOP_BY_HOP_HEADERS | {"content-length"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def _content_length(self) -> int | None:
            values = self.headers.get_all("Content-Length") or []
            if len(values) > 1:
                return None
            raw = (values[0] if values else "0").strip()
            return int(raw) if raw.isascii() and raw.isdigit() else None

        def _handle(self) -> None:
            # Path convention: /<tool_name>/<rest-of-path>
            parts = self.path.lstrip("/").split("/", 1)
            tool_name = parts[0] if parts else ""
            rest = parts[1] if len(parts) > 1 else ""

            token_wire = self.headers.get(AUTH_HEADER)
            allowed, reason, upstream_base, token = enforcer._authorize_request(  # noqa: SLF001
                tool_name, token_wire, self.command, rest
            )

            if not allowed:
                self._deny(tool_name, reason)
                return

            target_url = _resolve_target(upstream_base, rest)
            if target_url is None:
                self._notify_denied(tool_name, "BAD_PATH")
                self._reject(400, b'{"error":"bad_path"}')
                return

            if self.headers.get("Transfer-Encoding") is not None:
                self._reject(400, b'{"error":"unsupported_transfer_encoding"}')
                return

            content_length = self._content_length()
            if content_length is None:
                self._reject(400, b'{"error":"invalid_content_length"}')
                return
            if content_length > enforcer._max_body_bytes:  # noqa: SLF001
                self._reject(413, b'{"error":"body_too_large"}')
                return
            try:
                body = self.rfile.read(content_length) if content_length else None
            except OSError:
                self.close_connection = True
                return

            if token is not None and token.body_sha256 is not None:
                actual = hashlib.sha256(body or b"").hexdigest()
                if not hmac.compare_digest(actual, token.body_sha256):
                    self._deny(tool_name, "TOKEN_REQUEST_MISMATCH")
                    return

            excluded = _HOP_BY_HOP_HEADERS | {"host", AUTH_HEADER.lower(), "content-length"}
            forward_headers = {k: v for k, v in self.headers.items() if k.lower() not in excluded}

            try:
                # S310: target_url retains the authority from the registered route.
                req = urllib.request.Request(  # noqa: S310
                    target_url, data=body, headers=forward_headers, method=self.command
                )
                with _upstream_opener.open(req, timeout=30) as resp:
                    self._relay(resp.status, resp.getheaders(), resp)
            except urllib.error.HTTPError as exc:
                self._relay(exc.code, exc.headers.items(), exc)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("toolboundary.network: upstream request failed: %s", exc)
                self._reject(502, b'{"error":"upstream_unreachable"}')

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
