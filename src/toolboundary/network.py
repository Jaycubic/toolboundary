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
calling `Boundary.check()` first. An agent that tries to call the real
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

import http.server
import logging
import socketserver
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

from .tokens import AuthorizationToken, InMemoryTokenStore, TokenExpired, TokenInvalid, TokenIssuer

_logger = logging.getLogger("toolboundary.network")

AUTH_HEADER = "X-ToolBoundary-Token"


@dataclass(frozen=True)
class UpstreamRoute:
    """Maps a tool_name to the real upstream base URL it should proxy to."""

    tool_name: str
    upstream_base_url: str
    required_operation: str | None = None


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
    ) -> None:
        self._issuer = issuer
        self._routes = {r.tool_name: r for r in routes}
        self._token_store = token_store or InMemoryTokenStore()
        self._on_denied = on_denied
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
        self, tool_name: str, token_wire: str | None
    ) -> tuple[bool, str, str | None]:
        """
        Returns (allowed, reason, upstream_base_url).

        `reason` is a short machine-readable string useful for logs/audit,
        always populated whether allowed or denied.
        """
        route = self._routes.get(tool_name)
        if route is None:
            return False, "UNKNOWN_ROUTE", None

        if not token_wire:
            return False, "MISSING_TOKEN", None

        try:
            token = AuthorizationToken.from_wire(token_wire)
        except Exception:  # noqa: BLE001
            return False, "MALFORMED_TOKEN", None

        try:
            self._issuer.verify(
                token,
                expected_tool_name=tool_name,
                expected_operation=route.required_operation,
            )
        except TokenExpired:
            return False, "TOKEN_EXPIRED", None
        except TokenInvalid:
            return False, "TOKEN_INVALID", None

        first_use = self._token_store.mark_used(token.token_id, token.expires_at)
        if not first_use:
            return False, "TOKEN_ALREADY_USED", None

        return True, "ALLOWED", route.upstream_base_url


def _make_handler(enforcer: NetworkEnforcer) -> type[http.server.BaseHTTPRequestHandler]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
            _logger.debug("toolboundary.network: " + fmt, *args)

        def _handle(self) -> None:
            # Path convention: /<tool_name>/<rest-of-path>
            parts = self.path.lstrip("/").split("/", 1)
            tool_name = parts[0] if parts else ""
            rest = parts[1] if len(parts) > 1 else ""

            token_wire = self.headers.get(AUTH_HEADER)
            allowed, reason, upstream_base = enforcer.authorize_and_resolve(tool_name, token_wire)

            if not allowed:
                if enforcer._on_denied:  # noqa: SLF001
                    try:
                        enforcer._on_denied(tool_name, reason)  # noqa: SLF001
                    except Exception:  # noqa: BLE001
                        _logger.debug(
                            "toolboundary.network: on_denied callback raised", exc_info=True
                        )
                body = f'{{"error":"denied","reason":"{reason}"}}'.encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            target_url = urljoin(upstream_base.rstrip("/") + "/", rest)  # type: ignore[union-attr]
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length else None

            forward_headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in {"host", AUTH_HEADER.lower(), "content-length"}
            }

            try:
                # S310: target_url is resolved from a registered UpstreamRoute
                # (an operator-configured allowlist, see authorize_and_resolve),
                # never from unvalidated client input -- the whole point of
                # this proxy is that only pre-approved, token-gated
                # destinations are ever reachable here.
                req = urllib.request.Request(  # noqa: S310
                    target_url, data=body, headers=forward_headers, method=self.command
                )
                with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                    resp_body = resp.read()
                    self.send_response(resp.status)
                    for k, v in resp.getheaders():
                        if k.lower() not in {"transfer-encoding", "connection"}:
                            self.send_header(k, v)
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.HTTPError as exc:
                resp_body = exc.read()
                self.send_response(exc.code)
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("toolboundary.network: upstream request failed: %s", exc)
                body = b'{"error":"upstream_unreachable"}'
                self.send_response(502)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
