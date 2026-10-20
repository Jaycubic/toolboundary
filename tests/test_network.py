from __future__ import annotations

import http.server
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import pytest

from toolboundary.network import AUTH_HEADER, NetworkEnforcer, UpstreamRoute, _resolve_target
from toolboundary.tokens import InMemoryTokenStore, TokenIssuer


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """A trivial upstream server used as the 'real tool' behind the proxy."""

    def log_message(self, fmt, *args):  # silence test output
        pass

    def do_GET(self):  # noqa: N802
        body = b'{"ok": true, "path": "%s"}' % self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


@pytest.fixture
def upstream_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def enforcer(upstream_server):
    issuer = TokenIssuer(secret="shared-test-secret", ttl_seconds=30)
    store = InMemoryTokenStore()
    enf = NetworkEnforcer(
        issuer=issuer,
        routes=[UpstreamRoute("crm_api", upstream_server)],
        token_store=store,
    )
    enf.start(host="127.0.0.1", port=0)
    # find the actual bound port
    port = enf._server.server_address[1]  # noqa: SLF001
    yield enf, issuer, port
    enf.stop()


def _proxy_url(port: int, path: str) -> str:
    return f"http://127.0.0.1:{port}/{path}"


@pytest.mark.parametrize(
    ("rest", "reject"),
    [
        ("//evil/x", False),
        ("///evil/x", False),
        ("/../admin", True),
        ("/%2e%2e/admin", True),
        ("/%2E%2E%2Fadmin", True),
        ("\\\\evil", True),
        ("http://evil/x", False),
        ("@evil", False),
        ("?x=@evil", False),
    ],
)
def test_target_resolution_never_leaves_configured_upstream(rest, reject):
    base = "https://approved.example.com/api"
    target = _resolve_target(base, rest)
    if reject:
        assert target is None
    else:
        assert target is not None
        assert urlsplit(target).netloc == "approved.example.com"


def test_target_resolution_preserves_normal_paths_and_queries():
    assert _resolve_target("https://approved.example.com/api", "customers/42?x=1") == (
        "https://approved.example.com/api/customers/42?x=1"
    )


class TestNetworkEnforcement:
    def test_valid_token_allows_request_through(self, enforcer):
        enf, issuer, port = enforcer
        token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
        req = urllib.request.Request(
            _proxy_url(port, "crm_api/customers/1"),
            headers={AUTH_HEADER: token.to_wire()},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            body = resp.read()
            assert b"ok" in body

    def test_missing_token_denied(self, enforcer):
        enf, issuer, port = enforcer
        req = urllib.request.Request(_proxy_url(port, "crm_api/customers/1"))
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403

    def test_unknown_route_denied(self, enforcer):
        enf, issuer, port = enforcer
        token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
        req = urllib.request.Request(
            _proxy_url(port, "unregistered_tool/x"),
            headers={AUTH_HEADER: token.to_wire()},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403

    def test_token_scoped_to_wrong_tool_denied(self, enforcer):
        enf, issuer, port = enforcer
        # token issued for a different tool than the route being called
        token = issuer.issue(agent_name="agent-1", tool_name="other_tool")
        req = urllib.request.Request(
            _proxy_url(port, "crm_api/customers/1"),
            headers={AUTH_HEADER: token.to_wire()},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403

    def test_token_cannot_be_reused(self, enforcer):
        enf, issuer, port = enforcer
        token = issuer.issue(agent_name="agent-1", tool_name="crm_api")

        req1 = urllib.request.Request(
            _proxy_url(port, "crm_api/customers/1"),
            headers={AUTH_HEADER: token.to_wire()},
        )
        with urllib.request.urlopen(req1, timeout=5) as resp:
            assert resp.status == 200

        # second use of the exact same token must be rejected
        req2 = urllib.request.Request(
            _proxy_url(port, "crm_api/customers/1"),
            headers={AUTH_HEADER: token.to_wire()},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req2, timeout=5)
        assert exc_info.value.code == 403

    def test_expired_token_denied(self, upstream_server):
        issuer = TokenIssuer(secret="shared-test-secret", ttl_seconds=0.01)
        enf = NetworkEnforcer(issuer=issuer, routes=[UpstreamRoute("crm_api", upstream_server)])
        enf.start(host="127.0.0.1", port=0)
        port = enf._server.server_address[1]  # noqa: SLF001
        try:
            token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
            time.sleep(0.05)
            req = urllib.request.Request(
                _proxy_url(port, "crm_api/x"), headers={AUTH_HEADER: token.to_wire()}
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 403
        finally:
            enf.stop()

    def test_on_denied_callback_invoked(self, upstream_server):
        denied_calls = []
        issuer = TokenIssuer(secret="shared-test-secret")
        enf = NetworkEnforcer(
            issuer=issuer,
            routes=[UpstreamRoute("crm_api", upstream_server)],
            on_denied=lambda tool, reason: denied_calls.append((tool, reason)),
        )
        enf.start(host="127.0.0.1", port=0)
        port = enf._server.server_address[1]  # noqa: SLF001
        try:
            req = urllib.request.Request(_proxy_url(port, "crm_api/x"))
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(req, timeout=5)
            assert denied_calls == [("crm_api", "MISSING_TOKEN")]
        finally:
            enf.stop()

    def test_request_body_limit_rejects_oversized_body(self, upstream_server):
        issuer = TokenIssuer(secret="shared-test-secret")
        enf = NetworkEnforcer(
            issuer=issuer,
            routes=[UpstreamRoute("crm_api", upstream_server)],
            max_body_bytes=4,
        )
        enf.start(host="127.0.0.1", port=0)
        port = enf._server.server_address[1]  # noqa: SLF001
        try:
            token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
            req = urllib.request.Request(
                _proxy_url(port, "crm_api/customers"),
                data=b"12345",
                headers={AUTH_HEADER: token.to_wire()},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 413
        finally:
            enf.stop()

    def test_invalid_content_length_is_rejected(self, upstream_server):
        issuer = TokenIssuer(secret="shared-test-secret")
        enf = NetworkEnforcer(
            issuer=issuer,
            routes=[UpstreamRoute("crm_api", upstream_server)],
        )
        enf.start(host="127.0.0.1", port=0)
        port = enf._server.server_address[1]  # noqa: SLF001
        try:
            token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(
                    (
                        "POST /crm_api/customers HTTP/1.1\r\n"
                        "Host: 127.0.0.1\r\n"
                        f"{AUTH_HEADER}: {token.to_wire()}\r\n"
                        "Content-Length: invalid\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode()
                )
                response = client.recv(1024)
            assert b"400 Bad Request" in response
        finally:
            enf.stop()

    def test_transfer_encoded_request_body_is_rejected(self, upstream_server):
        issuer = TokenIssuer(secret="shared-test-secret")
        enf = NetworkEnforcer(
            issuer=issuer,
            routes=[UpstreamRoute("crm_api", upstream_server)],
        )
        enf.start(host="127.0.0.1", port=0)
        port = enf._server.server_address[1]  # noqa: SLF001
        try:
            token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(
                    (
                        "POST /crm_api/customers HTTP/1.1\r\n"
                        "Host: 127.0.0.1\r\n"
                        f"{AUTH_HEADER}: {token.to_wire()}\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Connection: close\r\n\r\n"
                        "0\r\n\r\n"
                    ).encode()
                )
                response = client.recv(1024)
            assert b"400 Bad Request" in response
        finally:
            enf.stop()

    def test_network_path_reference_cannot_redirect_proxy_to_another_host(self, enforcer):
        enf, issuer, proxy_port = enforcer
        evil_hits = []

        class _EvilHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):  # noqa: N802
                evil_hits.append(self.path)
                body = b"EVIL SERVER"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        evil_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EvilHandler)
        evil_thread = threading.Thread(target=evil_server.serve_forever, daemon=True)
        evil_thread.start()
        try:
            evil_authority = f"127.0.0.1:{evil_server.server_address[1]}"
            token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
            req = urllib.request.Request(
                _proxy_url(proxy_port, f"crm_api///{evil_authority}/steal"),
                headers={AUTH_HEADER: token.to_wire()},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read()
            assert b"EVIL SERVER" not in body
            assert evil_hits == []
        finally:
            evil_server.shutdown()
            evil_server.server_close()
