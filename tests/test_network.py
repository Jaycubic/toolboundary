from __future__ import annotations

import http.server
import socketserver
import threading
import time
import urllib.error
import urllib.request

import pytest

from toolboundary.network import AUTH_HEADER, NetworkEnforcer, UpstreamRoute
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
