"""
ToolBoundary network enforcement -- run this file directly:

    python examples/network_enforcement.py

Demonstrates the optional network-layer defense: a tiny local proxy that
only forwards requests carrying a valid, unexpired, single-use
authorization token issued by Boundary.check_and_authorize().

This starts a fake "internal CRM" server, wraps it behind the
NetworkEnforcer proxy, and shows:
  1. A properly authorized call succeeding.
  2. A call with no token being rejected before it ever reaches the CRM.
  3. The *same* token being rejected the second time it's used (replay).
"""

import http.server
import socketserver
import threading
import time
import urllib.error
import urllib.request

from toolboundary import AccessMode, AutonomyLevel, Boundary, ToolPermission
from toolboundary.network import AUTH_HEADER, NetworkEnforcer, UpstreamRoute
from toolboundary.tokens import TokenIssuer


class _FakeCRMHandler(http.server.BaseHTTPRequestHandler):
    """Stands in for a real internal API the agent should only reach via the proxy."""

    def log_message(self, fmt, *args):
        pass  # silence default request logging for a cleaner demo output

    def do_GET(self):
        body = b'{"customer_id": "42", "name": "Example Customer"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_fake_crm() -> str:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FakeCRMHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}"


def main() -> None:
    print("Starting fake internal CRM (the 'real tool' the agent should not reach directly)...")
    crm_url = start_fake_crm()
    print(f"  Fake CRM listening at {crm_url} (NOT directly reachable by the agent in a real deployment)")

    issuer = TokenIssuer(secret="demo-shared-secret", ttl_seconds=10)

    boundary = Boundary(
        agent_name="quote-agent",
        autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
        permissions=[ToolPermission("crm_api", access_mode=AccessMode.READ_ONLY)],
        token_issuer=issuer,
    )

    enforcer = NetworkEnforcer(
        issuer=issuer,
        routes=[UpstreamRoute("crm_api", crm_url)],
    )
    enforcer.start(host="127.0.0.1", port=0)
    proxy_port = enforcer._server.server_address[1]  # noqa: SLF001 (demo only)
    print(f"NetworkEnforcer proxy listening at http://127.0.0.1:{proxy_port}")

    proxy_url = f"http://127.0.0.1:{proxy_port}/crm_api/customers/42"

    print("\n--- 1. Properly authorized call ---")
    token = boundary.check_and_authorize("crm_api", access_mode=AccessMode.READ_ONLY)
    req = urllib.request.Request(proxy_url, headers={AUTH_HEADER: token.to_wire()})
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"  -> HTTP {resp.status}: {resp.read().decode()}")

    print("\n--- 2. Call with NO token (simulating a bypassing/compromised agent) ---")
    req = urllib.request.Request(proxy_url)
    try:
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as exc:
        print(f"  -> HTTP {exc.code}: {exc.read().decode()}  (correctly rejected, CRM never touched)")

    print("\n--- 3. Reusing the SAME token a second time (replay attack) ---")
    req = urllib.request.Request(proxy_url, headers={AUTH_HEADER: token.to_wire()})
    try:
        urllib.request.urlopen(req, timeout=5)
        print("  -> Unexpectedly allowed! (this should not happen)")
    except urllib.error.HTTPError as exc:
        print(f"  -> HTTP {exc.code}: {exc.read().decode()}  (correctly rejected as already-used)")

    print("\n--- 4. Waiting for token TTL to expire, then trying a fresh-but-stale token ---")
    stale_token = boundary.check_and_authorize("crm_api", access_mode=AccessMode.READ_ONLY)
    print("  Sleeping 11 seconds (TTL is 10s)...")
    time.sleep(11)
    req = urllib.request.Request(proxy_url, headers={AUTH_HEADER: stale_token.to_wire()})
    try:
        urllib.request.urlopen(req, timeout=5)
        print("  -> Unexpectedly allowed! (this should not happen)")
    except urllib.error.HTTPError as exc:
        print(f"  -> HTTP {exc.code}: {exc.read().decode()}  (correctly rejected as expired)")

    enforcer.stop()
    print("\nDone.")


if __name__ == "__main__":
    main()
