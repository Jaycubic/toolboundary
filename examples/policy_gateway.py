"""
examples/policy_gateway.py
--------------------------
Shows the policy gateway reading limits from the real request.

The gateway, fake tool and agent all run here so the example is self-contained.
In production the gateway must run as a separate OS user or container. See
docs/GATEWAY.md.
"""

from __future__ import annotations

import http.server
import json
import threading
from typing import Any

from toolboundary import AccessMode, AutonomyLevel, Boundary, ToolPermission
from toolboundary.audit import AuditTrail
from toolboundary.gateway import (
    GatewayAgent,
    GatewayClient,
    GatewayRoute,
    GatewayRule,
    PolicyGateway,
    generate_agent_key,
    json_field,
)


class FakeBillingTool(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        amount = json.loads(self.rfile.read(length))["payment"]["amount"]
        credential = self.headers.get("Authorization")
        print(f"  tool received amount={amount}, credential added by gateway: {bool(credential)}")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def main() -> None:
    tool = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeBillingTool)
    threading.Thread(target=tool.serve_forever, daemon=True).start()

    agent_key = generate_agent_key()
    boundary = Boundary(
        "billing-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        strict_limits=True,
        audit=AuditTrail([]),
        permissions=[ToolPermission("billing", access_mode=AccessMode.WRITE, max_value=100)],
    )
    gateway = PolicyGateway(
        [GatewayAgent(boundary, agent_key)],
        [
            GatewayRoute(
                "billing",
                f"http://127.0.0.1:{tool.server_address[1]}",
                rules=(
                    GatewayRule(
                        "POST",
                        "payments",
                        AccessMode.WRITE,
                        value=json_field("payment.amount"),
                    ),
                ),
                credential_headers={"Authorization": "Bearer held-only-by-the-gateway"},
            )
        ],
    )
    gateway.start(port=0)
    client = GatewayClient(f"http://127.0.0.1:{gateway.port}", agent_key)

    try:
        print("--- Allowed payment ---")
        allowed = client.request(
            "billing", "POST", "payments", json_body={"payment": {"amount": 25}}
        )
        print(f"  status={allowed.status}")

        print("--- Payment over the limit ---")
        over = client.request(
            "billing", "POST", "payments", json_body={"payment": {"amount": 999999}}
        )
        print(f"  status={over.status}, reason={over.denied_reason}")

        print("--- Request with no rule ---")
        unlisted = client.request("billing", "DELETE", "payments")
        print(f"  status={unlisted.status}, reason={unlisted.denied_reason}")

        print("--- Wrong agent key ---")
        stranger = GatewayClient(f"http://127.0.0.1:{gateway.port}", generate_agent_key())
        rejected = stranger.request("billing", "POST", "payments", json_body={})
        print(f"  status={rejected.status}, reason={rejected.denied_reason}")
    finally:
        gateway.stop()
        tool.shutdown()
        tool.server_close()


if __name__ == "__main__":
    main()
