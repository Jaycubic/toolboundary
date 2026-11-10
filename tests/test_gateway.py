"""Tests for the out-of-process policy gateway, written from the attacker's side."""

from __future__ import annotations

import http.client
import http.server
import json
import socket
import subprocess
import sys
import textwrap
import threading
import time
import warnings
from pathlib import Path
from typing import Any

import pytest

from toolboundary import AccessMode, AutonomyLevel, Boundary, ProviderMode, ToolPermission
from toolboundary.audit import AuditTrail
from toolboundary.decorators import guarded_tool
from toolboundary.exceptions import BoundaryViolation, ConfigurationError
from toolboundary.gateway import (
    AGENT_KEY_HEADER,
    DENIED_HEADER,
    GatewayAgent,
    GatewayClient,
    GatewayRoute,
    GatewayRule,
    PolicyGateway,
    constant,
    generate_agent_key,
    json_array_length,
    json_field,
    query_param,
)
from toolboundary.provider import ProviderGrant, ProviderReceipt

KEY = "agent-key-for-tests-000000000000001"
OTHER_KEY = "agent-key-for-tests-000000000000002"
UPSTREAM_SECRET = "Bearer real-upstream-credential"  # noqa: S105


class MemorySink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


class _Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:
        pass

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.requests.append(  # type: ignore[attr-defined]
            {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
        )
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/huge"):
            self.send_response(200)
            self.send_header("Content-Length", "64")
            self.end_headers()
            self.wfile.write(b"x" * 64)
            return
        if self.path.startswith("/missing"):
            self.send_response(404)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"no")
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "session=upstream")
        self.send_header(DENIED_HEADER, "SPOOFED")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve


@pytest.fixture
def upstream() -> Any:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    server.requests = []  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def rules() -> tuple[GatewayRule, ...]:
    free = {"value": constant(0)}
    one_record = {**free, "record_count": constant(1)}
    return (
        GatewayRule(
            "POST",
            "payments",
            AccessMode.WRITE,
            operation="pay",
            value=json_field("payment.amount"),
            record_count=constant(1),
        ),
        GatewayRule(
            "POST", "bulk", AccessMode.WRITE, record_count=json_array_length("items"), **free
        ),
        GatewayRule(
            "GET",
            "orders",
            AccessMode.READ_ONLY,
            record_count=query_param("limit"),
            allowed_query=frozenset({"limit"}),
            **free,
        ),
        GatewayRule("GET", "orders/{id}", AccessMode.READ_ONLY, **one_record),
        GatewayRule("GET", "redirect", AccessMode.READ_ONLY, **one_record),
        GatewayRule("GET", "huge", AccessMode.READ_ONLY, **one_record),
        GatewayRule("GET", "missing", AccessMode.READ_ONLY, **one_record),
        GatewayRule("POST", "admin/wipe", AccessMode.ADMIN, operation="wipe"),
    )


def make_boundary(sink: MemorySink | None = None, **kwargs: Any) -> Boundary:
    kwargs.setdefault(
        "permissions",
        [
            ToolPermission(
                "crm",
                access_mode=AccessMode.WRITE,
                max_value=100,
                max_records=10,
                blocked_operations=frozenset({"blocked"}),
            )
        ],
    )
    return Boundary(
        "agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        strict_limits=True,
        audit=AuditTrail([sink or MemorySink()]),
        **kwargs,
    )


class Harness:
    def __init__(self, upstream: Any, boundary: Boundary | None = None, **kwargs: Any) -> None:
        route_kwargs = kwargs.pop("route", {})
        route_kwargs.setdefault("rules", rules())
        route_kwargs.setdefault("credential_headers", {"Authorization": UPSTREAM_SECRET})
        self.upstream = upstream
        self.boundary = boundary or make_boundary()
        self.gateway = PolicyGateway(
            [GatewayAgent(self.boundary, KEY)],
            [
                GatewayRoute(
                    "crm", f"http://127.0.0.1:{upstream.server_address[1]}", **route_kwargs
                )
            ],
            max_response_bytes=32,
            **kwargs,
        )
        self.gateway.start(port=0)
        self.client = GatewayClient(f"http://127.0.0.1:{self.gateway.port}", KEY)

    @property
    def forwarded(self) -> list[dict[str, Any]]:
        return self.upstream.requests  # type: ignore[no-any-return]

    def raw(
        self,
        method: str,
        target: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        key: str | None = KEY,
    ) -> tuple[int, Any, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.gateway.port, timeout=5)
        request_headers = dict(headers or {})
        if key is not None:
            request_headers[AGENT_KEY_HEADER] = key
        connection.putrequest(method, target, skip_accept_encoding=True)
        for name, value in request_headers.items():
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, response, data


@pytest.fixture
def harness(upstream: Any) -> Any:
    instance = Harness(upstream)
    yield instance
    instance.gateway.stop()


JSON_HEADERS = {"Content-Type": "application/json"}


def pay_body(amount: Any) -> bytes:
    return json.dumps({"payment": {"amount": amount}}).encode()


# -- the agent can't authorize itself ------------------------------------------


def test_allowed_request_is_forwarded_with_gateway_credentials(harness: Harness) -> None:
    response = harness.client.request(
        "crm", "POST", "payments", json_body={"payment": {"amount": 5}}
    )
    assert response.status == 200 and response.body == b"ok"
    assert harness.forwarded[0]["headers"]["Authorization"] == UPSTREAM_SECRET
    assert json.loads(harness.forwarded[0]["body"]) == {"payment": {"amount": 5}}


def test_client_holds_no_policy_or_signing_material() -> None:
    client = GatewayClient("http://127.0.0.1:1", KEY)
    assert set(vars(client)) == {"_base_url", "_agent_key", "_timeout", "_opener"}


@pytest.mark.parametrize("key", [None, "", "wrong-key", OTHER_KEY, KEY + "x"])
def test_unauthenticated_requests_are_rejected(harness: Harness, key: str | None) -> None:
    status, response, _ = harness.raw(
        "POST", "/crm/payments", pay_body(1), JSON_HEADERS, key=key
    )
    assert status == 401 and response.getheader(DENIED_HEADER) == "UNAUTHENTICATED"
    assert harness.forwarded == []


def test_agent_cannot_choose_its_identity_with_a_header(upstream: Any) -> None:
    sink = MemorySink()
    instance = Harness(upstream, make_boundary(sink))
    try:
        instance.raw(
            "POST",
            "/crm/payments",
            pay_body(1),
            {**JSON_HEADERS, "X-Agent-Name": "admin", "X-ToolBoundary-Token": "forged"},
        )
        assert {event.agent_name for event in sink.events} == {"agent"}
        assert "X-Agent-Name" not in instance.forwarded[0]["headers"]
        assert "X-ToolBoundary-Token" not in instance.forwarded[0]["headers"]
        assert AGENT_KEY_HEADER not in instance.forwarded[0]["headers"]
    finally:
        instance.gateway.stop()


# -- value claims come from the request ----------------------------------------


@pytest.mark.parametrize("amount", [101, 999999, 1e308, "101"])
def test_value_is_read_from_the_body_being_forwarded(harness: Harness, amount: Any) -> None:
    status, response, _ = harness.raw("POST", "/crm/payments", pay_body(amount), JSON_HEADERS)
    assert status == 403 and response.getheader(DENIED_HEADER) == "MAX_VALUE_EXCEEDED"
    assert harness.forwarded == []


@pytest.mark.parametrize(
    "body",
    [
        b'{"payment":{"amount":1},"payment":{"amount":999999}}',
        b'{"payment":{"amount":1,"amount":999999}}',
        b'{"payment":{}}',
        b'{"payment":{"amount":NaN}}',
        b'{"payment":{"amount":Infinity}}',
        b"not json",
        b"\xef\xbb\xbf" + b'{"payment":{"amount":1}}',
        b"\xff\xfe" + '{"payment":{"amount":1}}'.encode("utf-16-le"),
        b"[" * 200000,
    ],
)
def test_ambiguous_or_unreadable_bodies_are_denied(harness: Harness, body: bytes) -> None:
    status, response, _ = harness.raw("POST", "/crm/payments", body, JSON_HEADERS)
    assert status == 403
    assert response.getheader(DENIED_HEADER) == "REQUEST_VALUE_UNREADABLE"
    assert harness.forwarded == []


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "application/json; charset=utf-16"},
    ],
)
def test_json_rules_require_a_json_utf8_content_type(
    harness: Harness, headers: dict[str, str]
) -> None:
    status, response, _ = harness.raw("POST", "/crm/payments", pay_body(1), headers)
    assert status == 403
    assert response.getheader(DENIED_HEADER) == "REQUEST_VALUE_UNREADABLE"
    assert harness.forwarded == []


def test_record_count_is_counted_from_the_body(harness: Harness) -> None:
    allowed = harness.client.request("crm", "POST", "bulk", json_body={"items": [1, 2]})
    assert allowed.status == 200
    denied = harness.client.request("crm", "POST", "bulk", json_body={"items": list(range(11))})
    assert denied.denied_reason == "MAX_RECORDS_EXCEEDED"


def test_query_values_are_checked(harness: Harness) -> None:
    assert harness.client.request("crm", "GET", "orders", query={"limit": "5"}).status == 200
    denied = harness.client.request("crm", "GET", "orders", query={"limit": "11"})
    assert denied.denied_reason == "MAX_RECORDS_EXCEEDED"


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("/crm/orders?limit=1&limit=500", "QUERY_NOT_ALLOWED"),
        ("/crm/orders?limit=1&override=1", "QUERY_NOT_ALLOWED"),
        ("/crm/orders/1?limit=1", "QUERY_NOT_ALLOWED"),
    ],
)
def test_unlisted_and_repeated_query_parameters_are_denied(
    harness: Harness, target: str, reason: str
) -> None:
    status, response, _ = harness.raw("GET", target)
    assert status == 403 and response.getheader(DENIED_HEADER) == reason
    assert harness.forwarded == []


def test_a_limit_cannot_be_skipped_by_a_rule_without_a_value(upstream: Any) -> None:
    instance = Harness(
        upstream, route={"rules": (GatewayRule("POST", "pay", AccessMode.WRITE),)}
    )
    try:
        status, response, _ = instance.raw("POST", "/crm/pay", b"{}", JSON_HEADERS)
        assert status == 403 and response.getheader(DENIED_HEADER) == "VALUE_REQUIRED"
    finally:
        instance.gateway.stop()


def test_min_value_alone_also_requires_a_value() -> None:
    boundary = make_boundary(permissions=[ToolPermission("t", min_value=1)])
    with pytest.raises(BoundaryViolation):
        boundary.check("t")


# -- only operator-written requests get through --------------------------------


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("DELETE", "/crm/payments"),
        ("GET", "/crm/payments"),
        ("GET", "/crm/orders/1/secrets"),
        ("GET", "/crm/unlisted"),
        ("POST", "/crm/orders/1"),
    ],
)
def test_requests_without_a_rule_are_denied(harness: Harness, method: str, target: str) -> None:
    status, response, _ = harness.raw(method, target, b"{}", JSON_HEADERS)
    assert status == 403 and response.getheader(DENIED_HEADER) == "REQUEST_NOT_ALLOWED"
    assert harness.forwarded == []


def test_unknown_tool_is_denied(harness: Harness) -> None:
    assert harness.client.request("other", "GET", "x").denied_reason == "UNKNOWN_ROUTE"


def test_rule_access_mode_is_enforced_by_policy(harness: Harness) -> None:
    denied = harness.client.request("crm", "POST", "admin/wipe", json_body={})
    assert denied.denied_reason == "ACCESS_MODE_EXCEEDED"
    assert harness.forwarded == []


@pytest.mark.parametrize(
    "target",
    [
        "/crm/orders/../admin/wipe",
        "/crm/orders/%2e%2e/admin/wipe",
        "/crm/orders%2F1",
        "/crm/orders/1%2fsecrets",
        "/crm/orders/%252e%252e",
        "/crm/orders/1;x=1",
        "/crm/orders/..;/admin",
        "/crm/orders\\1",
        "/crm/orders/1%5cadmin",
        "/crm/orders//1",
        "/crm/orders/./1",
        "/crm/orders/1%00",
        "/crm/orders/%0d%0aX-Evil:1",
        "/crm/orders/%ff",
        "http://evil.example/crm/orders/1",
    ],
)
def test_ambiguous_paths_are_refused(harness: Harness, target: str) -> None:
    status, _, _ = harness.raw("GET", target)
    assert status == 400
    assert harness.forwarded == []


# -- headers, credentials and responses ----------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "Cookie",
        "X-HTTP-Method-Override",
        "X-Forwarded-For",
        "X-Original-URL",
        "Proxy-Authorization",
        "Host-Override",
    ],
)
def test_agent_headers_are_not_forwarded_unless_allow_listed(
    harness: Harness, header: str
) -> None:
    harness.raw("GET", "/crm/orders/1", headers={header: "agent-value"})
    forwarded = harness.forwarded[0]["headers"]
    assert forwarded.get(header) != "agent-value"
    if header == "Authorization":
        assert forwarded[header] == UPSTREAM_SECRET


def test_route_can_allow_extra_headers_but_not_override_credentials(upstream: Any) -> None:
    instance = Harness(
        upstream, route={"forwarded_headers": frozenset({"X-Trace", "Authorization"})}
    )
    try:
        instance.raw(
            "GET", "/crm/orders/1", headers={"X-Trace": "1", "Authorization": "Bearer agent"}
        )
        assert instance.forwarded[0]["headers"]["X-Trace"] == "1"
        assert instance.forwarded[0]["headers"]["Authorization"] == UPSTREAM_SECRET
    finally:
        instance.gateway.stop()


def test_credentials_can_come_from_a_callable(upstream: Any) -> None:
    instance = Harness(upstream, route={"credential_headers": lambda: {"X-Api-Key": "rotating"}})
    try:
        instance.client.request("crm", "GET", "orders/1")
        assert instance.forwarded[0]["headers"]["X-Api-Key"] == "rotating"
    finally:
        instance.gateway.stop()


def test_credential_failure_blocks_the_request(upstream: Any) -> None:
    def broken() -> dict[str, str]:
        raise RuntimeError("vault is down")

    instance = Harness(upstream, route={"credential_headers": broken})
    try:
        response = instance.client.request("crm", "GET", "orders/1")
        assert response.denied_reason == "UPSTREAM_CREDENTIALS_UNAVAILABLE"
        assert b"vault" not in response.body
        assert instance.forwarded == []
    finally:
        instance.gateway.stop()


def test_upstream_cannot_spoof_a_denial_or_set_cookies(harness: Harness) -> None:
    response = harness.client.request("crm", "GET", "orders/1")
    assert response.denied_reason is None
    assert "set-cookie" not in response.headers


def test_redirects_are_returned_not_followed(harness: Harness) -> None:
    response = harness.client.request("crm", "GET", "redirect")
    assert response.status == 302
    assert len(harness.forwarded) == 1


def test_upstream_errors_are_relayed_without_a_denial(harness: Harness) -> None:
    response = harness.client.request("crm", "GET", "missing")
    assert response.status == 404 and response.denied_reason is None


def test_response_size_is_limited(harness: Harness) -> None:
    assert harness.client.request("crm", "GET", "huge").denied_reason == (
        "UPSTREAM_RESPONSE_TOO_LARGE"
    )


def test_unreachable_upstream_is_reported_generically(upstream: Any) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    boundary = make_boundary()
    gateway = PolicyGateway(
        [GatewayAgent(boundary, KEY)],
        [GatewayRoute("crm", f"http://127.0.0.1:{closed_port}", rules=rules())],
    )
    gateway.start(port=0)
    try:
        response = GatewayClient(f"http://127.0.0.1:{gateway.port}", KEY).request(
            "crm", "GET", "orders/1"
        )
        assert response.status == 502 and response.denied_reason == "UPSTREAM_UNREACHABLE"
    finally:
        gateway.stop()


# -- request framing -----------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ("Transfer-Encoding: chunked\r\n", "UNSUPPORTED_TRANSFER_ENCODING"),
        ("Content-Length: 1\r\nContent-Length: 2\r\n", "INVALID_CONTENT_LENGTH"),
        ("Content-Length: -1\r\n", "INVALID_CONTENT_LENGTH"),
        ("Content-Length: 1_0\r\n", "INVALID_CONTENT_LENGTH"),
    ],
)
def test_unsafe_request_framing_is_rejected(harness: Harness, headers: str, reason: str) -> None:
    with socket.create_connection(("127.0.0.1", harness.gateway.port), timeout=5) as client:
        client.sendall(
            (
                "POST /crm/payments HTTP/1.1\r\nHost: x\r\n"
                f"{AGENT_KEY_HEADER}: {KEY}\r\n{headers}\r\n"
            ).encode()
        )
        data = client.recv(2048)
    assert b"400" in data.split(b"\r\n")[0] and reason.encode() in data
    assert harness.forwarded == []


def test_oversized_body_is_rejected(upstream: Any) -> None:
    instance = Harness(upstream, max_body_bytes=8)
    try:
        response = instance.client.request("crm", "POST", "payments", body=b"x" * 9)
        assert response.status == 413
    finally:
        instance.gateway.stop()


def test_connection_limit_refuses_excess_connections(upstream: Any) -> None:
    instance = Harness(upstream, max_connections=1, socket_timeout=1.0)
    try:
        with socket.create_connection(("127.0.0.1", instance.gateway.port), timeout=2):
            time.sleep(0.2)
            with socket.create_connection(("127.0.0.1", instance.gateway.port), timeout=2) as extra:
                extra.settimeout(2)
                assert extra.recv(16) == b""
    finally:
        instance.gateway.stop()


# -- controls that live in the gateway -----------------------------------------


def test_kill_switch_file_stops_the_gateway(upstream: Any, tmp_path: Path) -> None:
    switch = tmp_path / "halt"
    instance = Harness(upstream, make_boundary(kill_switch_file=switch))
    try:
        assert instance.client.request("crm", "GET", "orders/1").status == 200
        switch.touch()
        denied = instance.client.request("crm", "GET", "orders/1")
        assert denied.status == 403 and denied.denied_reason == "KILL_SWITCH_ACTIVE"
    finally:
        instance.gateway.stop()


def test_rate_limit_returns_429(upstream: Any) -> None:
    instance = Harness(upstream, make_boundary(max_actions_per_hour=1))
    try:
        assert instance.client.request("crm", "GET", "orders/1").status == 200
        assert instance.client.request("crm", "GET", "orders/1").status == 429
    finally:
        instance.gateway.stop()


def test_approval_requirement_blocks_forwarding(upstream: Any) -> None:
    boundary = make_boundary(
        permissions=[ToolPermission("crm", requires_approval=True, max_records=10)]
    )
    instance = Harness(upstream, boundary)
    try:
        response = instance.client.request("crm", "GET", "orders/1")
        assert response.denied_reason == "APPROVAL_REQUIRED"
        assert instance.forwarded == []
    finally:
        instance.gateway.stop()


def test_blocked_operation_uses_the_rule_not_the_agent(upstream: Any) -> None:
    route = {"rules": (GatewayRule("POST", "x", AccessMode.WRITE, operation="BLOCKED"),)}
    boundary = make_boundary(permissions=[ToolPermission(
        "crm", access_mode=AccessMode.WRITE, blocked_operations=frozenset({"blocked"})
    )])
    instance = Harness(upstream, boundary, route=route)
    try:
        response = instance.client.request("crm", "POST", "x", json_body={})
        assert response.denied_reason == "OPERATION_BLOCKED"
    finally:
        instance.gateway.stop()


def test_custom_extractor_failure_denies(upstream: Any) -> None:
    def broken(_request: Any) -> int:
        raise RuntimeError("bug")

    route = {"rules": (GatewayRule("POST", "x", AccessMode.WRITE, record_count=broken),)}
    instance = Harness(upstream, route=route)
    try:
        response = instance.client.request("crm", "POST", "x", json_body={})
        assert response.denied_reason == "REQUEST_VALUE_UNREADABLE"
        assert instance.forwarded == []
    finally:
        instance.gateway.stop()


def test_every_denial_is_audited_once(upstream: Any) -> None:
    sink = MemorySink()
    instance = Harness(upstream, make_boundary(sink))
    try:
        instance.client.request("crm", "DELETE", "payments")
        instance.client.request("crm", "POST", "payments", json_body={"payment": {"amount": 500}})
        assert [event.decision for event in sink.events] == ["DENY", "DENY"]
        assert sink.events[0].metadata["gateway_reason"] == "REQUEST_NOT_ALLOWED"
        assert sink.events[1].reason_code == "MAX_VALUE_EXCEEDED"
    finally:
        instance.gateway.stop()


class _Provider:
    def __init__(self, allowed: bool = True, fail: bool = False) -> None:
        self.allowed = allowed
        self.fail = fail
        self.executions: list[Any] = []

    def authorize(self, call: Any, local: Any) -> ProviderGrant:
        if self.fail:
            raise RuntimeError("down")
        return ProviderGrant(allowed=self.allowed, provider="test", reason="test")

    def record(self, grant: Any, execution: Any) -> ProviderReceipt:
        self.executions.append(execution)
        return ProviderReceipt(recorded=True, provider="test")


@pytest.mark.parametrize(
    ("provider_kwargs", "status", "reason"),
    [
        ({"allowed": False}, 403, "PROVIDER_DENIED"),
        ({"fail": True}, 503, "PROVIDER_UNAVAILABLE"),
    ],
)
def test_enforcing_provider_can_block(
    upstream: Any, provider_kwargs: dict[str, bool], status: int, reason: str
) -> None:
    boundary = make_boundary(
        provider=_Provider(**provider_kwargs), provider_mode=ProviderMode.ENFORCE
    )
    instance = Harness(upstream, boundary)
    try:
        response = instance.client.request("crm", "GET", "orders/1")
        assert response.status == status and response.denied_reason == reason
        assert instance.forwarded == []
    finally:
        instance.gateway.stop()


def test_provider_records_execution(upstream: Any) -> None:
    provider = _Provider()
    boundary = make_boundary(provider=provider, provider_mode=ProviderMode.ENFORCE)
    instance = Harness(upstream, boundary)
    try:
        assert instance.client.request("crm", "GET", "orders/1").status == 200
        assert provider.executions[0].status == "success"
    finally:
        instance.gateway.stop()


# -- safe configuration --------------------------------------------------------


def test_short_agent_key_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        GatewayAgent(make_boundary(), "short")


def test_generated_keys_are_accepted_and_unique() -> None:
    first, second = generate_agent_key(), generate_agent_key()
    assert first != second
    GatewayAgent(make_boundary(), first)


def test_agent_key_is_not_stored_in_plaintext() -> None:
    assert KEY not in repr(vars(GatewayAgent(make_boundary(), KEY)))


def test_boundary_without_strict_limits_is_refused() -> None:
    boundary = Boundary("agent", permissions=[])
    with pytest.raises(ConfigurationError, match="strict_limits"):
        GatewayAgent(boundary, KEY)


def test_duplicate_agents_are_refused() -> None:
    first = GatewayAgent(make_boundary(), KEY)
    second = GatewayAgent(make_boundary(), OTHER_KEY)
    route = GatewayRoute("crm", "http://127.0.0.1:1", rules=rules())
    with pytest.raises(ConfigurationError):
        PolicyGateway([first, second], [route])


def test_shared_agent_key_is_refused() -> None:
    other = Boundary("other", strict_limits=True, permissions=[])
    route = GatewayRoute("crm", "http://127.0.0.1:1", rules=rules())
    with pytest.raises(ConfigurationError):
        PolicyGateway([GatewayAgent(make_boundary(), KEY), GatewayAgent(other, KEY)], [route])


@pytest.mark.parametrize(
    ("url", "credentials"),
    [
        ("ftp://example.test", None),
        ("file:///etc/passwd", None),
        ("https://user:pw@example.test", None),
        ("https://example.test?x=1", None),
        ("http://example.test", {"Authorization": "x"}),
    ],
)
def test_unsafe_upstreams_are_refused(url: str, credentials: dict[str, str] | None) -> None:
    with pytest.raises(ConfigurationError):
        GatewayRoute("crm", url, rules=rules(), credential_headers=credentials)


def test_route_needs_rules() -> None:
    with pytest.raises(ConfigurationError):
        GatewayRoute("crm", "http://127.0.0.1:1", rules=())


def test_rule_paths_and_methods_are_validated() -> None:
    with pytest.raises(ConfigurationError):
        GatewayRule("GET", "/leading", AccessMode.READ_ONLY)
    with pytest.raises(ConfigurationError):
        GatewayRule("TRACE", "x", AccessMode.READ_ONLY)


def test_rule_template_characters_are_literal() -> None:
    rule = GatewayRule("GET", "a.b/{id}", AccessMode.READ_ONLY)
    assert rule.matches("GET", "a.b/1")
    assert not rule.matches("GET", "aXb/1")
    assert not rule.matches("GET", "a.b/1/2")


def test_non_loopback_bind_needs_tls() -> None:
    gateway = PolicyGateway(
        [GatewayAgent(make_boundary(), KEY)],
        [GatewayRoute("crm", "http://127.0.0.1:1", rules=rules())],
    )
    with pytest.raises(ConfigurationError):
        gateway.start(host="0.0.0.0", port=0)  # noqa: S104


def test_client_refuses_to_send_keys_over_plain_http_remotely() -> None:
    with pytest.raises(ConfigurationError):
        GatewayClient("http://gateway.example.test", KEY)
    GatewayClient("https://gateway.example.test", KEY)


def test_gateway_works_over_tls(upstream: Any, tmp_path: Path) -> None:
    import ipaddress
    import ssl
    from datetime import datetime, timedelta, timezone

    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=str(cert_path))

    gateway = PolicyGateway(
        [GatewayAgent(make_boundary(), KEY)],
        [
            GatewayRoute(
                "crm", f"http://127.0.0.1:{upstream.server_address[1]}", rules=rules()
            )
        ],
        ssl_context=server_context,
    )
    gateway.start(port=0)
    try:
        client = GatewayClient(
            f"https://127.0.0.1:{gateway.port}", KEY, ssl_context=client_context
        )
        assert client.request("crm", "GET", "orders/1").status == 200
    finally:
        gateway.stop()


def test_gateway_runs_in_its_own_process(upstream: Any, tmp_path: Path) -> None:
    (tmp_path / "policy_app.py").write_text(
        textwrap.dedent(
            f"""
            from toolboundary import AccessMode, AutonomyLevel, Boundary, ToolPermission
            from toolboundary.gateway import GatewayAgent, GatewayRoute, GatewayRule, PolicyGateway

            def build():
                boundary = Boundary(
                    "agent",
                    autonomy=AutonomyLevel.AUTONOMOUS,
                    strict_limits=True,
                    permissions=[ToolPermission("crm")],
                )
                return PolicyGateway(
                    [GatewayAgent(boundary, {KEY!r})],
                    [GatewayRoute(
                        "crm",
                        "http://127.0.0.1:{upstream.server_address[1]}",
                        rules=(GatewayRule("GET", "orders/{{id}}", AccessMode.READ_ONLY),),
                    )],
                )
            """
        )
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "toolboundary.gateway",
            "--app",
            "policy_app:build",
            "--port",
            str(port),
        ],
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 20
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                assert time.time() < deadline and process.poll() is None
                time.sleep(0.1)
        client = GatewayClient(f"http://127.0.0.1:{port}", KEY)
        assert client.request("crm", "GET", "orders/1").status == 200
        assert client.request("crm", "GET", "orders/1/x").denied_reason == "REQUEST_NOT_ALLOWED"
    finally:
        process.terminate()
        process.wait(timeout=10)


# -- access_mode warning -------------------------------------------------------


def test_guarded_tool_without_access_mode_warns_and_stays_read_only() -> None:
    boundary = make_boundary(permissions=[ToolPermission("t")])
    with pytest.warns(FutureWarning, match="access_mode"):
        @guarded_tool(boundary, tool_name="t")
        def call() -> str:
            return "ok"
    assert call() == "ok"


def test_guarded_tool_with_access_mode_does_not_warn() -> None:
    boundary = make_boundary(permissions=[ToolPermission("t")])
    with warnings.catch_warnings():
        warnings.simplefilter("error", FutureWarning)

        @guarded_tool(boundary, tool_name="t", access_mode=AccessMode.READ_ONLY)
        def call() -> str:
            return "ok"
    assert call() == "ok"


def _langchain_tool() -> Any:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import BaseTool

    class Example(BaseTool):
        name: str = "example"
        description: str = "Example."

        def _run(self, text: str) -> str:
            return text

    return Example()


def test_langchain_guard_without_access_mode_warns() -> None:
    from toolboundary.integrations.langchain import guard_tools

    boundary = make_boundary(permissions=[ToolPermission("example")])
    with pytest.warns(FutureWarning, match="access_mode"):
        guard_tools([_langchain_tool()], boundary)


def test_langchain_guard_with_override_does_not_warn() -> None:
    from toolboundary.integrations.langchain import guard_tools

    boundary = make_boundary(permissions=[ToolPermission("example", access_mode=AccessMode.WRITE)])
    with warnings.catch_warnings():
        warnings.simplefilter("error", FutureWarning)
        guarded = guard_tools(
            [_langchain_tool()],
            boundary,
            overrides={"example": {"access_mode": AccessMode.WRITE}},
        )
    assert guarded[0].invoke("x") == "x"
