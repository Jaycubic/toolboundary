"""Regression tests for the security fixes shipped in v1.0.5."""

from __future__ import annotations

import asyncio
import http.client
import http.server
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from toolboundary import AccessMode, AutonomyLevel, Boundary, ProviderMode, ToolPermission
from toolboundary.audit import AuditTrail
from toolboundary.decorators import guarded_tool
from toolboundary.exceptions import (
    BoundaryViolation,
    ConfigurationError,
    KillSwitchActive,
    ProviderAuthorizationDenied,
)
from toolboundary.integrations.agentkey import AgentKeyProvider
from toolboundary.network import AUTH_HEADER, NetworkEnforcer, UpstreamRoute
from toolboundary.provider import ProviderGrant, ProviderReceipt
from toolboundary.tokens import AuthorizationToken, InMemoryTokenStore, TokenInvalid, TokenIssuer

SECRET = "regression-test-secret-value-0001"  # noqa: S105


class MemorySink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


class RecordingProvider:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[Any] = []
        self.executions: list[Any] = []

    def authorize(self, call: Any, local: Any) -> ProviderGrant:
        self.calls.append(call)
        return ProviderGrant(allowed=self.allowed, provider="recording", reason="test")

    def record(self, grant: Any, execution: Any) -> ProviderReceipt:
        self.executions.append(execution)
        return ProviderReceipt(recorded=True, provider="recording")


def make_boundary(*tools: ToolPermission, **kwargs: Any) -> Boundary:
    kwargs.setdefault("autonomy", AutonomyLevel.AUTONOMOUS)
    kwargs.setdefault("audit", AuditTrail([MemorySink()]))
    return Boundary("agent", permissions=list(tools), **kwargs)


class _Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:
        pass

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.requests.append(  # type: ignore[attr-defined]
            (self.command, self.path, dict(self.headers), body)
        )
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)  # type: ignore[attr-defined]
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/large"):
            self.send_response(200)
            self.send_header("Content-Length", "64")
            self.end_headers()
            self.wfile.write(b"x" * 64)
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve


@pytest.fixture
def upstream() -> Any:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    server.requests = []  # type: ignore[attr-defined]
    server.redirect_to = ""  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def issuer() -> TokenIssuer:
    return TokenIssuer(secret=SECRET)


def start_proxy(issuer: TokenIssuer, upstream: Any, **route: Any) -> tuple[NetworkEnforcer, int]:
    url = f"http://127.0.0.1:{upstream.server_address[1]}"
    enforcer = NetworkEnforcer(issuer, [UpstreamRoute("crm", url, **route)], max_response_bytes=32)
    enforcer.start(port=0)
    assert enforcer._server is not None
    return enforcer, enforcer._server.server_address[1]


def send(
    port: int,
    method: str,
    path: str,
    token: str | None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    request_headers = dict(headers or {})
    if token is not None:
        request_headers[AUTH_HEADER] = token
    connection.request(method, path, body=body, headers=request_headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, data, response


def reason(data: bytes) -> str:
    return str(json.loads(data)["reason"])


# -- kill switch ---------------------------------------------------------------


def test_kill_switch_file_halts_a_running_boundary(tmp_path: Path) -> None:
    switch = tmp_path / "halt"
    boundary = make_boundary(ToolPermission("t"), kill_switch_file=switch)
    boundary.check("t")
    switch.touch()
    with pytest.raises(KillSwitchActive):
        boundary.check("t")
    switch.unlink()
    boundary.check("t")


def test_kill_switch_file_fails_closed_when_it_cannot_be_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(path: Any) -> None:
        raise PermissionError(path)

    boundary = make_boundary(ToolPermission("t"), kill_switch_file=tmp_path / "halt")
    monkeypatch.setattr("toolboundary.boundary.os.lstat", denied)
    assert boundary.kill_switch_engaged is True


# -- AgentKey ------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"api_key": "k", "endpoint": "https://example.test"}, {"client": object()}],
)
def test_agentkey_refuses_to_silently_simulate(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ConfigurationError):
        AgentKeyProvider(**kwargs)


def test_agentkey_simulation_is_explicit_and_labelled() -> None:
    provider = AgentKeyProvider(simulate=True)
    boundary = make_boundary(ToolPermission("t"), provider=provider)
    authorization = boundary.authorize_call(tool_name="t", arguments={})
    assert authorization.provider_grant is not None
    assert authorization.provider_grant.metadata["simulated"] is True


def test_agentkey_treats_non_true_allowed_as_denied() -> None:
    class Client:
        def authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
            return {"allowed": "false"}

    provider = AgentKeyProvider(client=Client())
    boundary = make_boundary(
        ToolPermission("t"), provider=provider, provider_mode=ProviderMode.ENFORCE
    )
    with pytest.raises(ProviderAuthorizationDenied):
        boundary.authorize_call(tool_name="t", arguments={})


def test_agentkey_client_without_record_reports_nothing_recorded() -> None:
    class Client:
        def authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
            return {"allowed": True}

    boundary = make_boundary(
        ToolPermission("t"),
        provider=AgentKeyProvider(client=Client()),
        provider_mode=ProviderMode.ENFORCE,
    )
    authorization = boundary.authorize_call(tool_name="t", arguments={})
    now = time.time()
    receipt = boundary.record_execution(authorization, result="x", started_at=now, finished_at=now)
    assert receipt is not None and receipt.recorded is False


def test_agentkey_pending_calls_are_bounded() -> None:
    class Client:
        def authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
            return {"allowed": False}

    provider = AgentKeyProvider(client=Client())
    boundary = make_boundary(
        ToolPermission("t"), provider=provider, provider_mode=ProviderMode.ENFORCE
    )
    for _ in range(2100):
        with pytest.raises(ProviderAuthorizationDenied):
            boundary.authorize_call(tool_name="t", arguments={})
    assert len(provider.pending_calls) <= 4096


# -- proxy token scope ---------------------------------------------------------


@pytest.fixture
def read_write_boundary(issuer: TokenIssuer) -> Boundary:
    return make_boundary(
        ToolPermission("crm", access_mode=AccessMode.WRITE, max_value=10), token_issuer=issuer
    )


def test_read_only_token_cannot_use_write_methods(
    issuer: TokenIssuer, upstream: Any, read_write_boundary: Boundary
) -> None:
    enforcer, port = start_proxy(issuer, upstream)
    try:
        token = read_write_boundary.check_and_authorize("crm", value=1).to_wire()
        status, data, _ = send(port, "DELETE", "/crm/customers/all", token)
        assert status == 403 and reason(data) == "TOKEN_METHOD_NOT_ALLOWED"
        assert upstream.requests == []
    finally:
        enforcer.stop()


def test_token_without_access_mode_is_read_only(issuer: TokenIssuer, upstream: Any) -> None:
    enforcer, port = start_proxy(issuer, upstream)
    try:
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        status, data, _ = send(port, "POST", "/crm/x", wire, body=b"{}")
        assert status == 403 and reason(data) == "TOKEN_METHOD_NOT_ALLOWED"
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        assert send(port, "GET", "/crm/x", wire)[0] == 200
    finally:
        enforcer.stop()


def test_write_token_may_use_write_methods(
    issuer: TokenIssuer, upstream: Any, read_write_boundary: Boundary
) -> None:
    enforcer, port = start_proxy(issuer, upstream)
    try:
        token = read_write_boundary.check_and_authorize(
            "crm", access_mode=AccessMode.WRITE, value=1
        ).to_wire()
        assert send(port, "POST", "/crm/x", token, body=b"{}")[0] == 200
    finally:
        enforcer.stop()


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "/crm/orders/1", b'{"amount":1}'),
        ("POST", "/crm/orders/2", b'{"amount":1}'),
        ("POST", "/crm/orders/1", b'{"amount":999999}'),
    ],
)
def test_request_bound_token_rejects_any_other_request(
    issuer: TokenIssuer,
    upstream: Any,
    read_write_boundary: Boundary,
    method: str,
    path: str,
    body: bytes,
) -> None:
    enforcer, port = start_proxy(issuer, upstream, require_request_binding=True)
    try:
        token = read_write_boundary.check_and_authorize(
            "crm",
            access_mode=AccessMode.WRITE,
            value=1,
            request_method="POST",
            request_path="/orders/1",
            request_body=b'{"amount":1}',
        ).to_wire()
        status, data, _ = send(port, method, path, token, body=body)
        assert status == 403 and reason(data) == "TOKEN_REQUEST_MISMATCH"
        assert upstream.requests == []
    finally:
        enforcer.stop()


def test_request_bound_token_accepts_the_exact_request(
    issuer: TokenIssuer, upstream: Any, read_write_boundary: Boundary
) -> None:
    enforcer, port = start_proxy(issuer, upstream, require_request_binding=True)
    try:
        token = read_write_boundary.check_and_authorize(
            "crm",
            access_mode=AccessMode.WRITE,
            value=1,
            request_method="post",
            request_path="orders/1?dry=1",
            request_body=b'{"amount":1}',
        ).to_wire()
        assert send(port, "POST", "/crm/orders/1?dry=1", token, body=b'{"amount":1}')[0] == 200
    finally:
        enforcer.stop()


def test_route_can_require_request_binding(issuer: TokenIssuer, upstream: Any) -> None:
    enforcer, port = start_proxy(issuer, upstream, require_request_binding=True)
    try:
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        status, data, _ = send(port, "GET", "/crm/x", wire)
        assert status == 403 and reason(data) == "TOKEN_NOT_REQUEST_BOUND"
    finally:
        enforcer.stop()


def test_route_can_require_a_specific_agent(issuer: TokenIssuer, upstream: Any) -> None:
    enforcer, port = start_proxy(issuer, upstream, required_agent="owner")
    try:
        other = issuer.issue(agent_name="other", tool_name="crm").to_wire()
        assert send(port, "GET", "/crm/x", other)[0] == 403
        owner = issuer.issue(agent_name="owner", tool_name="crm").to_wire()
        assert send(port, "GET", "/crm/x", owner)[0] == 200
    finally:
        enforcer.stop()


def test_new_claims_are_tamper_evident(issuer: TokenIssuer) -> None:
    token = issuer.issue(agent_name="a", tool_name="crm", access_mode=AccessMode.READ_ONLY)
    round_tripped = AuthorizationToken.from_wire(token.to_wire())
    issuer.verify(round_tripped)
    forged = AuthorizationToken(**{**round_tripped.__dict__, "access_mode": "ADMIN"})
    with pytest.raises(TokenInvalid):
        issuer.verify(forged)


# -- proxy robustness ----------------------------------------------------------


def test_upstream_redirect_is_returned_not_followed(issuer: TokenIssuer, upstream: Any) -> None:
    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    other.requests = []  # type: ignore[attr-defined]
    threading.Thread(target=other.serve_forever, daemon=True).start()
    upstream.redirect_to = f"http://127.0.0.1:{other.server_address[1]}/stolen"
    enforcer, port = start_proxy(issuer, upstream)
    try:
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        status, _, response = send(
            port, "GET", "/crm/redirect", wire, headers={"Authorization": "Bearer upstream"}
        )
        assert status == 302
        assert response.getheader("Location") == upstream.redirect_to
        assert other.requests == []  # type: ignore[attr-defined]
    finally:
        enforcer.stop()
        other.shutdown()
        other.server_close()


def test_response_has_one_content_length_and_size_limit(issuer: TokenIssuer, upstream: Any) -> None:
    enforcer, port = start_proxy(issuer, upstream)
    try:
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        _, _, response = send(port, "GET", "/crm/x", wire)
        assert len([k for k, _ in response.getheaders() if k.lower() == "content-length"]) == 1
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        assert send(port, "GET", "/crm/large", wire)[0] == 502
    finally:
        enforcer.stop()


def test_hop_by_hop_request_headers_are_not_forwarded(issuer: TokenIssuer, upstream: Any) -> None:
    enforcer, port = start_proxy(issuer, upstream)
    try:
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        send(port, "GET", "/crm/x", wire, headers={"Proxy-Authorization": "Basic abc"})
        assert "Proxy-Authorization" not in upstream.requests[0][2]
    finally:
        enforcer.stop()


def test_non_ascii_signature_gets_a_403_and_on_denied(issuer: TokenIssuer, upstream: Any) -> None:
    denied: list[str] = []
    enforcer, port = start_proxy(issuer, upstream)
    enforcer._on_denied = lambda _tool, why: denied.append(why)
    try:
        wire = issuer.issue(agent_name="a", tool_name="crm").to_wire()
        status, data, _ = send(port, "GET", "/crm/x", wire.rsplit(".", 1)[0] + ".\xe9\xe9")
        assert status == 403 and reason(data) == "TOKEN_INVALID"
        assert denied == ["TOKEN_INVALID"]
    finally:
        enforcer.stop()


@pytest.mark.parametrize("payload", [b"[]", b'{"token_id":1}'])
def test_malformed_claims_raise_token_invalid(payload: bytes) -> None:
    import base64

    with pytest.raises(TokenInvalid):
        AuthorizationToken.from_wire(base64.urlsafe_b64encode(payload).decode() + ".sig")


def test_token_store_survives_concurrent_use() -> None:
    store = InMemoryTokenStore()
    failures: list[BaseException] = []

    def worker(number: int) -> None:
        try:
            for index in range(2000):
                expires = time.time() + (30 if index % 2 else -1)
                store.mark_used(f"{number}-{index}", expires)
        except BaseException as exc:  # noqa: BLE001
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []


# -- value limits and evidence -------------------------------------------------


def test_decorator_enforces_limit_passed_through_var_kwargs() -> None:
    boundary = make_boundary(ToolPermission("pay", max_value=100))

    @guarded_tool(boundary, tool_name="pay", value_arg="amount")
    def pay(**kwargs: Any) -> Any:
        return kwargs

    assert pay(amount=5) == {"amount": 5}
    with pytest.raises(BoundaryViolation):
        pay(amount=10_000_000)


def _langchain_transfer() -> Any:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import BaseTool

    class Transfer(BaseTool):
        name: str = "transfer"
        description: str = "Transfer money."

        def _run(self, amount: str) -> str:
            return f"sent {amount}"

    return Transfer()


def test_langchain_string_input_is_limit_checked() -> None:
    from toolboundary.integrations.langchain import guard_tool

    boundary = make_boundary(ToolPermission("transfer", max_value=100))
    guarded = guard_tool(_langchain_transfer(), boundary, value_arg="amount")
    assert guarded.invoke("5") == "sent 5"
    with pytest.raises(BoundaryViolation):
        guarded.invoke("10000000")


def test_langchain_digest_binds_positional_input() -> None:
    from toolboundary.integrations.langchain import guard_tool

    provider = RecordingProvider()
    boundary = make_boundary(
        ToolPermission("transfer"), provider=provider, provider_mode=ProviderMode.ENFORCE
    )
    guarded = guard_tool(_langchain_transfer(), boundary)
    guarded.invoke("alice")
    guarded.invoke("mallory")
    assert provider.calls[0].arguments == {"amount": "alice"}
    assert provider.calls[0].call_digest != provider.calls[1].call_digest


def test_langchain_decorated_tools_run_and_are_limit_checked() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from toolboundary.integrations.langchain import guard_tool

    @tool
    def transfer(amount: str) -> str:
        """Transfer money."""
        return f"sent {amount}"

    boundary = make_boundary(ToolPermission("transfer", max_value=100))
    guarded = guard_tool(transfer, boundary, value_arg="amount")
    assert guarded.invoke("5") == "sent 5"
    assert guarded.invoke({"amount": "6"}) == "sent 6"
    with pytest.raises(BoundaryViolation):
        guarded.invoke("10000000")


def test_async_tool_evidence_reflects_the_real_outcome() -> None:
    provider = RecordingProvider()
    boundary = make_boundary(
        ToolPermission("a"), provider=provider, provider_mode=ProviderMode.ENFORCE
    )

    @guarded_tool(boundary, tool_name="a")
    async def failing() -> None:
        raise RuntimeError("tool failed")

    @guarded_tool(boundary, tool_name="a")
    async def working() -> str:
        return "done"

    with pytest.raises(RuntimeError):
        asyncio.run(failing())
    assert provider.executions[-1].status == "error"
    assert asyncio.run(working()) == "done"
    assert provider.executions[-1].status == "success"


def test_enforced_provider_denial_is_audited_as_deny() -> None:
    sink = MemorySink()
    boundary = make_boundary(
        ToolPermission("a"),
        provider=RecordingProvider(allowed=False),
        provider_mode=ProviderMode.ENFORCE,
        audit=AuditTrail([sink]),
    )
    with pytest.raises(ProviderAuthorizationDenied):
        boundary.authorize_call(tool_name="a", arguments={})
    assert sink.events[-1].decision == "DENY"
    assert sink.events[-1].reason_code == "PROVIDER_DENIED"


# -- operations and redaction --------------------------------------------------


@pytest.mark.parametrize("operation", ["DROP_TABLE", "drop_table ", "ｄｒｏｐ_table"])
def test_blocked_operations_ignore_case_spacing_and_width(operation: str) -> None:
    global_block = make_boundary(
        ToolPermission("db"), blocked_operations=frozenset({"drop_table"})
    )
    tool_block = make_boundary(
        ToolPermission("db", blocked_operations=frozenset({"drop_table"}))
    )
    for boundary in (global_block, tool_block):
        with pytest.raises(BoundaryViolation):
            boundary.check("db", operation=operation)


def test_non_string_operation_is_denied() -> None:
    boundary = make_boundary(ToolPermission("db"))
    with pytest.raises(BoundaryViolation):
        boundary.check("db", operation=["drop_table"])  # type: ignore[arg-type]


def test_audit_metadata_redacts_nested_and_alternate_secret_names() -> None:
    sink = MemorySink()
    boundary = make_boundary(ToolPermission("t"), audit=AuditTrail([sink]))

    @guarded_tool(boundary, tool_name="t")
    def call(headers: dict[str, str], pwd: str, author: str, **kwargs: Any) -> None:
        return None

    call({"Authorization": "Bearer abc123"}, "hunter2", "Ada", password="hunter3", note="Bearer x")
    rendered = json.dumps(sink.events[-1].metadata)
    for secret in ("abc123", "hunter2", "hunter3", "Bearer x"):
        assert secret not in rendered
    assert "Ada" in rendered


def test_provider_receives_redacted_arguments_but_digest_binds_real_values() -> None:
    provider = RecordingProvider()
    boundary = make_boundary(
        ToolPermission("t"), provider=provider, provider_mode=ProviderMode.ENFORCE
    )

    @guarded_tool(boundary, tool_name="t", sensitive_args=frozenset({"pin"}))
    def call(pin: str, api_key: str, city: str) -> str:
        return city

    call("1111", "key-one", "Pune")
    call("2222", "key-two", "Pune")
    first, second = provider.calls
    assert first.arguments == {"pin": "<redacted>", "api_key": "<redacted>", "city": "Pune"}
    assert first.call_digest != second.call_digest
