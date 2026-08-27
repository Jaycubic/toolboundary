# API Reference

## `toolboundary.Boundary`

The core policy object. One `Boundary` instance represents the maximum
autonomy of one agent.

```python
Boundary(
    agent_name: str,
    *,
    autonomy: AutonomyLevel = AutonomyLevel.HUMAN_APPROVAL_REQUIRED,
    permissions: list[ToolPermission] | None = None,
    blocked_operations: frozenset[str] = frozenset(),
    allowed_environments: frozenset[str] | None = None,
    environment: str = "PRODUCTION",
    max_actions_per_hour: int | None = None,
    kill_switch: bool = False,
    kill_switch_env: str | None = None,
    valid_from: float | None = None,
    valid_to: float | None = None,
    audit: AuditTrail | None = None,
    policy_hooks: list[PolicyHook] | None = None,
    fail_closed_on_hook_error: bool = True,
    token_issuer: TokenIssuer | None = None,
)
```

| Parameter | Description |
|---|---|
| `agent_name` | Identifier for this agent, used in every audit event and error message. |
| `autonomy` | See `AutonomyLevel` below. Governs the default approval behavior. |
| `permissions` | List of `ToolPermission` — the only tools this agent may call. Any tool not listed is denied with `TOOL_NOT_ALLOWED`. |
| `blocked_operations` | Operation names denied for **every** tool, regardless of that tool's own permission. Blocked always wins. |
| `allowed_environments` | If set, `environment` must be one of these or every call is denied. |
| `environment` | The environment this boundary is currently running in (e.g. `"DEV"`, `"PRODUCTION"`). |
| `max_actions_per_hour` | Global sliding-window rate limit across all tools for this agent. |
| `kill_switch` | In-process boolean. Set `True` (or call `engage_kill_switch()`) to deny everything immediately. |
| `kill_switch_env` | Name of an environment variable checked on **every** call. Lets an operator halt a running agent externally (`export MY_KILL_SWITCH=1`) without a restart. |
| `valid_from` / `valid_to` | Unix timestamps bounding when this boundary is valid at all. |
| `audit` | An `AuditTrail` instance. Defaults to logging via stdlib `logging`. |
| `policy_hooks` | List of callables `(CallContext) -> str | None` for custom logic. Return a string to deny with that reason, `None` to allow. |
| `fail_closed_on_hook_error` | If `True` (default), an exception inside a policy hook denies the call. If `False`, the hook is treated as "allow" on error. |
| `token_issuer` | Optional `toolboundary.tokens.TokenIssuer`. Only needed if you use `check_and_authorize()` / the network enforcement layer. |

### `Boundary.check(...)`

```python
boundary.check(
    tool_name: str,
    *,
    operation: str | None = None,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    value: float | None = None,
    record_count: int | None = None,
    correlation_id: str | None = None,
    metadata: dict | None = None,
) -> None
```

Evaluates one prospective tool call. Returns `None` silently if allowed.
Raises on denial or approval-required (see Exceptions below).

Order of evaluation (first failure wins):

1. Kill switch engaged → `KillSwitchActive`
2. Agent quarantined (`autonomy == QUARANTINED`) → `BoundaryViolation`
3. Outside `valid_from`/`valid_to` window → `BoundaryViolation`
4. `environment` not in `allowed_environments` → `BoundaryViolation`
5. `operation` in global `blocked_operations` → `BoundaryViolation`
6. `tool_name` not in `permissions` → `BoundaryViolation`
7. `operation` not allowed for that tool → `BoundaryViolation`
8. `access_mode` exceeds the tool's granted access mode → `BoundaryViolation`
9. `value` exceeds the tool's `max_value` → `BoundaryViolation`
10. `record_count` exceeds the tool's `max_records` → `BoundaryViolation`
11. Rate limit (global or per-tool) exceeded → `RateLimitExceeded`
12. Any `policy_hooks` deny → `BoundaryViolation`
13. Approval required (by autonomy level or per-permission flag) → `ApprovalRequired`

Every outcome — allow, deny, or approval-required — is recorded to `audit`.

### `Boundary.check_and_authorize(...)`

Same signature and evaluation as `check()`, but returns an
`AuthorizationToken` on success instead of `None`. Requires `token_issuer`
to have been configured. See [Network Enforcement](#network-enforcement)
below.

### `Boundary.engage_kill_switch()` / `disengage_kill_switch()`

Programmatic control of the in-process kill switch flag.

---

## `toolboundary.ToolPermission`

```python
ToolPermission(
    tool_name: str,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    allowed_operations: frozenset[str] | None = None,
    blocked_operations: frozenset[str] = frozenset(),
    max_calls_per_hour: int | None = None,
    max_value: float | None = None,
    max_records: int | None = None,
    requires_approval: bool = False,
)
```

Declares what an agent may do with **one** named tool. `access_mode` is
checked as a ceiling: requesting a higher mode than granted is denied,
requesting a lower or equal mode is fine (e.g. a tool granted `EXECUTE`
can still be called with `access_mode=READ_ONLY`).

---

## `toolboundary.AutonomyLevel`

| Value | Meaning |
|---|---|
| `RECOMMEND_ONLY` | Agent may only take `READ_ONLY` actions; anything else requires approval. |
| `HUMAN_APPROVAL_REQUIRED` | **Every** action requires approval, regardless of tool permissions. |
| `LIMITED_AUTONOMOUS` | Agent executes within its declared tool/value/rate limits without per-call approval (unless a specific `ToolPermission.requires_approval=True`). |
| `AUTONOMOUS` | Broadest autonomy; still fully subject to all other boundary rules. |
| `QUARANTINED` | Every action denied, no exceptions. Use this to immediately and unambiguously halt an agent under investigation. |

## `toolboundary.AccessMode`

`READ_ONLY`, `WRITE`, `EXECUTE`, `ADMIN` — checked as an ordered ceiling
(`READ_ONLY < WRITE < EXECUTE < ADMIN`) against what each `ToolPermission`
grants.

---

## Exceptions

All exceptions live in `toolboundary.exceptions` and are re-exported from
the top-level `toolboundary` package.

| Exception | Raised when |
|---|---|
| `ToolBoundaryError` | Base class for everything below. |
| `BoundaryViolation` | An action is denied. Has `.agent_name`, `.tool_name`, `.operation`, `.rule` (a `ViolationReason` string) attributes. |
| `KillSwitchActive` | Subclass of `BoundaryViolation`; the kill switch was engaged. |
| `RateLimitExceeded` | Subclass of `BoundaryViolation`; a rate limit was hit. |
| `ApprovalRequired` | The action needs a human. Not a security failure — a control-flow signal. Has `.agent_name`, `.tool_name`, `.operation`. |
| `ConfigurationError` | A `Boundary` was misconfigured (fails fast at setup, not at call time). |

---

## `toolboundary.guarded_tool` (decorator)

```python
@guarded_tool(
    boundary: Boundary,
    *,
    tool_name: str | None = None,
    operation: str | None = None,
    access_mode: AccessMode = AccessMode.READ_ONLY,
    value_arg: str | None = None,
    record_count_arg: str | None = None,
    correlation_id_arg: str | None = None,
)
def my_function(...): ...
```

Wraps a plain Python function so `boundary.check(...)` runs automatically
before the function body executes. `value_arg` / `record_count_arg` /
`correlation_id_arg` name keyword arguments on the decorated function
whose runtime values should be forwarded into the boundary check.

---

## `toolboundary.integrations.langchain`

Requires `pip install toolboundary[langchain]`.

```python
from toolboundary.integrations.langchain import guard_tool, guard_tools
```

- `guard_tool(tool, boundary, **kwargs)` → wraps one `BaseTool`.
- `guard_tools(tools, boundary, default_access_mode=..., overrides={...})` →
  wraps a whole tool list at once, with per-tool overrides by `tool.name`.

Both wrap the tool's `_run`/`_arun` methods directly, so the boundary
check runs inside LangChain's own tool-execution path — it is not
something the agent's reasoning loop has to remember to invoke.

---

## Network Enforcement

Requires no extra install (`toolboundary.network` and `toolboundary.tokens`
are stdlib-only) but is entirely opt-in — nothing in the core package
imports these modules.

### The problem this solves

`check()`, `guarded_tool`, and the LangChain wrappers are all
**application-layer** controls. If any code path in your agent calls a
tool's real network endpoint directly — bypassing ToolBoundary entirely —
none of the above can see or stop it.

### The mechanism

1. `toolboundary.tokens.TokenIssuer` issues short-lived (default 30s),
   single-use, HMAC-signed `AuthorizationToken`s.
2. `Boundary.check_and_authorize(...)` runs the normal `check()`
   evaluation, and on success, asks the configured `token_issuer` for a
   token scoped to exactly that `(agent_name, tool_name, operation)`.
3. `toolboundary.network.NetworkEnforcer` runs a small local HTTP proxy.
   Real tool endpoints are registered as `UpstreamRoute`s. The proxy only
   forwards a request if it carries a valid, unexpired, not-yet-used token
   in the `X-ToolBoundary-Token` header — otherwise it returns `403`
   immediately, without contacting the upstream at all.

```python
from toolboundary import Boundary, ToolPermission, AutonomyLevel, AccessMode
from toolboundary.tokens import TokenIssuer
from toolboundary.network import NetworkEnforcer, UpstreamRoute, AUTH_HEADER

issuer = TokenIssuer(secret="a-shared-secret-you-generate-and-keep-private")

boundary = Boundary(
    agent_name="quote-agent",
    autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
    permissions=[ToolPermission("crm_api", access_mode=AccessMode.READ_ONLY)],
    token_issuer=issuer,
)

enforcer = NetworkEnforcer(
    issuer=issuer,
    routes=[UpstreamRoute("crm_api", "https://internal-crm.example.com")],
)
enforcer.start(host="127.0.0.1", port=8765)

# In your tool-calling code:
token = boundary.check_and_authorize("crm_api", access_mode=AccessMode.READ_ONLY)

import urllib.request
req = urllib.request.Request(
    "http://127.0.0.1:8765/crm_api/customers/42",
    headers={AUTH_HEADER: token.to_wire()},
)
urllib.request.urlopen(req)
```

For this to be a genuine guarantee (not just a convenience), your
deployment should also ensure the agent process **cannot reach
`internal-crm.example.com` directly** — e.g. via an egress firewall rule
or network policy that only allows outbound traffic to the loopback
proxy. `NetworkEnforcer` makes bypass require an explicit, auditable
infrastructure decision to open a hole, rather than a silent code path.

### Performance

Both layers are designed to add negligible overhead:

- `TokenIssuer.issue()` + `TokenIssuer.verify()`: ~20 microseconds combined (measured, single core, CPython 3.12).
- `Boundary.check()` full decision path: ~10 microseconds (measured, single core, CPython 3.12).
- `NetworkEnforcer` token verification: a single HMAC comparison per request, performed before any bytes are read from or forwarded to the upstream — the proxy adds no meaningful latency beyond the network hop that would occur anyway.

Run `python -m toolboundary.benchmarks` (see `examples/benchmark.py`) to reproduce these numbers on your own hardware.

### Multi-process deployments

Both `InMemoryTokenStore` (single-use tracking) and the in-memory rate
limiter are per-process by default. For multi-replica deployments, supply
a shared backing store (Redis is a natural fit for both — `SETNX` with
TTL for single-use tracking, `INCR`/`EXPIRE` for rate limiting). This is
one of the best first open-source contributions to this project — see
`CONTRIBUTING.md`.
