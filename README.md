# ToolBoundary

**A Python library for AI-agent runtime security, LLM tool-call authorization, and policy enforcement — without a separate service.**

[![PyPI](https://img.shields.io/pypi/v/toolboundary?cacheSeconds=300)](https://pypi.org/project/toolboundary/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/Jaycubic/toolboundary/actions/workflows/ci.yml/badge.svg)](https://github.com/Jaycubic/toolboundary/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Jaycubic/toolboundary/branch/main/graph/badge.svg)](https://codecov.io/gh/Jaycubic/toolboundary)

ToolBoundary enforces tool permissions, operation allow-lists, rate limits, approval rules,
emergency stops, audit trails, optional authorization/evidence providers, and token-gated
HTTP proxying for AI agents and LLM applications.

**Latest release: [v1.1.0](https://github.com/Jaycubic/toolboundary/releases/tag/v1.1.0)** ·
[Install from PyPI](https://pypi.org/project/toolboundary/)

ToolBoundary answers one question, fast and locally, every time your agent tries to call a
tool: **"is this exact call allowed, right now?"**

No separate web app or database is required. Your policy is plain Python, version-controlled
with the rest of your code.

```bash
pip install toolboundary
```

## What's new in v1.1.0

ToolBoundary v1.1.0 adds a policy gateway for protecting your tools from a compromised agent.

- **Policy outside the agent** — `toolboundary.gateway` runs in its own process. The agent
  holds only an identity key, so it can't approve its own requests.
- **Deny by default** — a request must match a `GatewayRule` you wrote.
- **Limits from the real request** — value and record count are read from the bytes being
  forwarded, not from what the agent claims.
- **Credentials stay out of the agent** — the gateway adds them when it forwards a request.

The gateway only protects you when it's deployed separately from the agent. See the
[gateway guide](docs/GATEWAY.md) for the requirements.

### Upgrade notes

- Guarding a tool without `access_mode` now raises `FutureWarning`. It still falls back to
  `READ_ONLY`, and `access_mode` will be required in ToolBoundary 2.0.
- `strict_limits=True` now also requires a value when a tool has only a `min_value`.

## What's new in v1.0.5

ToolBoundary v1.0.5 is a security release, and every user should upgrade.

- **A kill switch that can stop a running agent** — `kill_switch_file` is checked on every
  call, so creating the file halts the agent immediately.
- **Fail-closed AgentKey setup** — `AgentKeyProvider` now needs a real client. The demo mode
  that allows every call must be requested with `simulate=True`.
- **Tighter proxy tokens** — tokens carry the call's access mode, so read-only tokens can't
  use write methods. They can also be bound to one exact method, path and body.
- **Limits apply however arguments arrive** — `max_value` and `max_records` now cover
  positional LangChain input and `**kwargs` functions.
- **Safer proxy behavior** — upstream redirects are returned rather than followed, and
  response size and idle connections are capped.
- **Harder-to-evade block-lists** — blocked operations match regardless of case, surrounding
  spaces, or character width.
- **Better secret handling** — nested secrets are redacted, and providers no longer receive
  secret-named arguments.
- **More accurate evidence** — async tools record their real outcome, and enforced provider
  denials appear as `DENY` in the audit log.

### Upgrade notes

- `AgentKeyProvider()` without a client now raises `ConfigurationError`. Pass your client, or
  `simulate=True` for demos only.
- Proxy `POST`, `PUT`, `PATCH` and `DELETE` requests need a token with `WRITE` access or
  higher. Pass the real `access_mode` to `check_and_authorize()`.
- If you rely on the proxy following upstream redirects, your client must now follow them.
- The `langchain` extra now requires a `langchain-core` release patched for CVE-2025-68664.
- `kill_switch_env` is unchanged, but it only works if set before the process starts. Use
  `kill_switch_file` for emergency stops.

## What's new in v1.0.4

ToolBoundary v1.0.4 adds an optional CrewAI integration, allowing authorization to run inside CrewAI's actual tool-execution path rather than relying on an agent to remember a separate policy check.

### CrewAI integration

- **Guard individual or multiple CrewAI tools** with `guard_tool` and `guard_tools`.
- **Authorize synchronous and asynchronous execution** in the wrapped tool's `_run` / `_arun` paths, including structured-tool invocation.
- **Apply per-tool policies** such as access mode and numeric value limits, including positional arguments normalized against the original tool signature.
- **Keep framework dependencies optional** — install `toolboundary[crewai]` to use the adapter; the core package remains dependency-free.
- **Provider-aware execution** uses ToolBoundary's existing authorization and execution-evidence lifecycle when an external provider is configured.

Install the optional integration with `pip install 'toolboundary[crewai]'`.

## What's new in v1.0.3

ToolBoundary v1.0.3 is a security and correctness release. It prevents client paths
from changing a network proxy's configured upstream host, rejects traversal paths,
validates numeric limits, requires named operations for configured allow-lists, and
redacts sensitive arguments from decorator-generated audit metadata.

### Security and correctness fixes

- **Network proxy target validation** — request paths cannot change the configured
  upstream authority or traverse above its base path; oversized request bodies are
  rejected.
- **Operation allow-lists** — a call must provide an operation when a tool has an
  `allowed_operations` allow-list.
- **Numeric limits** — malformed and non-finite values are denied, optional minimum
  values are supported, and `strict_limits=True` requires values for configured
  ceilings.
- **Audit argument redaction** — common secret-like argument names are redacted by
  default, with options for custom sensitive argument names and value-free logging.
- **Execution evidence** — a tool that successfully returns `None` is recorded as a
  successful execution.

This release also includes the provider-neutral authorization/evidence architecture,
ToolBoundary-side AgentKey reference integration, and optional Redis shared backends
introduced in v1.0.2.

## What's new in v1.0.2 (historical)

ToolBoundary v1.0.2 consolidates the provider-neutral authorization/evidence architecture introduced in v1.0.0 with the ToolBoundary-side AgentKey reference integration and an optional Redis backend for shared rate limiting and token storage, while keeping ToolBoundary as the local enforcement authority.

### Key additions

- **Optional Redis shared backends** — `RedisSlidingWindowRateLimiter` and `RedisTokenStore` for multi-process and multi-replica deployments, available through `toolboundary[redis]` without changing the in-memory default
- **`EvidenceProvider` protocol** — a clean interface any external provider can implement to add authorization and execution evidence without coupling to a specific vendor
- **Provider-aware execution lifecycle** — `authorize_call()` / `record_execution()` freeze the exact tool call, compute the current ToolBoundary call digest, consult an optional provider, and record execution evidence
- **Observe / Enforce modes** — `ProviderMode.OBSERVE` logs provider decisions without blocking; `ProviderMode.ENFORCE` fails closed on provider denial or unavailability
- **`evaluate()` method** — returns a structured `LocalDecision` instead of raise-on-deny, enabling richer programmatic integration
- **Deterministic call binding** — the current Python implementation uses canonical JSON key ordering to produce stable SHA-256 call digests; future cross-language/native signed evidence will use a standardized canonicalization scheme (RFC 8785 / JCS) rather than relying on Python-specific JSON serialization
- **Replay prevention** — consumed authorizations cannot be reused for a second dispatch
- **Post-dispatch resilience** — if a provider fails to record execution evidence, the local record is preserved

### Core invariant

> **ToolBoundary remains the local enforcement authority.** An external provider can add a stricter gate or external evidence, but it can **never** turn a local deny into an allow.

## Why this exists

Enterprise AI-governance platforms (agent registries, policy engines, approval
dashboards) make sense when a large organization has dozens of AI agents built by
different teams and needs a compliance layer to track all of them. That's real
infrastructure for a real problem — but it's disproportionate for the much more common
case: **one developer or a small team building one to a handful of agents**, who just
need to make sure a tool-calling agent can't do something catastrophic.

ToolBoundary is built for that second case. It costs nothing, requires no
infrastructure, and takes minutes to add to an existing agent.

## Quickstart

```python
from toolboundary import Boundary, ToolPermission, AutonomyLevel, AccessMode

boundary = Boundary(
    agent_name="support-agent",
    autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
    permissions=[
        ToolPermission("read_ticket_db", access_mode=AccessMode.READ_ONLY),
        ToolPermission(
            "send_reply_email",
            access_mode=AccessMode.EXECUTE,
            max_calls_per_hour=30,
        ),
    ],
    blocked_operations=frozenset({"delete_ticket"}),
    max_actions_per_hour=100,
    kill_switch_file="/var/run/toolboundary/support-agent.stop",
)

# Somewhere in your agent's tool-calling code:
boundary.check("read_ticket_db", access_mode=AccessMode.READ_ONLY)   # passes silently
boundary.check("delete_ticket", operation="delete_ticket")           # raises BoundaryViolation
```

If a call is denied, `boundary.check(...)` raises `BoundaryViolation` (or a more
specific subclass like `KillSwitchActive` or `RateLimitExceeded`). If a call needs a
human before it can proceed, it raises `ApprovalRequired`. Every decision — allow,
deny, or approval-required — is written to a structured audit log automatically.

### Emergency stop

```bash
touch /var/run/toolboundary/support-agent.stop
```

Create the file your `Boundary` was configured with, and every future call for that
agent is denied immediately — no restart required, no code change, no separate dashboard
to log into. Delete the file to resume. If the file's status can't be checked, the switch
counts as engaged.

`kill_switch_env` is also available, but a running process's environment can't be changed
from outside, so it only works if set before the agent starts.

## Ways to enforce the boundary

### 1. Decorator (plain Python functions)

```python
from toolboundary import guarded_tool, AccessMode

@guarded_tool(boundary, access_mode=AccessMode.EXECUTE, value_arg="amount")
def wire_transfer(account_id: str, amount: float) -> str:
    return f"transferred {amount} to {account_id}"

wire_transfer(account_id="acct_1", amount=250_000)
# raises BoundaryViolation if 250_000 exceeds the permission's max_value —
# the function body never executes.
```

Once a function is decorated, calling it *is* calling through ToolBoundary. There is no
code path to the real implementation that skips the check.

### 2. LangChain tools

```python
from toolboundary.integrations.langchain import guard_tools
from toolboundary import AccessMode

guarded_tools = guard_tools(
    [read_db_tool, send_email_tool, wire_transfer_tool],
    boundary,
    default_access_mode=AccessMode.READ_ONLY,
    overrides={
        "send_email_tool": {"access_mode": AccessMode.EXECUTE},
        "wire_transfer_tool": {"access_mode": AccessMode.EXECUTE, "value_arg": "amount"},
    },
)

agent_executor = AgentExecutor(agent=agent, tools=guarded_tools)
```

This wraps the LangChain `BaseTool` objects themselves — the objects your
`AgentExecutor` actually invokes when the LLM decides to call a tool — so the boundary
check runs inside LangChain's own tool-execution path, not as a step the agent's
reasoning loop has to remember to call.

Install with the LangChain extra: `pip install toolboundary[langchain]`

### 3. CrewAI tools

```python
from toolboundary.integrations.crewai import guard_tools
from crewai import Crew
from toolboundary import AccessMode

guarded_tools = guard_tools(
    [read_db_tool, wire_transfer_tool],
    boundary,
    access_mode=AccessMode.READ_ONLY,
    overrides={
        "wire_transfer_tool": {
            "access_mode": AccessMode.EXECUTE,
            "value_arg": "amount",
        },
    },
)

crew = Crew(
    agents=[agent],
    tasks=[task],
)

```

## External authorization providers (introduced in v1.0.2)


ToolBoundary can optionally consult an external authorization provider before dispatching a tool call. The provider adds a second gate — it can never weaken a local policy decision.

### Without a provider (default — unchanged from v0.1.0)

```python
boundary = Boundary(
    agent_name="support-agent",
    ...
)
# Works exactly as before. No external service needed.
```

### With a provider (observe mode)

```python
from toolboundary import Boundary, ProviderMode

boundary = Boundary(
    agent_name="support-agent",
    ...,
    provider=my_provider,
    provider_mode=ProviderMode.OBSERVE,
)
# Provider decisions are logged but don't block locally-allowed actions.
# Provider unavailability is gracefully degraded.
```

### With a provider (enforce mode)

```python
boundary = Boundary(
    agent_name="support-agent",
    ...,
    provider=my_provider,
    provider_mode=ProviderMode.ENFORCE,
)
# Provider must explicitly allow the action.
# Provider denial or unavailability blocks execution before dispatch.
```

### Implementing a custom provider

Any class that implements the `EvidenceProvider` protocol can serve as a provider:

```python
from toolboundary import EvidenceProvider, FrozenToolCall, LocalDecision, ProviderGrant
from toolboundary import ExecutionRecord, ProviderReceipt

class MyProvider:
    def authorize(self, call: FrozenToolCall, local: LocalDecision) -> ProviderGrant:
        # Your authorization logic here
        return ProviderGrant(allowed=True, provider="my-provider")

    def record(self, grant: ProviderGrant, execution: ExecutionRecord) -> ProviderReceipt:
        # Your evidence recording logic here
        return ProviderReceipt(recorded=True, provider="my-provider")
```

### AgentKey integration

[AgentKey](https://agentkey.us/) is the first external provider reference integration built against ToolBoundary's provider-neutral contract.

The ToolBoundary repository contains the **ToolBoundary-side reference integration,
example, and end-to-end test coverage**. The AgentKey-specific provider implementation
is maintained on the AgentKey side and plugs into the existing `EvidenceProvider`
interface.

```python
from toolboundary import Boundary, ToolPermission, AutonomyLevel, AccessMode, ProviderMode
from toolboundary.integrations.agentkey import AgentKeyProvider

provider = AgentKeyProvider(client=your_agentkey_client)

boundary = Boundary(
    agent_name="support-agent",
    autonomy=AutonomyLevel.AUTONOMOUS,
    permissions=[ToolPermission("read_ticket", access_mode=AccessMode.READ_ONLY)],
    provider=provider,
    provider_mode=ProviderMode.ENFORCE,
)
```

Key points:

- **AgentKey is optional.** The core `pip install toolboundary` remains independent.
- **ToolBoundary remains the local enforcement authority.** A local deny is final.
- **The provider contract is vendor-neutral.** Other authorization/evidence providers can implement the same interface.
- **Cross-language canonical evidence is not defined by Python `json.dumps()`.** The native signed-evidence work will use RFC 8785 (JCS) as the canonicalization target.
- **The reference integration is intentionally small.** It covers pre-dispatch authorization and post-dispatch evidence without moving security authority out of ToolBoundary.

See [`examples/agentkey_integration.py`](examples/agentkey_integration.py) for the ToolBoundary-side example, [`tests/test_agentkey_integration.py`](tests/test_agentkey_integration.py) for the integration coverage, and [`src/toolboundary/redis_backend.py`](src/toolboundary/redis_backend.py) for the optional Redis backends.

### Authorization flow

```
Local policy check → DENY? → stop (provider never consulted)
                   → ALLOW? → freeze call → compute digest → provider.authorize()
                                                            → execute exact call
                                                            → provider.record()
```

## What a `Boundary` can enforce

| Control | Example |
|---|---|
| Which tools an agent may use at all | `permissions=[ToolPermission("read_db", ...)]` |
| Operation-level allow/block lists | `blocked_operations=frozenset({"delete_customer"})` |
| Access mode (READ_ONLY / WRITE / EXECUTE / ADMIN) | `access_mode=AccessMode.EXECUTE` |
| Transaction value ceilings | `ToolPermission(..., max_value=500_000)` |
| Record-count ceilings | `ToolPermission(..., max_records=100)` |
| Rate limits (global or per-tool) | `max_actions_per_hour=60` |
| Autonomy level | `AutonomyLevel.RECOMMEND_ONLY` / `HUMAN_APPROVAL_REQUIRED` / `LIMITED_AUTONOMOUS` / `AUTONOMOUS` / `QUARANTINED` |
| Time-bounded validity | `valid_from=`, `valid_to=` |
| Environment restriction | `allowed_environments=frozenset({"DEV", "TEST"})` |
| Emergency kill switch | in-process flag, kill-switch file, or startup environment variable |
| Custom policy logic | `policy_hooks=[my_custom_check]` |
| External authorization provider | `provider=my_provider, provider_mode=ProviderMode.ENFORCE` |
| Exact-call binding with cryptographic digest | Automatic when a provider is configured |

Full field reference: see [`docs/API.md`](docs/API.md).

## Audit trail

Every decision produces a structured event. By default it goes to Python's standard
`logging` module under the logger name `toolboundary.audit`, so it flows into whatever
logging pipeline you already have (stdout, a file, CloudWatch, Datadog, etc.) with zero
extra code.

```python
from toolboundary.audit import AuditTrail, JSONLFileSink

boundary = Boundary(
    agent_name="support-agent",
    ...,
    audit=AuditTrail(sinks=[JSONLFileSink("toolboundary-audit.jsonl")]),
)
```

For native or cross-language verifiable evidence, the canonicalization and signing format must be specified independently of Python's JSON serializer. See the RFC 8785/JCS evidence work planned for the native evidence roadmap.

When a provider is configured, audit events automatically include evidence metadata:
call digests, provider decisions, authorization IDs, and result digests.

A `WebhookSink` is also included if you want to forward events to a self-hosted
dashboard or a centralized governance platform. Audit delivery is always best-effort —
a network hiccup in your audit pipeline can never block or crash your agent, because
the ALLOW/DENY decision has already been enforced locally before the sink is invoked.

## Design philosophy

- **Fail closed.** Anything ambiguous, misconfigured, or erroring is treated as denied
  by default. See `fail_closed_on_hook_error` for the one place this is configurable.
- **No infrastructure required.** No database, no server, no login. The whole thing is
  a Python object you construct alongside your agent code.
- **Version-controlled policy.** Your boundary is code, reviewed in the same pull
  requests as everything else — not a setting buried in a web UI that drifts silently
  out of sync with what the agent actually does.
- **Loud by default.** Denials raise exceptions, not silent `False` returns that are
  easy to accidentally ignore.
- **Framework-agnostic core, framework-specific adapters.** The core `Boundary` has
  zero dependencies. Framework integrations for LangChain and CrewAI are optional extras.
- **Local authority, optional extension.** External providers add evidence and stricter
  gates but never override local policy. ToolBoundary works identically with or without
  a provider configured.

## Protecting against a compromised agent

`toolboundary.gateway` runs policy outside the agent's process. The agent
holds only a key, every request must match a rule you wrote, limits are read from the real
request, and tool credentials stay in the gateway. It needs the right deployment to be effective:
see the [gateway guide](docs/GATEWAY.md).

## Known limitations — please read this

ToolBoundary is an **in-process, application-layer** library. Being explicit about what
it does *not* do is more important than what it does:

- **It cannot stop an agent that bypasses it entirely.** If your agent's code has any
  path that calls a tool's real implementation directly — instead of through a
  `@guarded_tool`-wrapped function or a `guard_tool`-wrapped LangChain / CrewAI tool — that call
  is not evaluated. ToolBoundary governs the doors you route through it; it is not a
  network firewall.
- **It is not a substitute for credential scoping.** If the underlying API key or
  database credential your tool uses has broader permissions than ToolBoundary's policy
  allows, a determined attacker who obtains that credential directly bypasses
  ToolBoundary entirely. Scope your actual credentials as tightly as you can — ToolBoundary
  is a second layer, not a replacement for the first.
- **It is not a compliance/audit system of record for large organizations.** If you
  have dozens of agents across multiple teams and need human governance workflows,
  cross-team registries, and formal approval routing, look at enterprise AI governance
  platforms — ToolBoundary is intentionally not trying to be that.
- **The in-memory rate limiter is per-process.** If you run multiple replicas of your
  agent, each process has its own rate-limit counters unless you supply a shared
  backend. Install `toolboundary[redis]` and pass
  `RedisSlidingWindowRateLimiter` / `RedisTokenStore` from
  `toolboundary.redis_backend` into `Boundary(rate_limiter=...)` and
  `NetworkEnforcer(token_store=...)`.
- **Provider evidence is only as trustworthy as the provider.** An SDK-reported result
  does not itself prove that an external side effect occurred — it proves the SDK
  reported it. See the provider documentation for what guarantees each provider makes.
- **Numeric ceilings need supplied values by default.** If the caller omits `value` or
  `record_count`, its configured maximum is not evaluated unless
  `Boundary(strict_limits=True)` is enabled.

- **The token secret must stay away from the agent.** Tokens use a shared HMAC secret, so
  code in a process holding the `TokenIssuer` can mint tokens without calling
  `Boundary.check()`, and token request binding can't stop the caller declaring a false
  `value`. To defend against a compromised agent, use the
  [policy gateway](docs/GATEWAY.md).
- **Declared access modes are trusted.** Omitting `access_mode` when guarding a tool warns
  and falls back to `READ_ONLY`, and it will be required in 2.0. The library can't check that a
  declared mode matches what a tool really does.
- **Allowed actions can still be misused.** Even with the gateway, a prompt-injected agent can
  do anything its policy permits, so keep permissions narrow and limits low.

If your threat model requires guaranteeing that a compromised agent *physically
cannot* reach a tool's network endpoint except through an approved path, you need a
network-layer control (a sidecar proxy, egress firewall rule, or service mesh policy)
in addition to ToolBoundary, not instead of it.

## Installation

```bash
pip install toolboundary                # core, zero dependencies
pip install 'toolboundary[langchain]'   # + LangChain integration
pip install 'toolboundary[crewai]'      # + CrewAI integration
pip install 'toolboundary[redis]'       # + shared Redis rate limiter / token store
```

## Contributing

Issues and PRs are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Ideas that would make great first contributions:
- Custom `EvidenceProvider` implementations for popular platforms
- AutoGen / LangGraph integrations (mirroring the existing optional framework adapters)
- A minimal read-only local dashboard that tails a `JSONLFileSink` log

## License

MIT — see [`LICENSE`](LICENSE).
