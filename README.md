# ToolBoundary

**Runtime security and policy enforcement for AI agents and LLM tool calls — local-first, provider-neutral, and deployable as a Python library.**

[![PyPI](https://img.shields.io/badge/pypi-v1.0.0-blue)](https://pypi.org/project/toolboundary/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-86%20passed-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](tests/)

ToolBoundary answers one question, fast and locally, every time your agent tries to call a
tool: **"is this exact call allowed, right now?"**

No separate web app. No database to stand up. No dashboard to log into. No subscription.
Your policy is plain Python, version-controlled with the rest of your code.

```bash
pip install toolboundary
```

## What's new in v1.0.0

ToolBoundary v1.0.0 introduces a **provider-neutral authorization and evidence layer** for AI-agent tool execution. It keeps ToolBoundary as the local enforcement authority while allowing optional external providers — including [AgentKey](https://agentkey.us/) — to add external authorization, approval, and verifiable evidence.

### Key additions

- **`EvidenceProvider` protocol** — a clean interface any external provider can implement to add authorization and execution evidence without coupling to a specific vendor
- **`authorize_call()` / `record_execution()`** — a centralized orchestration flow that freezes the exact tool call, computes a cryptographic call digest (SHA-256 of canonical JSON), consults an optional provider, and records execution evidence
- **Observe / Enforce modes** — `ProviderMode.OBSERVE` logs provider decisions without blocking; `ProviderMode.ENFORCE` fails closed on provider denial or unavailability
- **`evaluate()` method** — returns a structured `LocalDecision` instead of raise-on-deny, enabling richer programmatic integration
- **Deterministic canonicalization** — equivalent dictionaries (`{"a":1,"b":2}` vs `{"b":2,"a":1}`) always produce identical digests, binding authorization to the exact call
- **Replay prevention** — consumed authorizations cannot be reused for a second dispatch
- **Post-dispatch resilience** — if a provider fails to record execution evidence, the local record is preserved

### Core invariant

> **ToolBoundary remains the local enforcement authority.** An external provider can add a stricter gate or external evidence, but it can **never** turn a local deny into an allow.

## Why this exists

AI agents need a runtime security boundary between model-generated intent and real-world tool execution. ToolBoundary is designed to provide that boundary locally, without requiring a web application, database, gateway, or subscription.

For teams that need centralized authorization, approvals, or independently verifiable evidence, the same local boundary can optionally integrate with an external provider. This keeps the standalone library useful on its own while leaving room for centralized security infrastructure when the deployment requires it.

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
    kill_switch_env="TOOLBOUNDARY_KILL_SWITCH",
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
export TOOLBOUNDARY_KILL_SWITCH=1
```

Set the environment variable your `Boundary` was configured with, and every future
call for that agent is denied immediately — no restart required, no code change,
no separate dashboard to log into.

## Two ways to enforce the boundary

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

<<<<<<< HEAD
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

This wraps CrewAI `BaseTool` objects and enforces the boundary at the tool execution path. Authorization is checked before the underlying CrewAI tool runs, so denied calls never reach the real tool implementation.

Both synchronous and asynchronous CrewAI tool execution paths are supported.

Install with the CrewAI extra: `pip install toolboundary[crewai]`

## External authorization providers (new in v1.0.0)
=======
## External authorization & evidence providers
>>>>>>> upstream/main

ToolBoundary can optionally consult an external authorization or evidence provider before dispatching a tool call. The provider adds a second gate and/or evidence layer — it can never weaken a local policy decision.

One example is [AgentKey](https://agentkey.us/), which can provide external authorization and verifiable evidence around agent actions. ToolBoundary does not require AgentKey and remains fully functional in local-only mode.

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

### AgentKey interoperability

ToolBoundary's provider-neutral interface is designed so an external system such as [AgentKey](https://agentkey.us/) can plug into the same authorization lifecycle without becoming a dependency of the core library. The local ToolBoundary decision remains authoritative: a local deny is final.

The integration boundary is intentionally provider-neutral so other authorization or evidence systems can implement the same contract.

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
| Emergency kill switch | in-process flag or environment variable |
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
  zero dependencies. Framework integrations (LangChain today; more welcome via PR) are
  optional extras.
- **Local authority, optional extension.** External providers can add authorization,
  approvals, or evidence, but never override local policy. ToolBoundary works identically
  in local-only mode.

## AI Agent Security Keywords

AI agent security, LLM security, tool-calling security, AI agent guardrails, runtime policy enforcement, agent authorization, least-privilege AI agents, human-in-the-loop approval, verifiable AI action evidence, tool execution security, LangChain security, Python AI security, autonomous agent controls, and application-layer AI security.

---

## Known limitations — please read this

ToolBoundary is an **in-process, application-layer** library. Being explicit about what
it does *not* do is more important than what it does:

- **It cannot stop an agent that bypasses it entirely.** If your agent's code has any
  path that calls a tool's real implementation directly — instead of through a
  `@guarded_tool`-wrapped function or a `guard_tool`-wrapped LangChain tool — that call
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
  backing store (see `Boundary`'s internals / open an issue if you need this — a
  Redis-backed limiter is a natural community contribution).
- **Provider evidence is only as trustworthy as the provider.** An SDK-reported result
  does not itself prove that an external side effect occurred — it proves the SDK
  reported it. See the provider documentation for what guarantees each provider makes.

If your threat model requires guaranteeing that a compromised agent *physically
cannot* reach a tool's network endpoint except through an approved path, you need a
network-layer control (a sidecar proxy, egress firewall rule, or service mesh policy)
in addition to ToolBoundary, not instead of it.

## Installation

```bash
pip install toolboundary                # core, zero dependencies
pip install toolboundary[langchain]     # + LangChain integration
```

## Contributing

Issues and PRs are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Ideas that would make great first contributions:
- Custom `EvidenceProvider` implementations for popular platforms
- Redis-backed rate limiter for multi-process deployments
- CrewAI / AutoGen / LangGraph integrations (mirroring `integrations/langchain.py`)
- A minimal read-only local dashboard that tails a `JSONLFileSink` log

## License

MIT — see [`LICENSE`](LICENSE).
