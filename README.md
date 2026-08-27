# ToolBoundary

**Runtime boundary enforcement for AI agents — as a library, not a service.**

[![PyPI](https://img.shields.io/badge/pypi-v0.1.0-blue)](https://pypi.org/project/toolboundary/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

ToolBoundary answers one question, fast and locally, every time your agent tries to call a
tool: **"is this exact call allowed, right now?"**

No separate web app. No database to stand up. No dashboard to log into. No subscription.
Your policy is plain Python, version-controlled with the rest of your code.

```bash
pip install toolboundary
```

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
- Redis-backed rate limiter for multi-process deployments
- CrewAI / AutoGen / LangGraph integrations (mirroring `integrations/langchain.py`)
- A minimal read-only local dashboard that tails a `JSONLFileSink` log

## License

MIT — see [`LICENSE`](LICENSE).
