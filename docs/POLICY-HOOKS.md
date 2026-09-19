# Policy hook examples

A policy hook receives a `CallContext` for a prospective call. Return `None` to
allow this hook to pass, or a string to deny the call with that reason. Hooks
run synchronously after the built-in checks, in list order; an exception fails
closed by default. Keep them fast and deterministic.

## Time-of-day rule

Use UTC explicitly so the policy does not change with the host's local timezone.
This example blocks refunds outside a 07:00–20:00 UTC window:

```python
from datetime import datetime, timezone
from typing import Optional

from toolboundary import CallContext


def refund_hours(ctx: CallContext) -> Optional[str]:
    if ctx.tool_name != "issue_refund":
        return None

    hour = datetime.now(timezone.utc).hour
    if hour < 7 or hour >= 20:
        return "refunds are allowed only from 07:00 to 20:00 UTC"
    return None
```

## Environment restrictions

Prefer the built-in `allowed_environments` option when the whole boundary has
the same environment rule. Use a hook when the rule depends on the call:

```python
from typing import Optional

from toolboundary import AccessMode, CallContext


def production_write_guard(ctx: CallContext) -> Optional[str]:
    if (
        ctx.access_mode is AccessMode.WRITE
        and ctx.metadata.get("environment") != "PRODUCTION"
    ):
        return "write tools are available only in the production environment"
    return None
```

Populate `environment` from trusted application configuration, not from an
agent-controlled tool argument.

## Network-aware rule

Pass a server-verified network decision in metadata. Do not trust a raw
`X-Forwarded-For` value unless a trusted proxy has validated it, and do not use
this hook as a substitute for firewall or egress controls:

```python
from typing import Optional

from toolboundary import CallContext


def customer_export_network_guard(ctx: CallContext) -> Optional[str]:
    if (
        ctx.tool_name == "export_customer_data"
        and ctx.metadata.get("trusted_network") is not True
    ):
        return "customer exports require a trusted network"
    return None
```

## External policy decision

Keep the policy client outside ToolBoundary and inject a callable. Give any
network request a short timeout; a timeout denies the call, while other errors
are also denied by the default fail-closed behavior:

```python
from typing import Callable, Optional

from toolboundary import CallContext

PolicyDecision = Callable[[CallContext], Optional[str]]


def external_policy_hook(decide: PolicyDecision) -> PolicyDecision:
    def check(ctx: CallContext) -> Optional[str]:
        try:
            return decide(ctx)
        except TimeoutError:
            return "external policy decision timed out"

    return check
```

```python
# `permissions` and `policy_client` are configured by the application.
from toolboundary import Boundary

boundary = Boundary(
    agent_name="support-agent",
    permissions=permissions,
    policy_hooks=[
        refund_hours,
        production_write_guard,
        customer_export_network_guard,
        external_policy_hook(policy_client.decide),
    ],
)
```

Do not set `fail_closed_on_hook_error=False` for authorization checks: that
turns hook failures into allows.
