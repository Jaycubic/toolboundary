# Policy Gateway

The policy gateway (`toolboundary.gateway`, new in v1.1.0) protects your tools from a
**compromised agent**. It moves policy out of the agent's process, so the agent can no longer
approve its own requests.

`Boundary.check()`, `@guarded_tool` and the framework adapters run inside the agent's process.
They stop mistakes and misbehaving model output, but code running in that process can get
around them. Use the gateway if you need to defend against that code.

| | In-process checks | Token proxy | Policy gateway |
|---|---|---|---|
| Stops a denied call made through the library | Yes | Yes | Yes |
| Agent can't create its own approval | No | Only if the agent never has the secret | Yes |
| Value limits are read from the real request | No | No | Yes |
| Agent never holds tool credentials | No | No | Yes, if you configure it |

## How it works

1. The agent sends each tool request to the gateway with its own agent key.
2. The gateway identifies the agent from that key. The agent can't choose its identity.
3. The request must match a `GatewayRule` you wrote. Anything else is denied.
4. The gateway reads the operation, access mode, value and record count from the rule and the
   request, then runs the agent's `Boundary`.
5. If allowed, the gateway adds the tool's credentials and forwards the exact bytes it checked.

Every denial is written to the agent's audit trail.

## Example

Run this in the gateway's process, never the agent's:

```python
# policy_app.py
import os

from toolboundary import AccessMode, AutonomyLevel, Boundary, ToolPermission
from toolboundary.gateway import (
    GatewayAgent, GatewayRoute, GatewayRule, PolicyGateway, constant, json_field,
)


def build() -> PolicyGateway:
    boundary = Boundary(
        "billing-agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        strict_limits=True,  # required by the gateway
        kill_switch_file="/var/run/toolboundary/billing-agent.stop",
        permissions=[ToolPermission("billing", access_mode=AccessMode.WRITE, max_value=100)],
    )
    route = GatewayRoute(
        "billing",
        "https://billing.internal.example.com",
        rules=(
            GatewayRule(
                "POST", "payments", AccessMode.WRITE, operation="pay",
                value=json_field("payment.amount"),
            ),
            GatewayRule("GET", "invoices/{id}", AccessMode.READ_ONLY, value=constant(0)),
        ),
        credential_headers={"Authorization": f"Bearer {os.environ['BILLING_TOKEN']}"},
    )
    return PolicyGateway([GatewayAgent(boundary, os.environ["BILLING_AGENT_KEY"])], [route])
```

```bash
python -m toolboundary.gateway --app policy_app:build --host 127.0.0.1 --port 8780
```

The agent only needs its key:

```python
from toolboundary.gateway import GatewayClient

client = GatewayClient("http://127.0.0.1:8780", agent_key)
response = client.request("billing", "POST", "payments", json_body={"payment": {"amount": 25}})

if response.denied_reason:
    print("Blocked by policy:", response.denied_reason)
```

Create agent keys with `generate_agent_key()`. The gateway stores only a hash of each key.

## Writing rules

A `GatewayRule` describes one allowed request.

- `path` is written without a leading slash. `{name}` matches one path segment, and everything
  else is literal.
- Query parameters are denied unless listed in `allowed_query`, and a repeated parameter is
  always denied.
- `value` and `record_count` are extractors. Use `json_field`, `json_array_length`,
  `query_param`, `constant`, or your own function that takes a `GatewayRequest`.

If an extractor can't read a value, the request is denied. Because `strict_limits=True` is
required, a rule without a `value` is denied when its tool has a value limit, and likewise for
`record_count`.

Only JSON sent as UTF-8 `application/json` can be read by the JSON extractors. Duplicate keys,
`NaN` and `Infinity` are refused, because a tool's parser might read them differently.

**Point extractors at the field your tool really acts on.** The gateway can't tell whether a
tool ignores `payment.amount` and reads another field. Only list endpoints whose behaviour you
understand.

## Deployment requirements

The gateway only protects you if all of these are true. The library can't enforce them.

1. **Separate identity.** Run the gateway as a different OS user or in a different container.
   A process under the same user can often read the gateway's memory or files.
2. **No direct route to tools.** Block the agent's network access to your tools, with an
   egress firewall or network policy, so the gateway is its only route.
3. **No tool credentials in the agent.** Keep them only in `credential_headers`, and remove them
   from the agent's environment, files and prompts.
4. **Encrypted transport.** Off a single host, give the gateway an `ssl_context`. It refuses to
   bind to a non-loopback address without one, unless you set `allow_insecure_bind=True`.
5. **One key per agent.** Treat a stolen agent key as that agent's identity, and replace it if
   it leaks. It can't grant more than that agent's policy allows.

For multiple gateway replicas, give each `Boundary` a shared `rate_limiter`, such as
`RedisSlidingWindowRateLimiter`.

## What the gateway does not do

- **It can't stop misuse of allowed actions.** A prompt-injected agent can still do anything its
  rules permit. Keep rules narrow, set low limits, and use `requires_approval` for risky actions.
- **It doesn't inspect responses.** Tools can still return sensitive data to the agent.
- **It only covers HTTP tools.** Local code, shells and databases need their own isolation.
- **Your policy can still be wrong.** An over-broad rule is allowed exactly as written.
- **Approvals are denials for now.** A `requires_approval` call returns `APPROVAL_REQUIRED`,
  and the gateway has no built-in way to resume it after a person approves.

## Denial reasons

The agent sees a short reason in `response.denied_reason`.

| Status | Reasons |
|---|---|
| 400 | `BAD_PATH`, `INVALID_QUERY`, `INVALID_CONTENT_LENGTH`, `INCOMPLETE_BODY`, `UNSUPPORTED_TRANSFER_ENCODING` |
| 401 | `UNAUTHENTICATED` |
| 403 | `REQUEST_NOT_ALLOWED`, `UNKNOWN_ROUTE`, `QUERY_NOT_ALLOWED`, `REQUEST_VALUE_UNREADABLE`, `POLICY_ERROR`, or a `ViolationReason` from the `Boundary` |
| 413 | `BODY_TOO_LARGE` |
| 429 | `RATE_LIMIT_EXCEEDED` |
| 502 | `UPSTREAM_UNREACHABLE`, `UPSTREAM_RESPONSE_TOO_LARGE`, `UPSTREAM_CREDENTIALS_UNAVAILABLE` |
| 503 | `PROVIDER_UNAVAILABLE` |
