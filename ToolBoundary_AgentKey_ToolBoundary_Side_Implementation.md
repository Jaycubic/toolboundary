> **Status:** Implemented on `main` for the v1.0.2 release. This document is retained as the implementation handoff/reference for the ToolBoundary side of the AgentKey integration.
>
# ToolBoundary × AgentKey — ToolBoundary-Side Implementation

## Objective

Implement the ToolBoundary-side of the first concrete AgentKey integration.

Ownership:

- **Ben / AgentKey:** implement the reference `AgentKeyProvider` against ToolBoundary's existing `EvidenceProvider` protocol.
- **Jofrey / ToolBoundary:** implement the runnable example, end-to-end integration tests, and documentation wiring.

The first integration should require **no ToolBoundary core contract change**. This is explicitly stated in Ben's handoff.

## Current ToolBoundary API to use

The current `main` already contains:

- `FrozenToolCall`
- `LocalDecision`
- `ProviderGrant`
- `ExecutionRecord`
- `ProviderReceipt`
- `AuthorizationContext`
- `ProviderMode`
- `EvidenceProvider`

in `src/toolboundary/provider.py`.

The provider contract is:

```python
class EvidenceProvider(Protocol):
    def authorize(
        self,
        call: FrozenToolCall,
        local: LocalDecision,
    ) -> ProviderGrant:
        ...

    def record(
        self,
        grant: ProviderGrant,
        execution: ExecutionRecord,
    ) -> ProviderReceipt:
        ...
```

Do **not** redesign this contract for the first integration.

## Existing execution flow

`src/toolboundary/boundary.py` already provides:

```text
local check()
    ↓
LocalDecision
    ↓
FrozenToolCall
    ↓
SHA-256 call_digest
    ↓
provider.authorize()
    ↓
AuthorizationContext
    ↓
tool execution
    ↓
record_execution()
    ↓
provider.record()
```

`src/toolboundary/decorators.py` already routes provider-enabled calls through `authorize_call()` and `record_execution()`.

`src/toolboundary/integrations/langchain.py` already uses the same provider-aware lifecycle for `_run()` and `_arun()`.

Therefore the AgentKey example should use these APIs instead of creating a separate execution path.

## Important: Ben owns AgentKeyProvider

Do not implement a second AgentKey provider.

Ben's handoff says he will take the reference `AgentKeyProvider`. The ToolBoundary-side work should consume that provider through the existing `EvidenceProvider` protocol.

Expected provider location is likely under:

```text
src/toolboundary/integrations/
```

but use the actual path from Ben's implementation rather than inventing or duplicating one.

## 1. Create `examples/agentkey_integration.py`

Create a minimal runnable example showing:

```text
AI Agent
   ↓
ToolBoundary
   ↓
Local ALLOW
   ↓
AgentKeyProvider
   ↓
AgentKey authorization
   ↓
Tool execution
   ↓
execution evidence
```

Use a harmless demo tool.

Example structure:

```python
from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    ProviderMode,
    ToolPermission,
    guarded_tool,
)

# Import path must match Ben's actual provider implementation.
from toolboundary.integrations.agentkey import AgentKeyProvider

provider = AgentKeyProvider(
    # actual configuration from Ben's provider
)

boundary = Boundary(
    agent_name="agentkey-demo",
    autonomy=AutonomyLevel.AUTONOMOUS,
    permissions=[
        ToolPermission(
            "read_ticket",
            access_mode=AccessMode.READ_ONLY,
        ),
    ],
    provider=provider,
    provider_mode=ProviderMode.ENFORCE,
    policy_version="demo-v1",
)

@guarded_tool(
    boundary,
    tool_name="read_ticket",
    access_mode=AccessMode.READ_ONLY,
)
def read_ticket(ticket_id: str) -> str:
    return f"ticket={ticket_id}"

print(read_ticket("INC-1001"))
```

Do not invent the AgentKey SDK name/version. Use whatever Ben's actual provider implementation requires.

Never commit API keys or credentials.

## 2. Create `tests/test_agentkey_integration.py`

The new tests must verify the **AgentKey-specific mapping and lifecycle**.

Do not simply duplicate `tests/test_provider.py`. That file already tests generic provider behavior.

Use a deterministic fake/mock AgentKey client so CI does not require a live AgentKey service.

### Test A — Allowed call

Required:

```text
Local ALLOW
→ AgentKey ALLOW
→ exactly one dispatch
→ record_execution()
→ AgentKey record()
```

Assert:

- tool executed exactly once;
- `authorize()` called once;
- `record()` called once;
- `ProviderGrant.allowed is True`;
- `ProviderReceipt.recorded is True`;
- authorization event ID, attempt ID, session ID, and ToolBoundary `call_digest` remain correlated.

### Test B — Provider denial

Required:

```text
Local ALLOW
→ AgentKey DENY
→ ProviderMode.ENFORCE
→ ProviderAuthorizationDenied
→ tool never executes
```

Assert:

```python
with pytest.raises(ProviderAuthorizationDenied):
    ...
```

and:

```python
assert tool_call_count == 0
```

Also assert `record()` was not called.

### Test C — Consumed-grant replay

Required:

```text
authorize
→ first execution
→ record_execution()
→ authorization consumed
→ second use
→ AuthorizationConsumed
```

Assert:

```python
assert context.consumed is True

with pytest.raises(AuthorizationConsumed):
    boundary.record_execution(...)
```

Preserve `attempt_id` so provider-side duplicate presentation can also be classified as replay.

### Test D — Post-dispatch reporting

Test both success and error outcomes.

Success:

```text
ExecutionRecord.status == "success"
result_digest exists
```

Error:

```text
ExecutionRecord.status == "error"
error_type exists
error_message exists
```

Then test provider recording failure:

```text
tool executes
→ local execution audit remains
→ ProviderReceipt.recorded == False
```

The provider failure must never erase the ToolBoundary local execution record.

## 3. Required additional assertions

### Local deny never calls AgentKey

Use a spy/mock provider.

Required:

```python
local deny
→ provider.authorize() is never called
```

This is a core security invariant.

### Exact arguments stay bound

Capture the `FrozenToolCall` passed to `authorize()`.

Then verify that the arguments used for post-dispatch evidence are the same exact resolved values.

Expected:

```python
authorized_call.arguments == recorded_arguments
```

### Correlation

Preserve:

```text
ToolBoundary call_digest
ToolBoundary decision_id
AgentKey authorization event_id
AgentKey attempt_id
AgentKey session_id
```

across the complete path.

## 4. AgentKey mapping to verify

The handoff specifies:

| ToolBoundary | AgentKey |
|---|---|
| `call.tool_name` | `tool` |
| `call.operation` | `action` |
| `call.resource` | `resource` |
| `call.arguments` | `arguments` |
| `call.call_digest` | `metadata.toolboundary_call_digest` |
| `local.decision_id` | `metadata.toolboundary_decision_id` |
| `local.policy_version` | `metadata.toolboundary_policy_version` |
| `schema_hash` / `manifest_hash` | metadata |
| AgentKey `event_id` | `ProviderGrant.authorization_id` |
| AgentKey `attempt_id` | `ProviderGrant.attempt_id` |
| AgentKey `allowed` | `ProviderGrant.allowed` |
| AgentKey `reason` | `ProviderGrant.reason` |
| session / request / execution contract | `ProviderGrant.metadata` |

**Do not map AgentKey `request_id` to `ProviderGrant.authorization_id`.**

The correct authorization identifier is the AgentKey authorization **event_id**, because that is what links the post-dispatch evidence back to the authorization.

## 5. Session handling

AgentKey must use the same session for:

```text
authorize()
+
record()
```

The session ID should be retained in provider-owned state and also exposed in:

```python
ProviderGrant.metadata["session_id"]
```

Tests should verify that the same session is used for both calls.

## 6. `record()` interface wrinkle

Ben's handoff identifies this explicitly:

Current ToolBoundary:

```python
record(grant, execution)
```

AgentKey needs:

```text
tool
action
resource
arguments
authorization linkage
```

`ExecutionRecord` does not contain the original call fields.

For the first reference implementation, Ben's provider should therefore keep short-lived state:

```text
authorize()
    ↓
store FrozenToolCall + session_id
    ↓
record()
    ↓
reconstruct exact AgentKey payload
    ↓
consume/delete pending state
```

No ToolBoundary core change is required for this first example.

Tests should verify that:

```text
authorize(arguments=A)
→ record()
→ AgentKey receives arguments=A
```

## 7. Approval-required behavior

AgentKey may return:

```text
allowed=false
approval_required=true
approval_id=...
```

For this first integration:

- preserve `approval_required` in provider metadata;
- preserve `approval_id`;
- treat it as a non-allow result under the current provider contract;
- do **not** implement approval-resume orchestration yet.

That is explicitly deferred in the handoff.

## 8. ProviderReceipt semantics

Expected mapping:

```text
AgentKey evidence_recorded
        ↓
ProviderReceipt.recorded

AgentKey execution event_id
        ↓
ProviderReceipt.evidence_id
```

Do not invent a per-record signature.

The handoff explicitly says:

```text
ProviderReceipt.signature = None
```

for the immediate record operation because AgentKey verification/signing is session-level after close/export.

Tests must not require a non-null per-record signature.

## 9. Observe / Enforce

Keep the current ToolBoundary semantics:

### OBSERVE

```text
Local ALLOW + provider DENY
→ execution continues

Local ALLOW + provider unavailable
→ execution continues
→ evidence degraded
```

### ENFORCE

```text
Local ALLOW + provider ALLOW
→ execution

Local ALLOW + provider DENY
→ blocked before dispatch

Local ALLOW + provider unavailable
→ blocked before dispatch
```

Do not modify these semantics for this example.

## 10. Documentation wiring

### `README.md`

Add a short concrete AgentKey section under:

```text
External authorization & evidence providers
```

It should show:

```python
provider = AgentKeyProvider(...)

boundary = Boundary(
    ...,
    provider=provider,
    provider_mode=ProviderMode.ENFORCE,
)
```

and link to:

```text
examples/agentkey_integration.py
```

State clearly:

- AgentKey is optional;
- ToolBoundary remains the local enforcement authority;
- local deny is final;
- provider integration adds external authorization/evidence;
- the core package does not require AgentKey.

### `docs/API.md`

The current API documentation does not fully expose the provider additions.

Update it to document:

```text
provider
provider_mode
policy_version
authorize_call()
record_execution()
EvidenceProvider
FrozenToolCall
LocalDecision
ProviderGrant
ExecutionRecord
ProviderReceipt
AuthorizationContext
ProviderMode
```

Only document APIs that actually exist in the current code.

### `CHANGELOG.md`

Only add an `Unreleased` entry if the project is using an unreleased section.

Do not call the AgentKey integration released until both sides and the tests are merged.

## 11. `pyproject.toml`

Do not add an AgentKey dependency to the core package.

If Ben's provider uses an actual Python SDK, add a separate optional extra only after the real package name and supported version are confirmed:

```toml
[project.optional-dependencies]
agentkey = [
    "<actual-package>"
]
```

Never invent the package name.

Core:

```bash
pip install toolboundary
```

must continue to work without AgentKey.

## 12. Do NOT include in this first PR

Do not implement:

- brokered target execution;
- destination credential isolation;
- approval resume orchestration;
- session export UX;
- centralized evidence dashboard;
- new cryptographic ledger design;
- AgentKey-specific logic inside `Boundary`;
- AgentKey-specific logic inside the LangChain integration;
- a mandatory AgentKey network dependency.

Ben's handoff explicitly limits the first reference example to:

```text
one AgentKeyProvider
one runnable example
four end-to-end tests
short README configuration
```

## 13. Suggested branch

```text
feature/agentkey-reference-example
```

Suggested commits:

```text
test: add AgentKey provider integration acceptance tests
docs: add AgentKey runnable example
docs: document AgentKey provider example
```

Keep the PR focused.

## 14. Definition of Done

Before opening the PR, all must be true:

```text
[ ] Runnable AgentKey example exists
[ ] No credentials committed
[ ] Core ToolBoundary remains dependency-free
[ ] Allowed-call case passes
[ ] Provider-denial case passes
[ ] Consumed-grant replay case passes
[ ] Post-dispatch reporting case passes
[ ] Local deny never calls provider
[ ] Exact arguments remain correlated
[ ] call_digest remains correlated
[ ] authorization event_id remains correlated
[ ] attempt_id remains correlated
[ ] session_id remains correlated
[ ] Observe mode remains non-blocking
[ ] Enforce mode requires provider allow
[ ] Provider denial occurs before dispatch
[ ] Provider record failure preserves local evidence
[ ] README example works against Ben's provider
[ ] API documentation reflects current provider APIs
[ ] Existing tests continue to pass
[ ] ruff check passes
```

## 15. Final Architecture

```text
                         AI AGENT
                            |
                            v
                     ToolBoundary
                            |
                   local policy check
                            |
                       LOCAL ALLOW
                            |
                    FrozenToolCall
                            |
                       call_digest
                            |
                    EvidenceProvider
                            |
                     AgentKeyProvider
                            |
                         AgentKey
                            |
                     external ALLOW
                            |
                            v
                      TOOL EXECUTES
                            |
                            v
                   ExecutionRecord
                            |
                            v
                   AgentKeyProvider
                            |
                            v
                     AgentKey evidence
```

The security invariant remains:

```text
ToolBoundary DENY
       ↓
     STOP

AgentKey ALLOW
       ↓
cannot override local DENY
```

## Source basis

This implementation plan is based on the attached:

**AgentKey × ToolBoundary — Reference AgentKeyProvider Handoff**, dated 27 Sep 2026.

The handoff explicitly defines the ownership split, field mapping, session handling, `record()` state workaround, ProviderReceipt semantics, four end-to-end acceptance cases, and the intentionally small first-PR scope. fileciteturn193file0L5-L25 fileciteturn193file0L28-L62 fileciteturn193file0L65-L94 fileciteturn193file0L97-L119
