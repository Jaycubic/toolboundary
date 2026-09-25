# Contributing to ToolBoundary

Thanks for considering a contribution. ToolBoundary is intentionally small in
scope — please read the "Known Limitations" section of the README before
proposing a feature, to check it fits the project's design philosophy
(no required infrastructure, fail-closed by default, framework-agnostic
core with optional integrations, local authority with optional external providers).

## Development setup

```bash
git clone https://github.com/Jaycubic/toolboundary.git
cd toolboundary
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev,langchain]"
```

## Running tests

```bash
pytest                          # full suite with coverage report
pytest tests/test_boundary.py   # a single file
pytest tests/test_provider.py   # provider contract tests
pytest -k kill_switch           # tests matching a keyword
```

All new code should include tests. We aim to keep coverage above 90%.

The provider contract tests in `tests/test_provider.py` are particularly
important — they verify the core invariant that a local DENY can never be
turned into an ALLOW by an external provider. Any change to the authorization
flow must pass these tests.

## Linting

```bash
ruff check src tests
mypy src
```

## Project structure

```
src/toolboundary/
    __init__.py              # public API surface
    boundary.py              # core Boundary decision engine + provider orchestration
    provider.py              # EvidenceProvider protocol + provider-neutral data models
    evidence.py              # deterministic canonicalization, SHA-256 hashing, call binding
    permissions.py           # ToolPermission
    enums.py                 # AutonomyLevel, AccessMode, etc.
    exceptions.py            # BoundaryViolation, ApprovalRequired, ProviderAuthorizationDenied, etc.
    audit.py                 # AuditTrail and sinks (Logging, JSONL, Webhook)
    tokens.py                # AuthorizationToken, TokenIssuer (network enforcement)
    network.py               # NetworkEnforcer proxy (optional, stdlib-only)
    _rate_limiter.py         # internal sliding-window rate limiter
    decorators.py            # @guarded_tool (provider-aware)
    integrations/
        langchain.py         # LangChain BaseTool wrapping (provider-aware)
        agentkey.py          # (future) AgentKey provider adapter
```

## Architecture: the provider layer

ToolBoundary v1.0.0 introduced a provider-neutral authorization and evidence
layer. If you're contributing to this area, understand the key design rules:

1. **Local DENY is final.** No provider, adapter, or integration may turn a
   local DENY into an ALLOW. The provider is only consulted after a local ALLOW.

2. **Observe vs Enforce.** In `OBSERVE` mode, provider failures or denials are
   logged but don't block. In `ENFORCE` mode, provider denial or unavailability
   blocks execution before dispatch (fail closed).

3. **Exact-call binding.** The `FrozenToolCall` captures the exact arguments at
   authorization time. The same arguments must be used for execution. The
   `call_digest` is a SHA-256 of the canonical JSON representation.

4. **Single-use authorization.** A consumed `AuthorizationContext` cannot be
   reused. This prevents replay attacks at the ToolBoundary layer.

5. **Post-dispatch resilience.** If `provider.record()` fails after the tool
   has executed, the local execution record is preserved. Provider recording
   failures never erase local evidence.

6. **No vendor coupling in core.** Provider-specific code belongs under
   `integrations/`, never in `boundary.py`, `provider.py`, or `evidence.py`.

## Good first contributions

These are scoped, valuable, and don't require redesigning anything:

- **Custom `EvidenceProvider` implementations** — implement the protocol for
  popular authorization platforms. Place under `integrations/` with an optional
  extra in `pyproject.toml`.
- **Redis-backed rate limiter / token store** — for multi-process
  deployments. Implement the same interface as `SlidingWindowRateLimiter`
  and `InMemoryTokenStore` and submit as an optional extra
  (`toolboundary[redis]`).
- **CrewAI / AutoGen / LangGraph integrations** — mirror the structure of
  `integrations/langchain.py`: wrap the framework's actual tool-execution
  call site, not just provide a decorator the user has to remember to apply.
  These should use the same `authorize_call()` / `record_execution()`
  orchestration as the existing integrations.
- **A minimal local dashboard** — a single-file script that tails a
  `JSONLFileSink` log and renders a simple live view. Should have zero
  required dependencies beyond the standard library, in keeping with the
  project's "no infrastructure required" philosophy — a `flask`/`fastapi`-based
  version is welcome too, but should be a clearly optional extra, not folded
  into core.
- **More policy hook examples** — e.g. a time-of-day hook, a
  geo/IP-based hook, or an example calling out to an external policy
  engine.

## Pull request guidelines

1. Open an issue first for anything beyond a small bugfix, so we can agree
   on the approach before you invest time.
2. Keep the core package (`toolboundary/__init__.py` and everything it
   imports by default) dependency-free. New framework integrations belong
   under `integrations/` with their own optional extra in `pyproject.toml`.
3. Match the existing docstring style — every public class/function should
   explain *why*, not just *what*, especially around security-relevant
   decisions (fail-open vs fail-closed, what a check does and doesn't cover).
4. Add tests that would fail without your change.
5. Provider-related changes must pass all tests in `tests/test_provider.py`
   — these are the contract tests that enforce the core invariant.

## Reporting security issues

Please do not open a public GitHub issue for a security vulnerability.
See `SECURITY.md` for how to report privately.

## Code of conduct

Be respectful. Assume good faith. This is a small project maintained in
someone's spare time — patience with review turnaround is appreciated.
