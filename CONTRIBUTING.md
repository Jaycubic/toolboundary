# Contributing to ToolBoundary

The latest published release is [v1.1.1](https://github.com/Jaycubic/toolboundary/releases/tag/v1.1.1). The current codebase includes the core policy engine, provider/evidence layer, network enforcement, the policy gateway, optional Redis backends, and optional LangChain and CrewAI adapters. Please check the existing implementation and tests before proposing overlapping functionality.

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
pip install -e ".[dev,langchain,crewai,redis]"
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

## Linting, formatting and types

```bash
ruff check src tests benchmarks
ruff format src tests benchmarks
mypy src
```

CI runs all three and fails if `ruff format --check` would change anything.

## Benchmarks

```bash
pytest benchmarks --benchmark-only --no-cov
```

`benchmarks/test_performance.py` measures each decision path. On every pull
request the Performance workflow runs it against the base branch and against
your change on the same machine, and fails if any benchmark's median gets more
than 25% slower. If a slowdown is intended, say why in the pull request.

## Continuous integration

Every push and pull request to `main` runs these workflows:

| Workflow | What it checks |
|---|---|
| CI | ruff lint and format, mypy, tests on Python 3.9–3.13 on Linux and on Windows and macOS, and a build of the package that is installed and smoke-tested |
| Security | CodeQL, `pip-audit` on the runtime extras, ruff's bandit rules, and dependency review on pull requests |
| Performance | benchmarks against the base branch |
| OpenSSF Scorecard | repository security practices (also weekly) |

Dependabot opens weekly pull requests for Python dependencies and GitHub
Actions. Actions are pinned to full commit SHAs; keep new ones pinned too.

If `pip-audit` reports an advisory that can't be fixed in this repository, for
example one in a dependency of an optional extra with no fixed release, add it to
the ignore list in `.github/workflows/security.yml` with a comment naming the
package and why. Remove it once a fix ships.

## Releasing

1. Update `__version__` in `src/toolboundary/__init__.py`, `CHANGELOG.md`, the
   README's "What's new" section and the supported version in `SECURITY.md`.
2. Merge to `main` and wait for every workflow to pass.
3. Tag the commit `vX.Y.Z` and publish a GitHub release from the tag.

Publishing the release runs `publish.yml`, which refuses to continue if the tag
doesn't match `__version__`, then uploads to PyPI with trusted publishing and
signed build attestations.

## Project structure

```
src/toolboundary/
    __init__.py              # public API surface
    boundary.py              # core Boundary decision engine + provider orchestration
    provider.py              # EvidenceProvider protocol + provider-neutral data models
    evidence.py              # deterministic JSON binding, SHA-256 hashing, call binding (JCS roadmap tracked separately)
    permissions.py           # ToolPermission
    enums.py                 # AutonomyLevel, AccessMode, etc.
    exceptions.py            # BoundaryViolation, ApprovalRequired, ProviderAuthorizationDenied, etc.
    audit.py                 # AuditTrail and sinks (Logging, JSONL, Webhook)
    tokens.py                # AuthorizationToken, TokenIssuer (network enforcement)
    network.py               # NetworkEnforcer proxy (optional, stdlib-only)
    gateway.py               # PolicyGateway, out-of-process enforcement (optional, stdlib-only)
    _rate_limiter.py         # internal sliding-window rate limiter
    redis_backend.py         # optional Redis rate limiter / token store
    decorators.py            # @guarded_tool (provider-aware)
    integrations/
        langchain.py         # LangChain BaseTool wrapping (provider-aware)
        crewai.py            # CrewAI BaseTool wrapping (provider-aware)
        agentkey.py          # AgentKey provider adapter (optional integration)
tests/                       # unit, integration and attack-focused tests
benchmarks/                  # pytest-benchmark performance suite
examples/                    # runnable usage examples
docs/                        # API reference and gateway guide
```

## Architecture: the provider layer

ToolBoundary v1.0.x introduced a provider-neutral authorization and evidence
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

7. **Optional Redis backends.** `redis_backend.py` provides the merged v1.0.2 shared
   rate-limiter and token-store implementations for multi-process deployments. Redis
   remains an optional dependency and must not become part of the core package.

## Good first contributions

These are scoped, valuable, and don't require redesigning anything:

- **Custom `EvidenceProvider` implementations** — implement the protocol for
  authorization/evidence platforms not already covered by the repository. Place
  provider-specific code under `integrations/` with an optional extra in
  `pyproject.toml`.
- **Additional framework integrations** — mirror the structure of
  `integrations/langchain.py`, `integrations/crewai.py`, and
  `integrations/agentkey.py`: wrap the framework's actual tool-execution call site
  and use the same `authorize_call()` / `record_execution()` orchestration as the
  existing integrations. AutoGen is tracked in issue #15.
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
