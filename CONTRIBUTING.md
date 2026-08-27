# Contributing to ToolBoundary

Thanks for considering a contribution. ToolBoundary is intentionally small in
scope — please read the "Known Limitations" section of the README before
proposing a feature, to check it fits the project's design philosophy
(no required infrastructure, fail-closed by default, framework-agnostic
core with optional integrations).

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
pytest -k kill_switch           # tests matching a keyword
```

All new code should include tests. We aim to keep coverage above 90%.

## Linting

```bash
ruff check src tests
mypy src
```

## Project structure

```
src/toolboundary/
    __init__.py          # public API surface
    boundary.py           # core Boundary decision engine
    permissions.py        # ToolPermission
    enums.py               # AutonomyLevel, AccessMode, etc.
    exceptions.py          # BoundaryViolation, ApprovalRequired, etc.
    audit.py                # AuditTrail and sinks (Logging, JSONL, Webhook)
    tokens.py               # AuthorizationToken, TokenIssuer (network enforcement)
    network.py              # NetworkEnforcer proxy (optional, stdlib-only)
    _rate_limiter.py        # internal sliding-window rate limiter
    decorators.py            # @guarded_tool
    integrations/
        langchain.py          # LangChain BaseTool wrapping
```

## Good first contributions

These are scoped, valuable, and don't require redesigning anything:

- **Redis-backed rate limiter / token store** — for multi-process
  deployments. Implement the same interface as `SlidingWindowRateLimiter`
  and `InMemoryTokenStore` and submit as an optional extra
  (`toolboundary[redis]`).
- **CrewAI / AutoGen / LangGraph integrations** — mirror the structure of
  `integrations/langchain.py`: wrap the framework's actual tool-execution
  call site, not just provide a decorator the user has to remember to apply.
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

## Reporting security issues

Please do not open a public GitHub issue for a security vulnerability.
See `SECURITY.md` for how to report privately.

## Code of conduct

Be respectful. Assume good faith. This is a small project maintained in
someone's spare time — patience with review turnaround is appreciated.
