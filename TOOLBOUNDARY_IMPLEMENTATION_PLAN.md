# ToolBoundary — Code-Level Review & Phased Implementation Plan

**Repo reviewed:** `Jaycubic/toolboundary` @ `81bfb7e` ("Remove the MD Implementation"), package version 1.0.2
**Scope of review:** every file under `src/toolboundary/`, all of `tests/test_boundary.py` and `tests/test_decorators.py`, `pyproject.toml`, CI workflows, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/API.md`.
**Goal:** add capability without touching the philosophy (local, in-process, zero-dependency core, fail-closed, loud, policy-as-code).

---

## 0. How this was verified (and what wasn't)

- Installed the package in a clean venv and ran the existing suite: **122 passed** (Python 3.13). I did **not** measure coverage (the README claims 90%) and did **not** run on Python 3.9.
- Wrote two probe scripts that call the real code and print what happens. Every finding marked **[reproduced]** below was observed, not inferred. Findings marked **[by reading]** come from reading the code only; add a test that pins the behaviour before fixing.
- The MCP adapter in Phase 5 is designed from memory of the MCP Python SDK. **Confirm the `ClientSession.call_tool` / `list_tools` signatures against the SDK version you pin** before coding it.

---

## 1. Philosophy guard-rails (every phase must pass these)

| Rule (from README / CONTRIBUTING) | What it means for new code |
|---|---|
| Core has **zero dependencies** | New core modules are stdlib-only. Anything needing a package goes under `integrations/` or an optional extra. |
| **Fail closed** | Missing/invalid input → deny, never skip. New features default to the safe behaviour; looser behaviour is an explicit flag. |
| **Loud by default** | New denials raise `BoundaryViolation` subclasses with a stable `ViolationReason` code. |
| **Policy is plain Python** | No YAML/JSON policy as the primary interface. Rules are objects constructed in code. |
| **Local DENY is final** | Nothing (provider, approval, shadow mode, session rule) may turn a DENY into an ALLOW. Approvals only convert `APPROVAL_REQUIRED → ALLOW`, and only as the *last* step. |
| Python **3.9+** | Keep `from __future__ import annotations`. No `match`, no `X \| Y` inside runtime `isinstance`, no `@dataclass(slots=True)`, no `zip(strict=)`. |
| Stable reason codes | Only **add** members to `ViolationReason`; never rename (docstring promises stability for log parsing). |

---

## 2. Findings from the code review

### 2.1 Security / correctness defects (fix first — Phase 0)

| # | Severity | Finding | Where | Evidence |
|---|---|---|---|---|
| F1 | **High** | **`NetworkEnforcer` can be steered to any host.** `urljoin(base, rest)` treats `//host/path` as a network-path reference, so a caller holding a valid token for tool `crm_api` can make the proxy fetch an arbitrary URL. `../` also climbs out of a path-prefixed upstream. This defeats the "only pre-approved destinations are reachable" guarantee stated in the comment at `network.py:229-233` and in `API.md`. | `network.py:218` | **[reproduced]** `GET /crm_api///127.0.0.1:18991/steal` with a valid token → proxy returned the *other* server's body (`evil host received: ['/steal']`). |
| F2 | **High** | **`allowed_operations` allow-list is bypassed when `operation=None`.** `operation_allowed()` returns `True` for `None` before looking at the allow-list. An agent that omits `operation` skips the allow-list entirely. | `permissions.py:64-66` | **[reproduced]** allow-list `{"read"}`: `operation="delete"` → denied; `operation=None` → **ALLOWED**. |
| F3 | **High** | **Value/record ceilings accept bad input silently or crash.** `value=None`, `NaN`, and negative values all pass `max_value`. A numeric **string** (typical LLM tool argument, e.g. `"999999"`) raises a raw `TypeError` from the comparison: unaudited, not a `BoundaryViolation`. | `boundary.py:794-822` | **[reproduced]** `None`/`NaN`/`-5000` → ALLOWED; `'5000'` → `TypeError`. Decorator with `amount="999999"` → `TypeError`; `amount` omitted → ALLOWED. |
| F4 | **High** | **Secrets are written to the audit log.** `_safe_repr(kwargs)` puts every argument's `repr` (200 chars) into audit metadata, which goes to logging / JSONL / webhook sinks. Also uses `kwargs` not the bound arguments, so positional args are logged inconsistently. | `decorators.py:115,150,162-171` | **[reproduced]** `password='hunter2-REAL'`, `api_key='sk-live-ABCDEF123456'` appear verbatim in `event.metadata["args"]`. |
| F5 | Medium | **LangChain adapter crashes on `Tool(func=...)` with current langchain-core.** `_GuardedTool._run(*args, **kwargs)` hides `config`/`run_manager` from LangChain's signature inspection, so the inner `Tool._run` is called without its required `config`. Fails closed (crash, not bypass) but it's the most common tool type. Tests only use `BaseTool` subclasses. Also: single-string tool input arrives as a positional arg, so `kwargs` is empty and `value_arg` / provider `arguments` can't resolve. | `integrations/langchain.py:122-145` | **[reproduced]** langchain-core 1.6.12: `Tool(func=...)` → `TypeError: Tool._run() missing ... 'config'`; `StructuredTool` works. |
| F6 | Medium | **`@guarded_tool` mishandles `async def` tools with a provider.** The sync wrapper calls `record_execution` right after getting the coroutine object, so the provider is told `success` before the tool runs, and later exceptions are never recorded. | `decorators.py:122-140` | **[reproduced]** recorded status `success` before awaiting; coroutine then raised; still only one record, `success`. |
| F7 | Medium | **Decorator's `operation` is silently overridden to `None`.** `call_kwargs.get("operation", operation)` after `apply_defaults()` returns the function's own `operation=None` default instead of the configured one. | `decorators.py:95` | **[reproduced]** configured `operation="delete"` + allow-list `{"read"}` → ALLOWED. |
| F8 | Medium | **Approval is a dead end.** `ApprovalRequired.approval_id` is always `None`; `authorize_call(approval_id=, approval_state=)` accepts values but nothing ever consults them. After a human says yes, the library has no way to let the call through. | `boundary.py:871-887`, `exceptions.py:63-84` | **[reproduced]** `approval_id = None`; `_check_requires_approval` never reads approval state. |
| F9 | Medium | **Rate-limit budget is consumed by calls that never run.** `_check_rate_limit` records *before* hooks and approval, so hook-denied and approval-pending calls burn the budget and the later error reason becomes `RATE_LIMIT_EXCEEDED`, masking the real cause. A looping LLM can exhaust the budget with calls that were all denied. | `boundary.py:824-846` (order at 337-339) | **[reproduced]** 3 approval-pending calls → 4th denied by rate limit; 2 hook-denied calls → 3rd reports `RATE_LIMIT_EXCEEDED`. |
| F10 | Low | **Tool returning `None` is recorded as `status="unknown"`.** `build_execution_record` can't distinguish "returned None" from "result not supplied". | `evidence.py:145-159` | **[reproduced]** `result=None, error=None` → `unknown`. |
| F11 | Low | **Network tokens aren't bound to the request.** A token carries only agent/tool/operation/times. A token obtained for a read can be used for `DELETE` on any path of the same tool route. | `tokens.py:55-73` | Token fields: `token_id, agent_name, tool_name, operation, issued_at, expires_at`. |
| F12 | Low | **Three `ALLOW` audit events per provider-authorized call** (`check()`, `authorize_call` step 8, `record_execution`), all with `decision="ALLOW"`. Inflates ALLOW counts and makes replay ambiguous. | `boundary.py:367, 583, 666` | **[by reading]** |
| F13 | Low | **The 13-step check sequence is copy-pasted** in `evaluate()` and `check()`. Every phase below adds a check, so this *will* drift. | `boundary.py:242-255` vs `326-339` | **[by reading]** |
| F14 | Low | `evaluate()` is documented as side-effect-free ("never raises") but increments rate counters; `authorize_call` docstring says it uses `evaluate()` but calls `check()`. | `boundary.py:253, 480` | **[by reading]** |
| F15 | Low | `NetworkEnforcer` reads `Content-Length` bytes with no cap, ignores chunked bodies, and an invalid `Content-Length` raises inside the handler thread. | `network.py:219-220` | **[by reading]** |
| F16 | Low | `JSONLFileSink` is documented "thread-safe" but has no lock and writes the line in two `write()` calls. | `audit.py:78-88` | **[by reading]** |
| F17 | Info | `ViolationReason.DATA_CLASSIFICATION_DENIED` and `UNKNOWN_TOOL` are defined but never raised anywhere. | `enums.py:55,57` | **[reproduced]** 0 uses outside `enums.py`. |

### 2.2 Housekeeping inconsistencies

- `__version__ = "1.0.0"` (`__init__.py:67`) vs `version = "1.0.2"` (`pyproject.toml:7`) vs README badge `v1.0.2`.
- README badges `tests-122 passed` and `coverage-90%` are hard-coded and will rot.
- `CONTRIBUTING.md` says to run `mypy src`; **CI does not run mypy** (0 matches in `ci.yml`).
- `pyproject.toml` declares `langchain-core>=0.1.0` but CI only tests whatever resolves today.
- `network.py` docstring references `boundary.check(..., issue_network_token=True)`; the real API is `check_and_authorize()`.
- No `CHANGELOG.md` at HEAD (the first GitHub page I fetched listed `CHANGELOG.md`, `CITATION.cff`, `docs/ARCHITECTURE.md`; none exist at `81bfb7e`). If the removal was deliberate, ignore this.
- `Development Status :: 5 - Production/Stable` while F1-F4 exist; consider `4 - Beta` until Phase 0 ships.

---

## 3. Phase map

| Phase | Release | Theme | Breaking? |
|---|---|---|---|
| **0A** | **1.0.3** | Security & correctness fixes (F1-F4, F7, F10) | Behaviour-tightening only (documented) |
| **0B** | 1.0.4 / 1.1.0-dev | Refactor with **no behaviour change** (F13, F5, F6 plumbing) | No |
| **1** | **1.1.0** | **Input-aware permissions** (`arg_rules`) + request-bound network tokens | No (opt-in) |
| **2** | 1.1.0 | **Shadow mode, `explain()`, audit enrichment, replay CLI** | No (opt-in) |
| **3** | **1.2.0** | **Approval flow that actually completes** | No (opt-in) |
| **4** | **1.3.0** | **Session-aware rules** (lethal-trifecta guard) | No (opt-in) |
| **5** | 1.4.0 | MCP adapter, tool-definition pinning, OWASP mapping, other adapters | No |

Ship 0A as soon as possible and open a **private GitHub security advisory** for F1 (and F2/F3 if you consider them in scope; `SECURITY.md` says "any scenario where a denied action could be allowed" is in scope).

---

## Phase 0A — Security & correctness patch (1.0.3)

Each item = file, exact change, tests to add. Keep this release small and backportable.

### 0A.1 Fix F1 — proxy target resolution (`network.py`)

Replace the `urljoin` line (`network.py:218`) with a function that never lets the client influence scheme/host:

```python
from urllib.parse import urlsplit, unquote
import posixpath

def _resolve_target(base: str, rest: str) -> str | None:
    """Join client path onto the operator-configured base. Return None to reject."""
    b = urlsplit(base)
    path, sep, query = rest.partition("?")
    decoded = unquote(path)
    # Reject traversal and anything that could be read as a URL reference.
    if "\\" in decoded or "\x00" in decoded:
        return None
    if any(seg == ".." for seg in decoded.split("/")):
        return None
    clean = posixpath.join(b.path or "/", path.lstrip("/"))   # '//evil' -> 'evil' under base
    target = f"{b.scheme}://{b.netloc}{clean}" + (f"?{query}" if sep else "")
    # Belt and braces: the authority must be exactly the configured one.
    if urlsplit(target).netloc != b.netloc:
        return None
    return target
```

In `_handle`, call it; on `None` respond `400 {"error":"bad_path"}` and call `on_denied(tool_name, "BAD_PATH")`.

Also (F15), in the same function: add `max_body_bytes: int = 10 * 1024 * 1024` to `NetworkEnforcer.__init__`; respond `413` above it; wrap `int(Content-Length)` in try/except → `400`.

**Tests (`tests/test_network.py`, parametrize):** `//evil/x`, `///evil/x`, `/../admin`, `/%2e%2e/admin`, `/%2E%2E%2Fadmin`, `\\evil`, `http://evil/x`, `@evil`, `?x=@evil`. Each must either 400 or reach **only** the configured upstream (assert the second server's hit list is empty — reuse the probe's two-server setup). Plus a happy-path test that `customers/42?x=1` still works.

### 0A.2 Fix F2 — allow-list with missing operation (`permissions.py`)

```python
def operation_allowed(self, operation: str | None) -> bool:
    if operation is not None and operation in self.blocked_operations:
        return False
    if self.allowed_operations is not None:
        return operation is not None and operation in self.allowed_operations
    return True
```

Update the docstring on `allowed_operations` ("if set, a call **must** name an operation in this set"). Add a line to `CHANGELOG`/release notes: *behaviour change: tools with `allowed_operations` now deny calls that omit `operation`.*

**Tests (`test_boundary.py`, new class `TestAllowedOperations`):** allow-list + `operation=None` → `OPERATION_BLOCKED`; allow-list + member → allowed; no allow-list + `None` → allowed (unchanged).

### 0A.3 Fix F3 — value/record validation (`boundary.py`, `enums.py`)

Add a private helper near the top of `boundary.py` (or a new `_validate.py`):

```python
import math
from decimal import Decimal

def _as_finite_number(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float, Decimal)):
        f = float(v)
    elif isinstance(v, str):
        try:
            f = float(v.strip())
        except ValueError:
            return None
    else:
        return None
    return f if math.isfinite(f) else None
```

Rewrite `_check_value_limit` / `_check_record_limit`: if `ctx.value is not None` **and** the permission has a ceiling, coerce; if coercion returns `None` → raise `BoundaryViolation(rule=ViolationReason.INVALID_VALUE)`; otherwise compare the coerced number. Same for `record_count` (must be a non-negative integer-valued number).

**Add to `ToolPermission`** (`permissions.py`): `min_value: float | None = None` (so negative amounts can be refused: `ToolPermission("refund", max_value=500, min_value=0)`). Check order: below `min_value` → `MAX_VALUE_EXCEEDED`'s sibling `MIN_VALUE_VIOLATED`.

**Add to `ViolationReason`** (`enums.py`, append only): `INVALID_VALUE`, `MIN_VALUE_VIOLATED`, and (used in Phase 0A.3b) `VALUE_REQUIRED`, `RECORDS_REQUIRED`.

**0A.3b — optional strictness:** add `Boundary(strict_limits: bool = False)`. When `True`, a permission with `max_value` set and `ctx.value is None` is denied `VALUE_REQUIRED` (same for `max_records`/`record_count`). Default stays `False` in 1.x so nothing breaks; document it in README "Known limitations" ("a ceiling only applies if the caller supplies the value") and plan to flip the default in 2.0.

**Tests:** `NaN`, `inf`, `-inf`, `True`, `"abc"`, `"999999"` (denied by magnitude, not crash), `"500"` (allowed), `Decimal("5000")` (denied), negative with `min_value=0` (denied), `None` with/without `strict_limits`. Decorator test: `amount="999999"` → `BoundaryViolation`, function body never ran.

### 0A.4 Fix F4 — redact audit arguments (`decorators.py`, new `_redact.py`)

New stdlib-only `src/toolboundary/_redact.py`:

```python
import re
_SENSITIVE = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie|session)", re.I)

def redact_args(arguments, *, extra_names=frozenset(), max_len=200, log_values=True):
    out = {}
    for k, v in arguments.items():
        if k in extra_names or _SENSITIVE.search(k):
            out[k] = "<redacted>"
        elif not log_values:
            out[k] = f"<{type(v).__name__}>"
        else:
            try: s = repr(v)
            except Exception: s = "<unrepresentable>"
            out[k] = s if len(s) <= max_len else s[:max_len] + "...(truncated)"
    return out
```

In `decorators.py` replace `_safe_repr(kwargs)` with `redact_args(call_kwargs, extra_names=sensitive_args, log_values=log_arg_values)` (note: **bound** arguments, fixing the positional-arg inconsistency). Add parameters to `guarded_tool`: `sensitive_args: frozenset[str] = frozenset()` and `log_arg_values: bool = True`. Keep a `_safe_repr` alias that delegates, in case anyone imported it.

**Tests (`test_decorators.py`):** audit event for `password=`/`api_key=` shows `<redacted>`; positional arguments are present and redacted by name; `log_arg_values=False` logs types only; custom `sensitive_args={"ssn"}`.

### 0A.5 Fix F7 — decorator operation precedence (`decorators.py:95`)

```python
resolved_operation = call_kwargs.get("operation") or operation
```

**Test:** function with own `operation=None` param + configured `operation="delete"` → boundary sees `"delete"`.

### 0A.6 Fix F10 — success with `None` result (`evidence.py`, `boundary.py`)

Introduce a module-level sentinel and use it as the default:

```python
_UNSET = object()

def build_execution_record(*, call_digest, started_at, finished_at, result=_UNSET, error=None):
    if error is not None: ...                      # unchanged
    if result is _UNSET:  ... status="unknown"     # caller didn't say
    return ExecutionRecord(..., status="success",
                           result_digest=None if result is None else result_digest(result))
```

Mirror the default (`result: Any = _UNSET`) in `Boundary.record_execution`, and make sure `decorators.py` / `langchain.py` pass `result=result` explicitly (they already do). **Tests:** a tool returning `None` → `status == "success"`; no result supplied → `"unknown"` (existing behaviour).

### 0A.7 Release hygiene

- `__init__.py`: single-source the version. Easiest: in `pyproject.toml` use `dynamic = ["version"]` + `[tool.hatch.version] path = "src/toolboundary/__init__.py"`, and keep `__version__` as the one literal. Bump to `1.0.3`.
- README: replace the two hard-coded badges with CI/Codecov badges; update the "Known limitations" section (ceilings need a supplied value; link to `strict_limits`).
- `SECURITY.md`: add 1.0.3 to the supported table.
- Recreate `CHANGELOG.md` (Keep a Changelog format) with a 1.0.3 "Security" section listing F1-F4.

**Acceptance for 0A:** all new tests pass; `probe` scripts A, B, B2, C, F, J, L/M no longer show the bad outcomes; existing 122 tests still pass (update any that encoded the old allow-list behaviour).

---

## Phase 0B — Refactor with no behaviour change

Do this *before* Phase 1 so every later feature is a one-line addition, not a three-place edit.

### 0B.1 One check pipeline (F13/F14) — `boundary.py`

```python
def _run_checks(self, ctx: CallContext, *, record_rate: bool = True) -> ToolPermission:
    self._check_kill_switch(ctx)
    self._check_quarantine(ctx)
    self._check_validity_window(ctx)
    self._check_environment(ctx)
    self._check_global_blocked_operations(ctx)
    permission = self._check_tool_permission(ctx)
    self._check_operation(ctx, permission)
    self._check_access_mode(ctx, permission)
    self._check_value_limit(ctx, permission)
    self._check_record_limit(ctx, permission)
    self._check_rate_limit(ctx, record=record_rate)
    self._check_policy_hooks(ctx)
    self._check_requires_approval(ctx, permission)
    return permission
```

`evaluate()` and `check()` both call it (`check()` keeps its own `try/except` for auditing). Move `rank` in `_check_access_mode` to a module constant. Fix the `authorize_call` docstring. **Test:** an "ordering contract" test that asserts the sequence of checks via a recording subclass, so future edits can't reorder silently.

### 0B.2 Reorder rate limiting (F9) — `boundary.py`

Move `_check_policy_hooks` **before** `_check_rate_limit` so hook-denied calls don't burn budget or mask the reason. Update `docs/API.md:78-79` (steps 11/12 swap). Decision for you: whether approval-pending calls should also stop consuming budget (move `_check_requires_approval` before the rate limiter). Trade-off: pro, no budget burned waiting on humans; con, approval spam isn't rate limited. Recommended: leave approval where it is until Phase 3, then record the rate-limit hit only on the *approved* retry.

### 0B.3 Shared guarded-call runner — new `_dispatch.py`

`decorators.py:104-153` and `integrations/langchain.py:122-178` duplicate the provider / non-provider branches. Extract:

```python
@dataclass(frozen=True)
class GuardSpec:
    tool_name: str; operation: str | None; access_mode: AccessMode
    value_arg: str | None = None; record_count_arg: str | None = None
    correlation_id_arg: str | None = None
    resource: str | None = None; tool_version: str | None = None
    schema_hash: str | None = None; manifest_hash: str | None = None

def run_guarded(boundary, fn, arguments: dict, spec: GuardSpec, call): ...
async def arun_guarded(boundary, afn, arguments: dict, spec: GuardSpec, call): ...
```

`guarded_tool` becomes: bind args → pick sync/async wrapper (`inspect.iscoroutinefunction`) → delegate. **This also lands the F6 fix** (async wrapper awaits before `record_execution`). `guard_tool` delegates the same way and later adapters (Phase 5) are ~15 lines.

> Note for async + Redis limiter: `RedisSlidingWindowRateLimiter.check_and_record` is blocking I/O inside the event loop. Document it; an `acheck()` using `asyncio.to_thread` is a cheap follow-up.

### 0B.4 Fix F5 — LangChain adapter (`integrations/langchain.py`)

Inside `_GuardedTool`:

```python
def _run(self, *args, config=None, run_manager=None, **kwargs):
    named = _name_args(tool, args, kwargs)          # positional -> field names
    inner = inspect.signature(tool._run).parameters
    extra = {}
    if "config" in inner:      extra["config"] = config
    if "run_manager" in inner: extra["run_manager"] = run_manager
    return run_guarded(boundary, lambda: tool._run(*args, **kwargs, **extra), named, spec, ...)
```

with `_name_args` mapping positional values onto `list(tool.args)` (for a `Tool(func=...)` that's `tool_input`, so `value_arg="tool_input"` works; document this). Do the same in `_arun`, and **don't** fall back to blocking `tool._run` inside `_arun` without `asyncio.to_thread`.

**Tests (`test_langchain_integration.py`):** add `Tool(func=...)`, `StructuredTool.from_function`, an async tool, and a single-string positional input with a value ceiling. **CI:** add a matrix job for the oldest and newest supported `langchain-core` (raise the floor in `pyproject.toml` to whatever the oldest passing version is rather than `>=0.1.0`).

### 0B.5 Audit hygiene (F12/F16) — `audit.py`, `boundary.py`

- `AuditEvent`: add `phase: str = "decision"` (`"decision" | "authorization" | "execution"`) and `enforced: bool = True` (used by Phase 2). Defaults keep old consumers working; `to_dict()` gains two keys.
- `authorize_call` step 8 → `phase="authorization"`; `record_execution` → `phase="execution"`; and give both a non-decision marker so ALLOW counting by `phase == "decision"` is exact.
- `JSONLFileSink`: add a `threading.Lock` and a single `f.write(line + "\n")`.

### 0B.6 CI & tooling

Add to `.github/workflows/ci.yml`: `mypy src` (as CONTRIBUTING already promises); a **clean-install import test** that proves the zero-dependency claim (`python -m venv v && v/bin/pip install . && v/bin/python -c "import toolboundary"`); the langchain-core matrix above. Either use or delete the two dead `ViolationReason` members (F17); if you delete, remember the "append-only" rule — prefer keeping them and wiring `UNKNOWN_TOOL` into `_check_tool_permission` for a clearer reason code than `TOOL_NOT_ALLOWED` only if you can do so without breaking log parsers.

**Acceptance for 0B:** zero behaviour diff except F6/F9/F12 as documented; full suite green on 3.9-3.12; mypy clean.

---

## Phase 1 — Input-aware permissions (`arg_rules`) · v1.1.0

**Why:** today the policy sees *which tool* and *how much* (`value`, `record_count`) but never the actual arguments, so "this tool may fetch URLs" can't be narrowed to "only `api.mycompany.com`". This is the single biggest least-privilege gap, and it maps directly to OWASP ASI02 (tool misuse: parameter pollution, unsafe inputs). It is pure stdlib and declarative, so it fits the philosophy exactly.

### 1.1 New file: `src/toolboundary/rules.py`

```python
class ArgRule(Protocol):
    def validate(self, value: Any) -> str | None:
        """Return None if acceptable, else a short denial reason.
        Never include the raw value in the reason (it may be a secret)."""

@dataclass(frozen=True) class OneOf:         values: frozenset
@dataclass(frozen=True) class AllowedHosts:  hosts: frozenset[str]; schemes: frozenset[str] = frozenset({"https"}); allow_subdomains: bool = False; allow_ip_literals: bool = False; ports: frozenset[int] | None = None
@dataclass(frozen=True) class PathWithin:    root: str
@dataclass(frozen=True) class MatchesRegex:  pattern: str; max_len: int = 4096
@dataclass(frozen=True) class MaxLength:     n: int
@dataclass(frozen=True) class NumberBetween: lo: float | None = None; hi: float | None = None
@dataclass(frozen=True) class Custom:        fn: Callable[[Any], bool]; reason: str = "argument rejected"
```

Implementation requirements (these are the bugs people ship):

- **`AllowedHosts`**: `urlsplit(value)`; require scheme in `schemes`; **reject any `username`/`password`** (blocks `https://allowed.com@evil.com`); use `.hostname` (lower-cased, port stripped); strip one trailing dot; IDNA-encode non-ASCII (reject on failure); exact match or, if `allow_subdomains`, `host.endswith("." + h)` (never `endswith(h)` — `evilallowed.com`); for IP literals use `ipaddress.ip_address(...)` and require `.is_global` unless explicitly allowed; apply `ports`. Non-`str` input → deny.
- **`PathWithin`**: resolve with `os.path.realpath(os.path.join(root, value))`; compare with `os.path.commonpath([real_root, real_value]) == real_root` (**not** `startswith`: `/srv/data-evil` shares the prefix `/srv/data`); reject `\x00`; catch `ValueError` (Windows drive mismatch). Document the check-then-open race and recommend `O_NOFOLLOW`/dir-fd opens in the tool itself.
- **`MatchesRegex`**: compile once in `__post_init__` (raises `ConfigurationError` on a bad pattern → fail fast at setup); use `fullmatch`, not `search`; reject input longer than `max_len` *before* matching (ReDoS guard).
- All rules: wrong type → deny, never raise.

### 1.2 `permissions.py` — extend `ToolPermission`

```python
arg_rules: Mapping[str, Sequence[ArgRule]] = field(default_factory=dict, hash=False, compare=False)
allowed_args: frozenset[str] | None = None   # deny unknown argument names (parameter pollution)
```

`hash=False, compare=False` keeps the frozen dataclass hashable despite the dict. Normalise a single rule to a one-item tuple in `__post_init__` (use `object.__setattr__`, frozen dataclass).

### 1.3 `boundary.py` — plumb `arguments` through and add the check

- `CallContext`: add `arguments: Mapping[str, Any] | None = None`.
- `check()`, `evaluate()`, `check_and_authorize()`: add `arguments: Mapping[str, Any] | None = None`. Today `authorize_call` *requires* `arguments` but forwards none of it into `check()` — fix that: pass `arguments=arguments`.
- New `_check_arguments(ctx, permission)`, placed after `_check_record_limit` and before the rate limiter:
  1. `permission.arg_rules` non-empty and `ctx.arguments is None` → `ARGUMENTS_REQUIRED` (**fail closed**: someone configured rules but called `check()` the old way).
  2. `allowed_args` set and any key outside it → `ARGUMENT_NOT_ALLOWED`.
  3. Each rule: argument **missing** → `ARGUMENT_NOT_ALLOWED` (a required-but-absent argument must not skip validation); else `rule.validate(value)`; first reason → `BoundaryViolation(..., rule=ARGUMENT_NOT_ALLOWED, details={"argument": name, "rule": type(rule).__name__})`. The unused `BoundaryViolation.details` field is exactly for this.
- `enums.py`: append `ARGUMENT_NOT_ALLOWED`, `ARGUMENTS_REQUIRED`.
- `decorators.py` / `_dispatch.py` / `langchain.py`: pass `arguments=` (bound arguments).
- **Audit**: put `details` (argument *name* and rule type) in event metadata; never the value.

### 1.4 Usage (goes in README and `examples/arg_rules.py`)

```python
from toolboundary import Boundary, ToolPermission, AccessMode
from toolboundary.rules import AllowedHosts, PathWithin, MatchesRegex, NumberBetween

Boundary("support-agent", permissions=[
    ToolPermission("fetch_url", access_mode=AccessMode.EXECUTE,
                   arg_rules={"url": [AllowedHosts({"api.mycompany.com"})]},
                   allowed_args=frozenset({"url"})),
    ToolPermission("read_file", arg_rules={"path": [PathWithin("/srv/data")]}),
    ToolPermission("send_email",  access_mode=AccessMode.EXECUTE,
                   arg_rules={"to": [MatchesRegex(r"[\w.+-]+@mycompany\.com")]}),
])
```

### 1.5 Tests — new `tests/test_arg_rules.py`

URL: `https://allowed.com@evil.com`, `https://allowed.com.evil.com`, `https://evilallowed.com`, `http://` when only https, `https://ALLOWED.com.`, punycode/IDN, `http://127.0.0.1`, `http://[::1]`, `file:///etc/passwd`, `javascript:`. Path: `../`, `/srv/data-evil/x`, symlink escaping the root, `\x00`, relative vs absolute. Regex: `search`-vs-`fullmatch` bypass (`evil@x.com;a@mycompany.com`), oversize input. Pipeline: rules configured but `arguments=None` → `ARGUMENTS_REQUIRED`; missing argument; unknown argument with `allowed_args`; non-string input; decorator + LangChain end-to-end; audit event contains the argument name but not the value.

### 1.6 Docs to update

- `docs/API.md`: `ToolPermission` signature/table (`:97-118`); new "Argument rules" section; renumber the evaluation-order list (`:68-80`) to insert "arguments violate `arg_rules`" after step 10.
- `README.md`: add rows to the "What a `Boundary` can enforce" table; add a 10-line example; add a **limitations** bullet: *rules validate the string the tool receives; they don't stop DNS rebinding or redirects: pair with `NetworkEnforcer`/egress rules for a hard guarantee.*
- `CONTRIBUTING.md`: add `rules.py` to the project-structure tree.

### 1B. Bind network tokens to the request (F11) — `tokens.py`, `network.py`, `boundary.py`

- `tokens.py`: factor the payload dict (built by hand in `to_wire`, `issue`, and `verify`: three places that must stay identical) into one `AuthorizationToken._payload()` / `_payload_for(...)` helper. Add optional fields `method: str | None = None` and `resource: str | None = None`; include them in the payload **only when not `None`** so existing tokens and signatures remain valid.
- `TokenIssuer.issue(..., method=None, resource=None)`; `verify(..., expected_method=None, expected_resource=None)`.
- `Boundary.check_and_authorize(..., method=None, resource=None)` forwards to `issue`.
- `UpstreamRoute`: add `allowed_methods: frozenset[str] | None = None` (a read-only tool route can simply refuse `DELETE` even without token binding).
- `NetworkEnforcer.authorize_and_resolve(tool_name, token_wire, *, method, path)`: reject with `TOKEN_SCOPE_MISMATCH` when a bound `method` differs or the request path isn't equal to/under the bound `resource`.
- Optional: `body_sha256` claim for write calls (token binds the exact payload). Skip unless asked; it needs the proxy to buffer the body (it already does).
- Tests in `test_tokens.py` and `test_network.py`: old-format tokens still verify; mismatched method/path rejected; signature tampering of the new fields rejected.
- Fix the stale `issue_network_token=True` docstring.

**Acceptance for Phase 1:** a `fetch_url` tool with `AllowedHosts` denies the whole URL-trick list above; `ARGUMENTS_REQUIRED` fires if `arguments` is omitted; existing users who set no `arg_rules` see zero change; `ruff`, `mypy`, 3.9-3.12 green.

---

## Phase 2 — Safe rollout: shadow mode, `explain()`, replay · v1.1.0

**Why:** the biggest adoption fear is "this will break my agent". Staged rollout (observe → partial enforce → enforce) is standard practice for policy engines, and you already have the vocabulary: `ProviderMode.OBSERVE` exists for *external providers* but there is nothing equivalent for *local policy*.

### 2.1 Shadow mode — `enums.py`, `boundary.py`

```python
class EnforcementMode(str, Enum):
    ENFORCE = "enforce"
    SHADOW  = "shadow"
```

`Boundary(..., mode=EnforcementMode.ENFORCE, shadow_until: float | None = None)`

Design rules (these keep it fail-closed in spirit):

1. `SHADOW` **requires** `shadow_until` (a future Unix timestamp, capped at e.g. 30 days) → else `ConfigurationError`. **Shadow mode expires on its own and reverts to ENFORCE**, so it can't be left on by accident. Log one `WARNING` at construction and one when it expires.
2. `KillSwitchActive` and `AGENT_QUARANTINED` are **never** shadowed. They always raise.
3. In `check()`, when shadowing and a `BoundaryViolation` or `ApprovalRequired` is caught: record the audit event with the *real* decision (`DENY` / `APPROVAL_REQUIRED`) but `enforced=False` and `metadata["shadow"]=True`, then **return normally**.
4. Property `Boundary.is_enforcing`. `authorize_call` inherits shadow behaviour via `check()`. `ProviderMode.ENFORCE` is independent and still blocks.

`audit.py`: add `enforced: bool = True` to `AuditEvent` and `AuditTrail.record(..., enforced=True)` (already added in 0B.5). Keeping `decision="DENY"` means dashboards still count "what the policy decided".

### 2.2 `explain()` — non-raising, complete diagnosis

```python
@dataclass(frozen=True)
class Finding:      rule: str; message: str; kind: str            # "deny" | "approval"
@dataclass(frozen=True)
class Explanation:  decision: str; findings: tuple[Finding, ...]

def explain(self, tool_name, *, operation=None, access_mode=..., value=None,
            record_count=None, arguments=None) -> Explanation
```

Runs **every** check even after the first failure (so you see all reasons), writes **no audit event** and records **no rate-limit hit**: use the `rate_limiter.current_count(key, 3600) >= max` path (both the in-memory and Redis limiters already expose `current_count`; document that custom limiters must too). This is what `_run_checks(record_rate=False)` from 0B.1 is for. Useful in tests and in the CLI below.

### 2.3 Audit enrichment — `boundary.py` (`check()` audit calls)

Today audit events carry tool/operation/access mode but **not** `value`, `record_count`, `policy_version`, `autonomy`, or `environment` (`policy_version` is set on the boundary but only ever appears in `LocalDecision`). Add them via one private `_audit_meta(ctx)` merged into `metadata`. Numeric fields only; no argument values.

### 2.4 Replay CLI — new `src/toolboundary/__main__.py` (stdlib `argparse`)

```
python -m toolboundary replay audit.jsonl --boundary mypkg.policy:boundary [--only-changes]
python -m toolboundary explain --boundary mypkg.policy:boundary --tool send_email --op send_bulk --mode EXECUTE
```

`replay` reads a `JSONLFileSink` log, rebuilds a `CallContext` from each event (enabled by 2.3), calls `explain()` against the candidate boundary (loaded by `module:attribute` through `importlib`; it runs your own code, so say so in the docs) and prints a table of *old decision → new decision*. This lets someone tighten a policy and see exactly which historical calls would now be blocked, with no service and no database. Limitation to document: events don't contain argument values (by design, see F4), so `arg_rules` can't be replayed. Name the argument-level gap rather than hiding it.

### 2.5 Tests & docs

- `tests/test_shadow.py`: shadow logs and returns; kill switch still raises in shadow; shadow without `shadow_until` → `ConfigurationError`; expired shadow window enforces; audit has `enforced=False`; provider `ENFORCE` still blocks under shadow.
- `tests/test_explain.py`: multiple findings returned; no audit event emitted; rate limiter counts unchanged afterwards.
- `tests/test_cli.py`: replay on a fixture JSONL.
- `README.md`: "Rolling out safely" section; `docs/API.md`: `EnforcementMode`, `explain()`, CLI.

**Acceptance for Phase 2:** an operator can run an agent for a week in shadow mode, replay the log against a tighter policy, and flip to `ENFORCE` with a one-line change, with no behaviour change for anyone who never sets `mode`.

---

## Phase 3 — Make approvals complete · v1.2.0

**Why (F8):** "Human-in-the-loop" is a headline feature, but `ApprovalRequired` is currently a dead end: `approval_id` is always `None` and nothing ever consults `approval_state`, so after a human approves there's no sanctioned way to proceed. Closing this keeps the library self-contained (still no service).

### 3.1 Data model — new `src/toolboundary/approvals.py` (stdlib-only)

```python
@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str; agent_name: str; tool_name: str; operation: str | None
    fingerprint: str          # sha256 of canonicalize({tool, operation, arguments}), reuse evidence.py
    requested_at: float; expires_at: float; summary: str

class ApprovalStore(Protocol):
    def create(self, req: ApprovalRequest) -> None: ...
    def decide(self, approval_id: str, *, approved: bool, approver: str) -> bool: ...
    def consume(self, approval_id: str, fingerprint: str) -> bool: ...   # atomic

class InMemoryApprovalStore: ...     # threading.Lock + TTL GC, mirroring InMemoryTokenStore
```

`consume` returns `True` only if the request is approved, unexpired, **not already consumed**, and the fingerprint matches (single use, bound to the exact call). Reuse `evidence.canonicalize()` / `evidence.sha256()`; don't write new hashing.

### 3.2 Boundary changes — `boundary.py`

New constructor params: `approval_store: ApprovalStore | None = None`, `approver: Callable[[ApprovalRequest], bool] | None = None`, `approval_ttl: float = 900.0`. New `check(..., approval_id: str | None = None)` parameter (also on `authorize_call`, which already has it).

Rewrite `_check_requires_approval` (still the **last** step, so approval can never override a deny):

1. Not needed → return.
2. `ctx.approval_id` given → `store.consume(approval_id, fingerprint)`; success → pass (audit `approval_id`, `approver`); failure → `ApprovalRequired` with an explicit reason (`expired`, `already used`, `mismatch`).
3. Else if `approver` callback is configured → create the request, call it synchronously inside `try/except` (exception or non-`True` → raise `ApprovalRequired`; **fail closed**); `True` → pass.
4. Else if a store exists → create request, raise `ApprovalRequired(approval_id=req.approval_id)` so the caller can route it to a human and retry with that id.
5. Else raise exactly as today (`approval_id=None`): fully backward compatible.

Also populate `FrozenToolCall.approval_id` / `approval_state="approved"` automatically in `authorize_call` (the digest already covers both fields).

### 3.3 Security rules to encode and test

- **The approval id must never be an LLM-controllable tool argument.** An agent that can pass `approval_id` can approve itself. So: **no** `approval_id_arg` on `guarded_tool`. Supply it from the host application through a `contextvars.ContextVar` (`toolboundary.approvals.approval_context(approval_id)`) or an explicit `boundary.check(approval_id=...)` in custom code. Put this warning in the docs.
- Approval converts only `APPROVAL_REQUIRED → ALLOW`. Add a **contract test in the style of `tests/test_provider.py`**: an approved id cannot rescue a call that fails kill switch, quarantine, validity, environment, blocked op, permission, access mode, value, records, arguments, hooks, or rate limit.
- Single use (second `consume` → `False`); expiry; fingerprint mismatch when arguments differ by one character; kill switch engaged between approval and retry → still denied.
- Rate budget: record the rate-limit hit on the approved retry only (resolves the 0B.2 open question).

### 3.4 Helpers & backends

- `toolboundary.approvals.console_approver(request) -> bool`: `input()` prompt; **denies automatically if `sys.stdin` isn't a TTY** (so a background agent never hangs or auto-approves).
- `redis_backend.RedisApprovalStore`: `HSET` + a Lua `consume` that compares status/fingerprint/expiry and flips to `consumed` atomically, following the existing `_SLIDING_WINDOW_LUA` pattern, same `fail_closed=True` default.
- `__init__.py`: export `ApprovalRequest`, `ApprovalStore`, `InMemoryApprovalStore`.

### 3.5 Docs

`docs/API.md` (new "Approvals" section, step 14 wording), `README.md` (replace the vague "routes to a human" sentences with the real flow and a 12-line example), `examples/approval_flow.py`, `CONTRIBUTING.md` structure tree.

**Acceptance for Phase 3:** `check()` → `ApprovalRequired(approval_id=X)` → operator calls `store.decide(X, approved=True, approver="alice")` → retry with `approval_id=X` succeeds exactly once; an altered argument, an expired id, a second use, or an engaged kill switch all fail.

---

## Phase 4 — Session-aware rules (the "lethal trifecta" guard) · v1.3.0

**Why:** some dangerous behaviour is invisible call-by-call: *private data + untrusted content + a way to send data out* in the same session. Several MCP proxies implement this with session taint; none is a zero-dependency in-process library. You already keep per-key state for rate limits and already have `correlation_id` in `check()` and the audit log, so this is state + declarative labels, not a new architecture.

### 4.1 Model — new `src/toolboundary/session.py`

```python
class Capability(str, Enum):
    PRIVATE_DATA = "private_data"; UNTRUSTED_CONTENT = "untrusted_content"; EGRESS = "egress"

class SessionAction(str, Enum): DENY = "deny"; APPROVE = "approve"

@dataclass(frozen=True)
class SessionRule:
    forbid: frozenset[Capability]            # e.g. all three
    action: SessionAction = SessionAction.DENY

class SessionStore(Protocol):
    def labels(self, session_id: str) -> frozenset[Capability]: ...
    def add(self, session_id: str, labels: frozenset[Capability]) -> None: ...

class InMemorySessionStore:   # bounded: max_sessions (LRU) + TTL, like InMemoryTokenStore._gc
```

### 4.2 Wiring

- `ToolPermission`: add `capabilities: frozenset[Capability] = frozenset()`.
- `Boundary(session_rules=[...], session_store=None)`.
- Session id = `correlation_id` (already a parameter everywhere), falling back to a `ContextVar` (`session_scope("conv-123")`), falling back to one default session per `Boundary`. The shared default errs toward over-blocking when conversations are mixed, which is the safe direction; document it and tell multi-conversation servers to pass ids.
- New `_check_session(ctx, permission)` after `_check_arguments`: `after = store.labels(sid) | permission.capabilities`; if `rule.forbid <= after` **and** the call's own capabilities intersect `rule.forbid` → deny (`SESSION_POLICY_DENIED`) or raise `ApprovalRequired` per `action`. This blocks the *call that completes the set*.
- Labels are added **only when a call is finally allowed** (the `else:` branch of `check()`), declaratively from the permission, with no heuristics and no inspection of tool results. In shadow mode, still record labels so the shadow log shows what would have happened.
- `enums.py`: append `SESSION_POLICY_DENIED`.
- `redis_backend.RedisSessionStore`: `SADD` + `EXPIRE`, fail-closed default.

### 4.3 Honest limits (put these in the README, as you did for the rate limiter)

Capabilities are *declared*, not discovered: this tracks **exposure**, not data flow. A tool labelled `PRIVATE_DATA` taints the session even if it returned nothing. Different processes/sub-agents don't share state unless you pass a shared store. It reduces the blast radius of prompt injection; it doesn't detect injection.

### 4.4 Tests, docs, example

`tests/test_session.py`: two legs allowed, third denied; order independence; `APPROVE` action; sessions isolated by id; LRU/TTL eviction bounds memory; shadow mode still labels; denied calls don't add labels. `examples/lethal_trifecta.py`. `docs/API.md` section; README table row.

**Acceptance for Phase 4:** an agent with `read_crm` (PRIVATE_DATA), `fetch_url` (UNTRUSTED_CONTENT) and `send_email` (EGRESS) is allowed any two in a session but denied the call that completes the trio.

---

## Phase 5 — Ecosystem & distribution · v1.4.0

### 5.1 Tool-definition pinning ("rug-pull" defence)

`FrozenToolCall` already has `schema_hash` / `manifest_hash`, and `authorize_call` accepts them, but **nothing enforces them**. Add:

- `evidence.tool_digest(name, description, input_schema) -> str` (reuse `canonicalize` + `sha256`).
- `check(..., schema_hash: str | None = None)` and `CallContext.schema_hash`.
- `Boundary(pinned_tools: Mapping[str, str] | None = None)`; `_check_tool_pin`: if the tool is pinned and `schema_hash` is missing or different → deny `TOOL_DEFINITION_CHANGED` (append to `ViolationReason`).
- `toolboundary.pins.pin_from_tools(tool_list) -> dict[str, str]` that prints a literal you **commit to the repo**, which matches the "policy is version-controlled code" principle better than a hidden TOFU file.

This is meaningful for **remote tool servers (MCP)**, whose definitions can change between sessions. It adds nothing for in-process LangChain tools (their definitions are static in your own code), so say so.

### 5.2 MCP client adapter — `integrations/mcp.py` + `mcp = ["mcp>=…"]` extra

Wrap a client session so `call_tool(name, arguments)` goes through `run_guarded` / `arun_guarded` (from 0B.3) with `arguments=` forwarded (so Phase 1 `arg_rules` work), and compute `schema_hash` from the tool list for 5.1. **Confirm against the pinned `mcp` SDK before coding** (see §0).

### 5.3 Other adapters

LangGraph `ToolNode`, OpenAI Agents SDK, CrewAI (PR #11), AutoGen (issue #15): each ~15 lines on top of `run_guarded` / `arun_guarded`, each with its own optional extra and the same contract tests (`allow`, `deny-before-body`, `provider ENFORCE`, `arguments match authorization`).

### 5.4 Docs

- `docs/OWASP-MAPPING.md`: a table mapping features → OWASP Top 10 for Agentic Applications (2026). Only claim IDs I verified: **ASI01** goal hijack (session rules reduce blast radius), **ASI02** tool misuse (permissions, `arg_rules`, ceilings, rate limits), **ASI03** identity/privilege abuse (least-privilege permissions, scoped tokens), **ASI04** supply chain (tool pinning), **ASI05** unexpected code execution (only `blocked_operations`/`arg_rules` on exec tools; be honest that sandboxing is out of scope), **ASI10** rogue agents (kill switch, quarantine). Fill ASI06-09 from the OWASP source itself rather than from this document.
- Recreate `docs/ARCHITECTURE.md` if you removed it unintentionally.

---

## 4. File-by-file change matrix

| File | 0A | 0B | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|---|
| `boundary.py` | value checks, `strict_limits` | `_run_checks`, reorder hooks/rate, `record_rate` | `arguments`, `_check_arguments` | `mode`, `shadow_until`, `explain`, `_audit_meta` | approval store/approver, `approval_id` | `session_rules`, `_check_session` | `pinned_tools`, `schema_hash` |
| `permissions.py` | allow-list fix, `min_value` | | `arg_rules`, `allowed_args` | | | `capabilities` | |
| `enums.py` | `INVALID_VALUE`, `MIN_VALUE_VIOLATED`, `VALUE_REQUIRED`, `RECORDS_REQUIRED` | | `ARGUMENT_NOT_ALLOWED`, `ARGUMENTS_REQUIRED` | `EnforcementMode` | | `SESSION_POLICY_DENIED` | `TOOL_DEFINITION_CHANGED` |
| `decorators.py` | redaction, operation precedence | delegate to `_dispatch` + async wrapper | pass `arguments` | | | | |
| `integrations/langchain.py` | | signature/positional fix, delegate | pass `arguments` | | | | |
| `evidence.py` | `_UNSET` / success-with-None | | | | reuse for fingerprint | | `tool_digest` |
| `audit.py` | | `phase`, `enforced`, lock | | uses `enforced` | | | |
| `network.py` | `_resolve_target`, body cap | | route `allowed_methods`, scope check | | | | |
| `tokens.py` | | `_payload()` refactor | `method`, `resource` claims | | | | |
| `redis_backend.py` | | | | | `RedisApprovalStore` | `RedisSessionStore` | |
| `exceptions.py` | | | | | richer `ApprovalRequired` reason | | |
| `__init__.py` | version | | export `rules` types | export `EnforcementMode` | export approvals | export session types | |
| `__main__.py` (new) | | | | replay / explain CLI | | | |
| **new:** `_redact.py` | ✔ | | | | | | |
| **new:** `_dispatch.py` | | ✔ | | | | | |
| **new:** `rules.py` | | | ✔ | | | | |
| **new:** `approvals.py` | | | | | ✔ | | |
| **new:** `session.py` | | | | | | ✔ | |
| **new:** `pins.py`, `integrations/mcp.py` | | | | | | | ✔ |
| `pyproject.toml` | version, dynamic version | langchain floor, mypy | | | | | `mcp` extra |
| `ci.yml` | | mypy, clean-install import test, langchain-core matrix | | | | | |
| `docs/API.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| New tests | allow-list, value, redaction, network traversal, None-result | ordering contract, async, LangChain `Tool` | `test_arg_rules.py`, token binding | `test_shadow.py`, `test_explain.py`, `test_cli.py` | approval contract tests | `test_session.py` | pin / MCP adapter tests |
| New examples | | | `arg_rules.py` | | `approval_flow.py` | `lethal_trifecta.py` | `mcp_guard.py` |

---

## 5. Cross-cutting rules for every PR

1. Every new public name is exported from `__init__.py` **and** listed in `docs/API.md` **and** in the `CONTRIBUTING.md` structure tree.
2. Every new `ViolationReason` is append-only, with a test asserting the raised `rule` string.
3. Every new check has a test that proves the call **does not execute** (the `calls == []` pattern already used in `test_decorators.py`).
4. Every new stateful component has an in-memory default **and** a Redis variant that is `fail_closed=True` by default, following `redis_backend.py`.
5. Any change to the authorization flow must pass `tests/test_provider.py` unchanged (that file is your "local DENY is final" contract).
6. Security-relevant docstrings explain **why** (fail-open vs fail-closed, what the check does *not* cover), as `CONTRIBUTING.md` already requires.

---

## 6. What deliberately **not** to add

- **YAML/JSON policy files as the main interface:** contradicts "policy is plain Python, reviewed in PRs". If ever offered, make it an optional extra that *compiles to* the same objects.
- **A dashboard, sandbox, anomaly detection, or LLM-as-judge in core:** pulls the project toward the gateway-style products it differentiates against, and adds dependencies or non-determinism. The replay CLI (Phase 2) covers the "see what happened" need with the stdlib.
- **Prompt-injection text classifiers:** heuristic and bypassable; Phase 4's declarative session rules reduce blast radius without pretending to detect attacks.

---

## 7. Suggested order of work (if you only have a few evenings)

1. **Evening 1:** 0A.1 (proxy) and 0A.2 (allow-list). Tag 1.0.3, publish an advisory.
2. **Evening 2:** 0A.3, 0A.4, 0A.5, 0A.6 + release hygiene.
3. **Weekend:** 0B (pipeline, `_dispatch`, LangChain fix, CI).
4. **Then in order:** Phase 1 → 2 → 3 → 4 → 5. Phases 1 and 2 together give the best "wow per line of code": input-aware rules plus a safe way to adopt them.
