"""
Performance benchmarks for ToolBoundary's decision paths.

Run them with:

    pytest benchmarks --benchmark-only --no-cov

The benchmark workflow runs these on every pull request, first against the base
branch and then against the change, and fails if a decision path gets markedly slower.
They use only the public API, so the same file can measure an older release.
"""

from __future__ import annotations

import warnings

import pytest

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    BoundaryViolation,
    ToolPermission,
)
from toolboundary.audit import AuditTrail
from toolboundary.tokens import TokenIssuer

# Large enough that the rate limiter never denies during a benchmark run.
_UNLIMITED = 10**9


def _boundary(**overrides: object) -> Boundary:
    settings: dict[str, object] = {
        "autonomy": AutonomyLevel.AUTONOMOUS,
        "max_actions_per_hour": _UNLIMITED,
        "audit": AuditTrail(sinks=[]),  # measure the decision, not logging I/O
        "permissions": [
            ToolPermission("read_db", access_mode=AccessMode.READ_ONLY),
            ToolPermission(
                "pay",
                access_mode=AccessMode.EXECUTE,
                min_value=0,
                max_value=1_000,
                max_records=50,
                allowed_operations=frozenset({"charge"}),
            ),
        ],
        "blocked_operations": frozenset({"delete_everything"}),
    }
    settings.update(overrides)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        return Boundary("bench-agent", **settings)  # type: ignore[arg-type]


@pytest.mark.benchmark(group="check")
def test_check_allow(benchmark) -> None:
    boundary = _boundary()
    benchmark(boundary.check, "read_db", access_mode=AccessMode.READ_ONLY)


@pytest.mark.benchmark(group="check")
def test_check_allow_with_limits(benchmark) -> None:
    boundary = _boundary()
    benchmark(
        boundary.check,
        "pay",
        operation="charge",
        access_mode=AccessMode.EXECUTE,
        value=250,
        record_count=10,
    )


@pytest.mark.benchmark(group="check")
def test_check_deny(benchmark) -> None:
    boundary = _boundary()

    def deny() -> None:
        try:
            boundary.check("unregistered_tool", access_mode=AccessMode.READ_ONLY)
        except BoundaryViolation:
            pass

    benchmark(deny)


@pytest.mark.benchmark(group="check")
def test_evaluate_without_raising(benchmark) -> None:
    boundary = _boundary()
    benchmark(boundary.evaluate, "pay", access_mode=AccessMode.EXECUTE, value=5_000)


@pytest.mark.benchmark(group="tokens")
def test_token_issue_and_verify(benchmark) -> None:
    issuer = TokenIssuer(secret="benchmark-secret-not-real", ttl_seconds=30)

    def issue_and_verify() -> None:
        token = issuer.issue(agent_name="agent-1", tool_name="crm_api", operation="READ")
        issuer.verify(token, expected_agent_name="agent-1", expected_tool_name="crm_api")

    benchmark(issue_and_verify)


@pytest.mark.benchmark(group="tokens")
def test_check_and_authorize(benchmark) -> None:
    boundary = _boundary(
        token_issuer=TokenIssuer(secret="benchmark-secret-not-real", ttl_seconds=30)
    )
    benchmark(boundary.check_and_authorize, "read_db", access_mode=AccessMode.READ_ONLY)
