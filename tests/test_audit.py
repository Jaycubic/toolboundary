from __future__ import annotations

import json

import pytest

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    ToolPermission,
)
from toolboundary.audit import AuditTrail, JSONLFileSink


class RecordingSink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def test_allow_and_deny_both_produce_audit_events():
    sink = RecordingSink()
    audit = AuditTrail(sinks=[sink])
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        audit=audit,
    )

    boundary.check("read_db", access_mode=AccessMode.READ_ONLY)
    with pytest.raises(Exception):  # noqa: B017 - BoundaryViolation subclass, exact type not the point here
        boundary.check("write_db", access_mode=AccessMode.WRITE)

    decisions = [e.decision for e in sink.events]
    assert decisions == ["ALLOW", "DENY"]


def test_jsonl_file_sink_writes_valid_json_lines(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = AuditTrail(sinks=[JSONLFileSink(log_path)])
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        audit=audit,
    )

    boundary.check("read_db", access_mode=AccessMode.READ_ONLY)

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["decision"] == "ALLOW"
    assert parsed["agent_name"] == "agent"
    assert parsed["tool_name"] == "read_db"


def test_webhook_sink_failure_never_raises():
    from toolboundary.audit import WebhookSink

    sink = WebhookSink("http://localhost:1/nonexistent-endpoint", timeout=0.1)
    audit = AuditTrail(sinks=[sink])
    boundary = Boundary(
        agent_name="agent",
        autonomy=AutonomyLevel.AUTONOMOUS,
        permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
        audit=audit,
    )

    # Should not raise even though the webhook endpoint doesn't exist
    boundary.check("read_db", access_mode=AccessMode.READ_ONLY)
