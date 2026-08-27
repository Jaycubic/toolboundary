"""
toolboundary.audit
------------------
Local-first audit trail.

Design goal: ToolBoundary must never require a hosted service or database to
produce useful audit evidence. By default every decision is emitted as a
structured JSON line to stdlib `logging` (logger name "toolboundary.audit"),
which the host application can route anywhere logging already goes
(stdout, a file, Datadog, CloudWatch, etc.) with zero extra code.

Optional sinks (JSONL file, HTTP webhook) are provided for teams that want
a durable local record or want to forward events to a centralized
governance platform (e.g. a GuardianIQ-style registry) without coupling
ToolBoundary itself to any specific vendor.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

_logger = logging.getLogger("toolboundary.audit")


@dataclass(frozen=True)
class AuditEvent:
    """
    One record of a single ToolBoundary decision.

    Field names intentionally echo the vocabulary used by enterprise AI
    governance registries (agent_id, tool_id, access_mode, decision) so
    that events can be reconciled with, or imported into, such a system
    later without a translation layer.
    """

    event_id: str
    timestamp: float
    agent_name: str
    tool_name: str | None
    operation: str | None
    access_mode: str | None
    decision: str  # ALLOW | DENY | APPROVAL_REQUIRED
    reason_code: str | None
    message: str
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, sort_keys=True)


class AuditSink(Protocol):
    """Anything with an `emit(event)` method can be used as a sink."""

    def emit(self, event: AuditEvent) -> None: ...


class LoggingSink:
    """Default sink: writes structured JSON to Python's stdlib logging."""

    def __init__(self, level: int = logging.INFO) -> None:
        self._level = level

    def emit(self, event: AuditEvent) -> None:
        level = self._level if event.decision == "ALLOW" else logging.WARNING
        _logger.log(level, event.to_json())


class JSONLFileSink:
    """Appends each event as one JSON line to a local file. Thread-safe append."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        with self._path.open("a", encoding="utf-8") as f:
            f.write(event.to_json())
            f.write("\n")


class WebhookSink:
    """
    Forwards events to an HTTP endpoint (e.g. a self-hosted dashboard or a
    governance platform's ingestion API). Uses `urllib` to avoid forcing a
    `requests` dependency on users who don't need this sink.

    Failures are swallowed (never raised) so that a network hiccup in your
    audit pipeline can never block or crash the agent itself -- audit
    delivery is best-effort by design; the ALLOW/DENY decision has already
    been enforced locally before this sink is even invoked.
    """

    def __init__(
        self, url: str, timeout: float = 2.0, headers: dict[str, str] | None = None
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._headers = headers or {"Content-Type": "application/json"}

    def emit(self, event: AuditEvent) -> None:
        import urllib.request

        try:
            data = event.to_json().encode("utf-8")
            # S310: the webhook URL is supplied by the host application at
            # WebhookSink construction time, not by untrusted input reaching
            # this code path -- this is a deliberate, documented HTTP POST,
            # not an arbitrary-scheme file open.
            req = urllib.request.Request(  # noqa: S310
                self._url, data=data, headers=self._headers, method="POST"
            )
            urllib.request.urlopen(req, timeout=self._timeout)  # noqa: S310
        except Exception:  # noqa: BLE001 - audit delivery must never raise
            _logger.debug("toolboundary: webhook audit sink failed to deliver event", exc_info=True)


class AuditTrail:
    """Fans out one AuditEvent to any number of configured sinks."""

    def __init__(self, sinks: list[AuditSink] | None = None) -> None:
        self.sinks: list[AuditSink] = sinks if sinks is not None else [LoggingSink()]

    def add_sink(self, sink: AuditSink) -> None:
        self.sinks.append(sink)

    def record(
        self,
        *,
        agent_name: str,
        decision: str,
        message: str,
        tool_name: str | None = None,
        operation: str | None = None,
        access_mode: str | None = None,
        reason_code: str | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            agent_name=agent_name,
            tool_name=tool_name,
            operation=operation,
            access_mode=access_mode,
            decision=decision,
            reason_code=reason_code,
            message=message,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception:  # noqa: BLE001
                _logger.debug(
                    "toolboundary: sink %r raised while emitting event", sink, exc_info=True
                )
        return event
