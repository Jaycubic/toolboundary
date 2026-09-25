"""
toolboundary.evidence
---------------------
Deterministic canonicalization and hashing of tool-call evidence.

The proposal explicitly requires freezing the exact call and hashing the
canonical representation so that:

1. Equivalent dictionaries produce identical digests regardless of key order.
2. The digest cryptographically binds the authorization to the exact call.
3. Raw secrets never need to appear in evidence records — the digest binds
   arguments without requiring them to be stored in plaintext.

Canonicalization uses ``json.dumps`` with ``sort_keys=True`` and minimal
separators, then SHA-256 of the UTF-8 bytes.  Do NOT use ``repr()`` as
the cryptographic representation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .provider import ExecutionRecord, FrozenToolCall


def canonicalize(value: Any) -> str:
    """Produce a deterministic JSON string from an arbitrary value.

    Equivalent dictionaries such as ``{"a": 1, "b": 2}`` and
    ``{"b": 2, "a": 1}`` produce the same canonical form.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256(data: str) -> str:
    """Return the hex-encoded SHA-256 digest of the given string's UTF-8 bytes."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def call_digest(call: FrozenToolCall) -> str:
    """Compute a deterministic digest that binds the exact tool call.

    The digest covers agent, tool, operation, arguments, and all
    optional binding fields (resource, version, schema/manifest hashes,
    approval state) so that mutating any of these invalidates the
    authorization.

    Returns
    -------
    str
        Hex-encoded SHA-256 of the canonical JSON representation.
    """
    binding = {
        "agent_name": call.agent_name,
        "tool_name": call.tool_name,
        "operation": call.operation,
        "arguments": call.arguments,
        "resource": call.resource,
        "tool_version": call.tool_version,
        "schema_hash": call.schema_hash,
        "manifest_hash": call.manifest_hash,
        "approval_id": call.approval_id,
        "approval_state": call.approval_state,
    }
    return sha256(canonicalize(binding))


def result_digest(result: Any) -> str:
    """Compute a digest of a tool execution result.

    This allows evidence records to bind to the outcome without
    storing the raw result (which may contain sensitive data).
    """
    return sha256(canonicalize(result))


def freeze_with_digest(call: FrozenToolCall) -> FrozenToolCall:
    """Return a new FrozenToolCall with ``call_digest`` populated.

    Because FrozenToolCall is a frozen dataclass, this creates a new
    instance with the computed digest. The original is not modified.
    """
    digest = call_digest(call)
    # Use object.__setattr__ to work around frozen=True, or construct new.
    # Constructing new is cleaner and more explicit:
    return FrozenToolCall(
        agent_name=call.agent_name,
        tool_name=call.tool_name,
        operation=call.operation,
        arguments=call.arguments,
        resource=call.resource,
        tool_version=call.tool_version,
        schema_hash=call.schema_hash,
        manifest_hash=call.manifest_hash,
        approval_id=call.approval_id,
        approval_state=call.approval_state,
        call_digest=digest,
    )


def build_execution_record(
    *,
    call_digest: str,
    started_at: float,
    finished_at: float,
    result: Any = None,
    error: BaseException | None = None,
) -> ExecutionRecord:
    """Build an ExecutionRecord from execution outcomes.

    Parameters
    ----------
    call_digest:
        The digest of the frozen call this execution corresponds to.
    started_at / finished_at:
        Timestamps bounding the execution.
    result:
        The return value of the tool, if execution succeeded.
    error:
        The exception raised by the tool, if execution failed.

    Returns
    -------
    ExecutionRecord
        With status "success", "error", or "unknown" as appropriate.
    """
    if error is not None:
        return ExecutionRecord(
            call_digest=call_digest,
            status="error",
            started_at=started_at,
            finished_at=finished_at,
            result_digest=None,
            error_type=type(error).__name__,
            error_message=str(error),
        )
    elif result is not None:
        return ExecutionRecord(
            call_digest=call_digest,
            status="success",
            started_at=started_at,
            finished_at=finished_at,
            result_digest=result_digest(result),
        )
    else:
        return ExecutionRecord(
            call_digest=call_digest,
            status="unknown",
            started_at=started_at,
            finished_at=finished_at,
        )
