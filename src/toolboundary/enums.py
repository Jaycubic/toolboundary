"""
toolboundary.enums
------------------
Deliberately mirrors the vocabulary used by enterprise AI-governance
registries (e.g. execution_mode, access_mode) so that logs produced by
ToolBoundary can later be ingested by, or reconciled against, a centralized
governance platform without a translation layer.
"""

from __future__ import annotations

from enum import Enum


class AutonomyLevel(str, Enum):
    """How much an agent may do without a human in the loop."""

    RECOMMEND_ONLY = "RECOMMEND_ONLY"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    LIMITED_AUTONOMOUS = "LIMITED_AUTONOMOUS"
    AUTONOMOUS = "AUTONOMOUS"
    QUARANTINED = "QUARANTINED"


class AccessMode(str, Enum):
    """Operation-level access, independent of which tool is being called."""

    READ_ONLY = "READ_ONLY"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    ADMIN = "ADMIN"


class DecisionType(str, Enum):
    """Outcome of an ToolBoundary evaluation for a single tool call."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class ViolationReason(str, Enum):
    """Machine-readable reason codes, stable across versions for log parsing."""

    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    AGENT_QUARANTINED = "AGENT_QUARANTINED"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    OPERATION_BLOCKED = "OPERATION_BLOCKED"
    ACCESS_MODE_EXCEEDED = "ACCESS_MODE_EXCEEDED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    MAX_VALUE_EXCEEDED = "MAX_VALUE_EXCEEDED"
    MAX_RECORDS_EXCEEDED = "MAX_RECORDS_EXCEEDED"
    OUTSIDE_VALID_PERIOD = "OUTSIDE_VALID_PERIOD"
    ENVIRONMENT_NOT_ALLOWED = "ENVIRONMENT_NOT_ALLOWED"
    DATA_CLASSIFICATION_DENIED = "DATA_CLASSIFICATION_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    POLICY_HOOK_DENIED = "POLICY_HOOK_DENIED"
