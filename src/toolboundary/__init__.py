"""
ToolBoundary
============
Runtime boundary enforcement for AI agents -- as a library, not a service.

ToolBoundary answers one question, fast and locally, every time an agent
tries to call a tool: "is this exact call allowed, right now?" It is
designed for the common case of one to a handful of agents built by a
single team, where standing up a separate governance web application and
database would be disproportionate overhead.

Quickstart
----------
>>> from toolboundary import Boundary, ToolPermission, AutonomyLevel, AccessMode
>>>
>>> boundary = Boundary(
...     agent_name="support-agent",
...     autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
...     permissions=[
...         ToolPermission("read_ticket_db", access_mode=AccessMode.READ_ONLY),
...         ToolPermission(
...             "send_reply_email",
...             access_mode=AccessMode.EXECUTE,
...             max_calls_per_hour=30,
...         ),
...     ],
...     blocked_operations=frozenset({"delete_ticket"}),
...     max_actions_per_hour=100,
...     kill_switch_env="TOOLBOUNDARY_KILL_SWITCH",
... )
>>>
>>> boundary.check("read_ticket_db", access_mode=AccessMode.READ_ONLY)  # passes silently
>>> boundary.check("delete_ticket", operation="delete_ticket")  # raises BoundaryViolation

For a decorator-based approach, see `toolboundary.guarded_tool`.
For LangChain, see `toolboundary.integrations.langchain`.
"""

from .audit import AuditEvent, AuditTrail, JSONLFileSink, LoggingSink, WebhookSink
from .boundary import Boundary, CallContext
from .decorators import guarded_tool
from .enums import AccessMode, AutonomyLevel, DecisionType, ViolationReason
from .exceptions import (
    ApprovalRequired,
    BoundaryViolation,
    ConfigurationError,
    KillSwitchActive,
    RateLimitExceeded,
    ToolBoundaryError,
)
from .permissions import ToolPermission

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # core
    "Boundary",
    "CallContext",
    "ToolPermission",
    "guarded_tool",
    # enums
    "AccessMode",
    "AutonomyLevel",
    "DecisionType",
    "ViolationReason",
    # exceptions
    "ToolBoundaryError",
    "BoundaryViolation",
    "KillSwitchActive",
    "RateLimitExceeded",
    "ApprovalRequired",
    "ConfigurationError",
    # audit
    "AuditTrail",
    "AuditEvent",
    "LoggingSink",
    "JSONLFileSink",
    "WebhookSink",
]
