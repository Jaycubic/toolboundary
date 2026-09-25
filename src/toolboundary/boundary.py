"""
toolboundary.boundary
----------------------
The Boundary class is the policy itself: what an agent is allowed to do,
declared as plain Python at construction time (version-controlled with
your code, no separate service or database required).

A Boundary is evaluated on every governed tool call via `.check(...)`,
which either returns silently (allowed), raises BoundaryViolation (denied),
or raises ApprovalRequired (needs a human).

When an optional ``EvidenceProvider`` is configured, the boundary also
orchestrates external authorization and execution recording through
``authorize_call()`` and ``record_execution()``.  The provider can never
turn a local deny into an allow.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .tokens import AuthorizationToken

from ._rate_limiter import SlidingWindowRateLimiter
from .audit import AuditTrail
from .enums import AccessMode, AutonomyLevel, DecisionType, ViolationReason
from .evidence import build_execution_record, freeze_with_digest
from .exceptions import (
    ApprovalRequired,
    AuthorizationConsumed,
    BoundaryViolation,
    ConfigurationError,
    KillSwitchActive,
    ProviderAuthorizationDenied,
    ProviderUnavailable,
    RateLimitExceeded,
)
from .permissions import ToolPermission
from .provider import (
    AuthorizationContext,
    EvidenceProvider,
    ExecutionRecord,
    FrozenToolCall,
    LocalDecision,
    ProviderGrant,
    ProviderMode,
    ProviderReceipt,
)

_logger = logging.getLogger("toolboundary.boundary")

# TokenIssuer/AuthorizationToken are imported lazily inside the method that
# needs them (see `check_and_authorize`) so that importing `toolboundary.boundary`
# -- and therefore `toolboundary` itself -- never requires touching the network
# enforcement module. Network enforcement stays fully optional and adds zero
# import cost for users who never enable it.

PolicyHook = Callable[["CallContext"], Optional[str]]
"""
A policy hook receives the CallContext for a prospective tool call and
returns None to allow it, or a string reason to deny it. This is the
extension point for custom logic (e.g. "no calls between midnight and 6am",
or calling out to an external policy engine / GuardianIQ-style registry).
"""


@dataclass(frozen=True)
class CallContext:
    """Everything ToolBoundary knows about one prospective tool call."""

    agent_name: str
    tool_name: str
    operation: str | None = None
    access_mode: AccessMode = AccessMode.READ_ONLY
    value: float | None = None
    record_count: int | None = None
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Boundary:
    """
    Declares the maximum autonomy of a single agent.

    Example
    -------
    >>> boundary = Boundary(
    ...     agent_name="quote-agent",
    ...     autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
    ...     permissions=[
    ...         ToolPermission("read_customer_db", access_mode=AccessMode.READ_ONLY),
    ...         ToolPermission(
    ...             "send_email",
    ...             access_mode=AccessMode.EXECUTE,
    ...             requires_approval=True,
    ...         ),
    ...     ],
    ...     blocked_operations=frozenset({"delete_customer", "drop_table"}),
    ...     max_actions_per_hour=60,
    ...     kill_switch_env="TOOLBOUNDARY_KILL_SWITCH",
    ... )
    """

    def __init__(
        self,
        agent_name: str,
        *,
        autonomy: AutonomyLevel = AutonomyLevel.HUMAN_APPROVAL_REQUIRED,
        permissions: list[ToolPermission] | None = None,
        blocked_operations: frozenset[str] = frozenset(),
        allowed_environments: frozenset[str] | None = None,
        environment: str = "PRODUCTION",
        max_actions_per_hour: int | None = None,
        kill_switch: bool = False,
        kill_switch_env: str | None = None,
        valid_from: float | None = None,
        valid_to: float | None = None,
        audit: AuditTrail | None = None,
        policy_hooks: list[PolicyHook] | None = None,
        fail_closed_on_hook_error: bool = True,
        token_issuer: Any | None = None,
        # -- optional provider configuration --
        provider: EvidenceProvider | None = None,
        provider_mode: ProviderMode = ProviderMode.OBSERVE,
        policy_version: str | None = None,
    ) -> None:
        if not agent_name:
            raise ConfigurationError("Boundary requires a non-empty agent_name.")

        self.agent_name = agent_name
        self.autonomy = autonomy
        self._permissions: dict[str, ToolPermission] = {
            p.tool_name: p for p in (permissions or [])
        }
        self.blocked_operations = blocked_operations
        self.allowed_environments = allowed_environments
        self.environment = environment
        self.max_actions_per_hour = max_actions_per_hour
        self._kill_switch = kill_switch
        self._kill_switch_env = kill_switch_env
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.audit = audit or AuditTrail()
        self.policy_hooks: list[PolicyHook] = policy_hooks or []
        self.fail_closed_on_hook_error = fail_closed_on_hook_error

        self._rate_limiter = SlidingWindowRateLimiter()

        # Optional: only set if the caller wants network-layer enforcement.
        # See `toolboundary.network` -- this is never required and never
        # imported unless a token_issuer is explicitly passed in.
        self._token_issuer = token_issuer

        # Optional: external authorization/evidence provider.
        self._provider = provider
        self._provider_mode = provider_mode
        self._policy_version = policy_version

    # -- kill switch -----------------------------------------------------

    @property
    def kill_switch_engaged(self) -> bool:
        """
        Kill switch is engaged if either the in-memory flag is True, or the
        configured environment variable is set to a truthy value.

        Checking an environment variable on every call (rather than only at
        construction time) means an operator can halt a running agent by
        setting the env var externally, without restarting the process --
        e.g. `export TOOLBOUNDARY_KILL_SWITCH=1` picked up on the next call.
        """
        if self._kill_switch:
            return True
        if self._kill_switch_env:
            val = os.environ.get(self._kill_switch_env, "")
            return val.strip().lower() in {"1", "true", "yes", "on"}
        return False

    def engage_kill_switch(self) -> None:
        """Programmatically halt this boundary immediately for all future calls."""
        self._kill_switch = True

    def disengage_kill_switch(self) -> None:
        self._kill_switch = False

    # -- permission management --------------------------------------------

    def add_permission(self, permission: ToolPermission) -> None:
        self._permissions[permission.tool_name] = permission

    def get_permission(self, tool_name: str) -> ToolPermission | None:
        return self._permissions.get(tool_name)

    # -- structured local evaluation ---------------------------------------

    def evaluate(
        self,
        tool_name: str,
        *,
        operation: str | None = None,
        access_mode: AccessMode = AccessMode.READ_ONLY,
        value: float | None = None,
        record_count: int | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LocalDecision:
        """Evaluate local policy and return a structured LocalDecision.

        Unlike ``check()``, this method never raises on deny — it returns
        a ``LocalDecision`` with ``decision="DENY"`` or
        ``decision="APPROVAL_REQUIRED"`` instead. This makes it suitable
        for use by the provider orchestration flow.

        Returns
        -------
        LocalDecision
            Always returned, never raised as an exception.
        """
        ctx = CallContext(
            agent_name=self.agent_name,
            tool_name=tool_name,
            operation=operation,
            access_mode=access_mode,
            value=value,
            record_count=record_count,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )
        decision_id = str(uuid.uuid4())

        try:
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
            self._check_rate_limit(ctx)
            self._check_policy_hooks(ctx)
            self._check_requires_approval(ctx, permission)
        except ApprovalRequired as exc:
            return LocalDecision(
                decision=DecisionType.APPROVAL_REQUIRED.value,
                decision_id=decision_id,
                agent_name=self.agent_name,
                tool_name=tool_name,
                operation=operation,
                reason_code=ViolationReason.APPROVAL_REQUIRED.value,
                approval_id=getattr(exc, "approval_id", None),
                policy_version=self._policy_version,
            )
        except BoundaryViolation as exc:
            return LocalDecision(
                decision=DecisionType.DENY.value,
                decision_id=decision_id,
                agent_name=self.agent_name,
                tool_name=tool_name,
                operation=operation,
                reason_code=exc.rule,
                policy_version=self._policy_version,
            )
        else:
            return LocalDecision(
                decision=DecisionType.ALLOW.value,
                decision_id=decision_id,
                agent_name=self.agent_name,
                tool_name=tool_name,
                operation=operation,
                policy_version=self._policy_version,
            )

    # -- the core decision function ----------------------------------------

    def check(
        self,
        tool_name: str,
        *,
        operation: str | None = None,
        access_mode: AccessMode = AccessMode.READ_ONLY,
        value: float | None = None,
        record_count: int | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Evaluate whether the described tool call is allowed.

        Raises
        ------
        KillSwitchActive, RateLimitExceeded, BoundaryViolation
            If the call is denied for any reason.
        ApprovalRequired
            If the call needs a human before it can proceed.

        Returns
        -------
        None
            Silently, if and only if the call is allowed outright.
        """
        ctx = CallContext(
            agent_name=self.agent_name,
            tool_name=tool_name,
            operation=operation,
            access_mode=access_mode,
            value=value,
            record_count=record_count,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )

        try:
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
            self._check_rate_limit(ctx)
            self._check_policy_hooks(ctx)
            self._check_requires_approval(ctx, permission)
        except ApprovalRequired as exc:
            self.audit.record(
                agent_name=self.agent_name,
                decision="APPROVAL_REQUIRED",
                message=str(exc),
                tool_name=tool_name,
                operation=operation,
                access_mode=access_mode.value,
                reason_code=ViolationReason.APPROVAL_REQUIRED.value,
                correlation_id=correlation_id,
                metadata=metadata,
            )
            raise
        except BoundaryViolation as exc:
            self.audit.record(
                agent_name=self.agent_name,
                decision="DENY",
                message=str(exc),
                tool_name=tool_name,
                operation=operation,
                access_mode=access_mode.value,
                reason_code=exc.rule,
                correlation_id=correlation_id,
                metadata=metadata,
            )
            raise
        else:
            self.audit.record(
                agent_name=self.agent_name,
                decision="ALLOW",
                message=f"{tool_name}.{operation or '*'} allowed",
                tool_name=tool_name,
                operation=operation,
                access_mode=access_mode.value,
                reason_code=None,
                correlation_id=correlation_id,
                metadata=metadata,
            )

    def check_and_authorize(
        self,
        tool_name: str,
        *,
        operation: str | None = None,
        access_mode: AccessMode = AccessMode.READ_ONLY,
        value: float | None = None,
        record_count: int | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuthorizationToken:
        """
        Like `check()`, but additionally issues a short-lived
        AuthorizationToken on ALLOW, for use with the optional
        `toolboundary.network` enforcement proxy.

        Requires a `token_issuer` to have been passed to this Boundary's
        constructor (an `toolboundary.tokens.TokenIssuer`). Raises
        ConfigurationError if none was configured -- this keeps the
        network-enforcement path entirely opt-in: calling plain `check()`
        never requires a token_issuer, and calling this method without one
        configured fails loudly rather than silently returning an
        unusable token.

        The returned token authorizes exactly this (agent_name, tool_name,
        operation) tuple for a short window (default 30s) and exactly one
        use -- see `toolboundary.tokens.TokenIssuer` for details.
        """
        if self._token_issuer is None:
            raise ConfigurationError(
                "check_and_authorize() requires a token_issuer to be configured "
                "on this Boundary. Pass token_issuer=TokenIssuer(...) when "
                "constructing it, or use plain check() if you don't need "
                "network-layer enforcement."
            )

        # Run the exact same evaluation as check(); raises on denial.
        self.check(
            tool_name,
            operation=operation,
            access_mode=access_mode,
            value=value,
            record_count=record_count,
            correlation_id=correlation_id,
            metadata=metadata,
        )

        return self._token_issuer.issue(
            agent_name=self.agent_name,
            tool_name=tool_name,
            operation=operation,
        )

    # -- provider-aware authorization flow ---------------------------------

    def authorize_call(
        self,
        *,
        tool_name: str,
        operation: str | None = None,
        access_mode: AccessMode = AccessMode.READ_ONLY,
        arguments: dict[str, Any],
        value: float | None = None,
        record_count: int | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        resource: str | None = None,
        tool_version: str | None = None,
        schema_hash: str | None = None,
        manifest_hash: str | None = None,
        approval_id: str | None = None,
        approval_state: str | None = None,
    ) -> AuthorizationContext:
        """Evaluate locally, freeze the call, and optionally consult a provider.

        This is the single orchestration entry point that both decorator-based
        and framework-based integrations should call. It:

        1. Evaluates ToolBoundary locally (via ``evaluate()``).
        2. Stops immediately on local deny (raises the original exception).
        3. Builds a ``FrozenToolCall`` with the exact resolved arguments.
        4. Computes the call digest.
        5. If no provider exists, returns an ``AuthorizationContext`` allowing
           local execution.
        6. If a provider exists, calls ``provider.authorize(...)``.
        7. Never lets provider ALLOW override a local deny.
        8. Respects observe/enforce mode.

        Does NOT execute the actual tool. Returns authorization for the
        exact call only.

        Raises
        ------
        BoundaryViolation, KillSwitchActive, RateLimitExceeded, ApprovalRequired
            On local deny (same as ``check()``).
        ProviderAuthorizationDenied
            In enforce mode, when the provider explicitly denies.
        ProviderUnavailable
            In enforce mode, when the provider cannot be reached.
        """
        # Step 1: Local evaluation — raises on deny to preserve existing semantics.
        self.check(
            tool_name,
            operation=operation,
            access_mode=access_mode,
            value=value,
            record_count=record_count,
            correlation_id=correlation_id,
            metadata=metadata,
        )

        # Step 2: Build structured local decision (for provider communication).
        local_decision = LocalDecision(
            decision=DecisionType.ALLOW.value,
            decision_id=str(uuid.uuid4()),
            agent_name=self.agent_name,
            tool_name=tool_name,
            operation=operation,
            policy_version=self._policy_version,
        )

        # Step 3: Freeze the exact call.
        frozen = FrozenToolCall(
            agent_name=self.agent_name,
            tool_name=tool_name,
            operation=operation,
            arguments=arguments,
            resource=resource,
            tool_version=tool_version,
            schema_hash=schema_hash,
            manifest_hash=manifest_hash,
            approval_id=approval_id,
            approval_state=approval_state,
        )

        # Step 4: Compute digest and bind it.
        frozen = freeze_with_digest(frozen)

        # Step 5: No provider → local-only authorization.
        if self._provider is None:
            return AuthorizationContext(
                local_decision=local_decision,
                frozen_call=frozen,
                provider_grant=None,
            )

        # Step 6: Consult the provider.
        provider_grant: ProviderGrant | None = None
        try:
            provider_grant = self._provider.authorize(frozen, local_decision)
        except Exception as exc:  # noqa: BLE001
            if self._provider_mode == ProviderMode.ENFORCE:
                raise ProviderUnavailable(
                    f"Provider unavailable in enforce mode: {exc}",
                    agent_name=self.agent_name,
                    tool_name=tool_name,
                    operation=operation,
                ) from exc
            else:
                # Observe mode: log and proceed without provider evidence.
                _logger.warning(
                    "Provider unavailable in observe mode; proceeding without "
                    "external authorization: %s",
                    exc,
                )
                provider_grant = ProviderGrant(
                    allowed=True,
                    provider="unavailable",
                    reason=f"Provider unavailable (observe mode): {exc}",
                    metadata={"evidence_degraded": True},
                )

        # Step 7: Provider deny handling.
        if provider_grant is not None and not provider_grant.allowed:
            if self._provider_mode == ProviderMode.ENFORCE:
                raise ProviderAuthorizationDenied(
                    f"Provider denied the action: {provider_grant.reason}",
                    agent_name=self.agent_name,
                    tool_name=tool_name,
                    operation=operation,
                    provider=provider_grant.provider,
                    reason=provider_grant.reason,
                )
            else:
                # Observe mode: log the denial but proceed.
                _logger.warning(
                    "Provider denied action in observe mode (proceeding): %s",
                    provider_grant.reason,
                )

        # Step 8: Emit audit event with provider metadata.
        evidence_metadata = dict(metadata or {})
        evidence_metadata["call_digest"] = frozen.call_digest
        evidence_metadata["decision_id"] = local_decision.decision_id
        if provider_grant is not None:
            evidence_metadata["provider"] = provider_grant.provider
            evidence_metadata["provider_decision"] = (
                "allow" if provider_grant.allowed else "deny"
            )
            if provider_grant.attempt_id:
                evidence_metadata["attempt_id"] = provider_grant.attempt_id
            if provider_grant.authorization_id:
                evidence_metadata["authorization_id"] = provider_grant.authorization_id

        self.audit.record(
            agent_name=self.agent_name,
            decision="ALLOW",
            message=f"{tool_name}.{operation or '*'} authorized (provider: "
            f"{provider_grant.provider if provider_grant else 'none'})",
            tool_name=tool_name,
            operation=operation,
            access_mode=access_mode.value,
            correlation_id=correlation_id,
            metadata=evidence_metadata,
        )

        return AuthorizationContext(
            local_decision=local_decision,
            frozen_call=frozen,
            provider_grant=provider_grant,
        )

    def record_execution(
        self,
        authorization: AuthorizationContext,
        *,
        result: Any = None,
        error: BaseException | None = None,
        started_at: float,
        finished_at: float,
        correlation_id: str | None = None,
    ) -> ProviderReceipt | None:
        """Record execution evidence after the tool has been dispatched.

        Must be called with the same ``AuthorizationContext`` returned by
        ``authorize_call()``. Marks the authorization as consumed to prevent
        reuse.

        Parameters
        ----------
        authorization:
            The context from ``authorize_call()``.
        result:
            The tool's return value (on success).
        error:
            The exception raised by the tool (on failure).
        started_at / finished_at:
            Timestamps bounding execution.
        correlation_id:
            Optional correlation ID for audit.

        Returns
        -------
        ProviderReceipt or None
            Receipt from the provider if one was configured, else None.

        Raises
        ------
        AuthorizationConsumed
            If the authorization has already been used.
        """
        if authorization.consumed:
            raise AuthorizationConsumed(
                "This authorization has already been consumed and cannot be reused."
            )

        authorization.mark_consumed()

        execution = build_execution_record(
            call_digest=authorization.frozen_call.call_digest,
            started_at=started_at,
            finished_at=finished_at,
            result=result,
            error=error,
        )

        # Audit the execution outcome locally.
        exec_metadata: dict[str, Any] = {
            "call_digest": authorization.frozen_call.call_digest,
            "decision_id": authorization.local_decision.decision_id,
            "execution_status": execution.status,
        }
        if execution.result_digest:
            exec_metadata["result_digest"] = execution.result_digest
        if authorization.provider_grant:
            exec_metadata["provider"] = authorization.provider_grant.provider

        self.audit.record(
            agent_name=self.agent_name,
            decision="ALLOW",
            message=f"Execution recorded: {execution.status}",
            tool_name=authorization.frozen_call.tool_name,
            operation=authorization.frozen_call.operation,
            correlation_id=correlation_id,
            metadata=exec_metadata,
        )

        # Record with provider (if configured).
        if self._provider is not None and authorization.provider_grant is not None:
            try:
                receipt = self._provider.record(authorization.provider_grant, execution)
                return receipt
            except Exception as exc:  # noqa: BLE001
                # Post-dispatch provider failure cannot erase the local execution record.
                _logger.warning(
                    "Provider failed to record execution evidence (local record preserved): %s",
                    exc,
                )
                return ProviderReceipt(
                    recorded=False,
                    provider=authorization.provider_grant.provider,
                    metadata={"error": str(exc)},
                )

        return None

    # -- individual checks (each raises on failure) -------------------------

    def _check_kill_switch(self, ctx: CallContext) -> None:
        if self.kill_switch_engaged:
            raise KillSwitchActive(
                "Kill switch is engaged; all actions are denied.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.KILL_SWITCH_ACTIVE.value,
            )

    def _check_quarantine(self, ctx: CallContext) -> None:
        if self.autonomy == AutonomyLevel.QUARANTINED:
            raise BoundaryViolation(
                "Agent is quarantined; all governed actions are denied.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.AGENT_QUARANTINED.value,
            )

    def _check_validity_window(self, ctx: CallContext) -> None:
        now = time.time()
        if self.valid_from is not None and now < self.valid_from:
            raise BoundaryViolation(
                "Boundary is not yet valid (before valid_from).",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                rule=ViolationReason.OUTSIDE_VALID_PERIOD.value,
            )
        if self.valid_to is not None and now > self.valid_to:
            raise BoundaryViolation(
                "Boundary has expired (after valid_to).",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                rule=ViolationReason.OUTSIDE_VALID_PERIOD.value,
            )

    def _check_environment(self, ctx: CallContext) -> None:
        if (
            self.allowed_environments is not None
            and self.environment not in self.allowed_environments
        ):
            raise BoundaryViolation(
                f"Environment {self.environment!r} is not in allowed_environments.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                rule=ViolationReason.ENVIRONMENT_NOT_ALLOWED.value,
            )

    def _check_global_blocked_operations(self, ctx: CallContext) -> None:
        if ctx.operation is not None and ctx.operation in self.blocked_operations:
            raise BoundaryViolation(
                f"Operation {ctx.operation!r} is globally blocked for this agent.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.OPERATION_BLOCKED.value,
            )

    def _check_tool_permission(self, ctx: CallContext) -> ToolPermission:
        permission = self._permissions.get(ctx.tool_name)
        if permission is None:
            raise BoundaryViolation(
                f"Tool {ctx.tool_name!r} is not in this agent's permitted tool list.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                rule=ViolationReason.TOOL_NOT_ALLOWED.value,
            )
        return permission

    def _check_operation(self, ctx: CallContext, permission: ToolPermission) -> None:
        if not permission.operation_allowed(ctx.operation):
            raise BoundaryViolation(
                f"Operation {ctx.operation!r} is not allowed for tool {ctx.tool_name!r}.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.OPERATION_BLOCKED.value,
            )

    def _check_access_mode(self, ctx: CallContext, permission: ToolPermission) -> None:
        rank = {
            AccessMode.READ_ONLY: 0,
            AccessMode.WRITE: 1,
            AccessMode.EXECUTE: 2,
            AccessMode.ADMIN: 3,
        }
        if rank[ctx.access_mode] > rank[permission.access_mode]:
            raise BoundaryViolation(
                f"Requested access_mode {ctx.access_mode.value} exceeds granted "
                f"{permission.access_mode.value} for tool {ctx.tool_name!r}.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.ACCESS_MODE_EXCEEDED.value,
            )

    def _check_value_limit(self, ctx: CallContext, permission: ToolPermission) -> None:
        if (
            ctx.value is not None
            and permission.max_value is not None
            and ctx.value > permission.max_value
        ):
            raise BoundaryViolation(
                f"Value {ctx.value} exceeds max_value {permission.max_value} "
                f"for tool {ctx.tool_name!r}.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.MAX_VALUE_EXCEEDED.value,
            )

    def _check_record_limit(self, ctx: CallContext, permission: ToolPermission) -> None:
        if (
            ctx.record_count is not None
            and permission.max_records is not None
            and ctx.record_count > permission.max_records
        ):
            raise BoundaryViolation(
                f"record_count {ctx.record_count} exceeds max_records {permission.max_records} "
                f"for tool {ctx.tool_name!r}.",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
                rule=ViolationReason.MAX_RECORDS_EXCEEDED.value,
            )

    def _check_rate_limit(self, ctx: CallContext) -> None:
        permission = self._permissions.get(ctx.tool_name)

        if self.max_actions_per_hour is not None:
            key = f"{self.agent_name}::__global__"
            if not self._rate_limiter.check_and_record(key, self.max_actions_per_hour, 3600):
                raise RateLimitExceeded(
                    f"Agent exceeded global limit of {self.max_actions_per_hour} actions/hour.",
                    agent_name=ctx.agent_name,
                    tool_name=ctx.tool_name,
                    rule=ViolationReason.RATE_LIMIT_EXCEEDED.value,
                )

        if permission is not None and permission.max_calls_per_hour is not None:
            key = f"{self.agent_name}::{ctx.tool_name}"
            if not self._rate_limiter.check_and_record(key, permission.max_calls_per_hour, 3600):
                raise RateLimitExceeded(
                    f"Tool {ctx.tool_name!r} exceeded limit of "
                    f"{permission.max_calls_per_hour} calls/hour for this agent.",
                    agent_name=ctx.agent_name,
                    tool_name=ctx.tool_name,
                    rule=ViolationReason.RATE_LIMIT_EXCEEDED.value,
                )

    def _check_policy_hooks(self, ctx: CallContext) -> None:
        for hook in self.policy_hooks:
            try:
                denial_reason = hook(ctx)
            except Exception as exc:  # noqa: BLE001
                if self.fail_closed_on_hook_error:
                    raise BoundaryViolation(
                        f"Policy hook {hook!r} raised an error; failing closed: {exc}",
                        agent_name=ctx.agent_name,
                        tool_name=ctx.tool_name,
                        operation=ctx.operation,
                        rule=ViolationReason.POLICY_HOOK_DENIED.value,
                    ) from exc
                continue
            if denial_reason:
                raise BoundaryViolation(
                    denial_reason,
                    agent_name=ctx.agent_name,
                    tool_name=ctx.tool_name,
                    operation=ctx.operation,
                    rule=ViolationReason.POLICY_HOOK_DENIED.value,
                )

    def _check_requires_approval(self, ctx: CallContext, permission: ToolPermission) -> None:
        needs_approval = (
            permission.requires_approval
            or self.autonomy == AutonomyLevel.HUMAN_APPROVAL_REQUIRED
            or (
                self.autonomy == AutonomyLevel.RECOMMEND_ONLY
                and ctx.access_mode != AccessMode.READ_ONLY
            )
        )
        if needs_approval:
            raise ApprovalRequired(
                f"{ctx.tool_name}.{ctx.operation or '*'} requires human approval "
                f"(autonomy={self.autonomy.value}).",
                agent_name=ctx.agent_name,
                tool_name=ctx.tool_name,
                operation=ctx.operation,
            )
