# Changelog

All notable changes to ToolBoundary are documented here.

## [1.1.0] - 2026-11-10

### Added

- Add `toolboundary.gateway`, a policy gateway that runs outside the agent's process. Agents
  authenticate with a key and cannot create their own approvals.
- Add `GatewayRule`, which denies by default and reads operation, access mode, value and
  record count from the request being forwarded instead of from agent claims.
- Add gateway-held upstream credentials, so agents never need them.
- Add `GatewayClient` for agents, and `python -m toolboundary.gateway` for running a gateway
  in its own process.
- Add `docs/GATEWAY.md` and `examples/policy_gateway.py`.

### Changed

- Guarding a tool without `access_mode` now raises `FutureWarning`. It still falls back to
  `READ_ONLY`, and `access_mode` will be required in ToolBoundary 2.0.
- `strict_limits=True` now also requires a value when a tool has only a `min_value`.

### Fixed

- Correct documentation that implied token request binding stops a compromised agent from
  declaring a false value. It only stops a request being changed after approval.
- Reject oversized `Content-Length` header values cleanly in the network proxy.

## [1.0.5] - 2026-11-10

### Security

- Add `kill_switch_file`, which halts an already-running agent and fails closed if it
  cannot be checked. Correct documentation that claimed an environment variable could do this.
- `AgentKeyProvider` no longer allows every call when no client is configured. Simulation
  now requires `simulate=True`, and simulated grants and receipts are labelled.
- Proxy tokens carry the call's access mode, and read-only tokens cannot use write methods.
- Add optional token binding to the exact method, path and body, plus
  `UpstreamRoute.require_request_binding` and `UpstreamRoute.required_agent`.
- Enforce value and record limits for positional LangChain input and `**kwargs` functions.
- Stop following upstream redirects, which could send credentials to another host.
- Match blocked operations regardless of case, surrounding spaces, or character width.
- Redact nested secrets, bearer values and more credential names from audit metadata.
- Stop sending secret-named arguments to providers while the call digest still binds them.
- Require a `langchain-core` release patched for CVE-2025-68664.
- Pin GitHub Actions to commit SHAs and build packages outside the publishing job.

### Fixed

- Record the real outcome of async `@guarded_tool` functions.
- Bind positional LangChain arguments into the call digest.
- Audit enforced provider denials and outages as `DENY`.
- Return 403 and call `on_denied` for tokens with malformed signatures or claims.
- Make `InMemoryTokenStore` thread-safe.
- Bound AgentKey pending-call retention.
- Limit proxy response size and idle connections, and send one `Content-Length`.
- Stop forwarding hop-by-hop headers to upstreams.
- Make `guard_tool` work with LangChain `@tool` functions.
- Report `recorded=False` when an AgentKey client has no `record()` method.

### Changed

- `AgentKeyProvider()` without a client now raises `ConfigurationError`.
- Proxy write methods require a token with `WRITE` access or higher.
- `Boundary` logs a warning when a provider runs in `ProviderMode.OBSERVE`.

## [1.0.4] - 2026-10-25

### Added

- Add an optional CrewAI adapter with `guard_tool` and `guard_tools`.
- Enforce ToolBoundary authorization in CrewAI's synchronous `_run` and asynchronous
  `_arun` execution paths, including structured-tool invocation.
- Normalize positional arguments against the wrapped tool's signature before evaluating
  configured value and record-count limits.
- Support ToolBoundary's provider authorization and execution-evidence lifecycle for
  CrewAI tool calls when a provider is configured.
- Add CrewAI integration tests for allowed and denied calls, value limits, async calls,
  multiple tools, structured-tool invocation, positional arguments, and provider evidence.

## [1.0.3] - 2026-10-20

### Security

- Prevent client-controlled paths from changing the configured network proxy upstream
  authority; reject traversal and malformed paths.
- Limit network proxy request body size and reject invalid `Content-Length` values.
- Redact common sensitive argument names from decorator-generated audit metadata.

### Fixed

- Deny calls that omit an operation when a tool has an `allowed_operations` allow-list.
- Validate values and record counts before applying configured ceilings; support
  optional minimum values and strict checks for omitted values.
- Preserve the configured decorator operation when the wrapped function's
  `operation` argument is `None`.
- Record a successful `None` tool result as a success rather than an unknown outcome.

## [1.0.2]

- Added provider-neutral authorization and execution evidence, the ToolBoundary-side
  AgentKey reference integration, and optional Redis shared backends.
