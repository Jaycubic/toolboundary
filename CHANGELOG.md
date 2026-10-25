# Changelog

All notable changes to ToolBoundary are documented here.

## [1.0.4] - Unreleased

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
