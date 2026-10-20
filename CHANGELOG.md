# Changelog

All notable changes to ToolBoundary are documented here.

## [1.0.3] - Unreleased

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
