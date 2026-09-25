# Changelog

All notable changes to ToolBoundary are documented here.

## [0.1.0] — Initial Public Alpha

### Added
- Local runtime policy boundary for AI agents and LLM tool-calling workflows.
- Tool permissions and access modes.
- Operation blocklists.
- Transaction value and record-count ceilings.
- Global and per-tool rate limits.
- Autonomy-level controls.
- Time-bounded validity windows.
- Environment restrictions.
- Custom policy hooks.
- Emergency kill switch.
- Structured audit trail with logging, JSONL, and webhook sinks.
- `@guarded_tool` decorator.
- LangChain `BaseTool` integration.
- Network/token enforcement modules.
- Public API documentation.

### Project Status
ToolBoundary is an application-layer security library. It is intentionally not a network firewall, credential-management system, or centralized enterprise AI governance platform.
