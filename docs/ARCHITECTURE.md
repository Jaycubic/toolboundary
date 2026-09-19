# ToolBoundary Architecture

ToolBoundary is a local, application-layer policy boundary for AI agents and LLM tool-calling workflows.

## Core Flow

```text
LLM / Agent
    |
    v
Tool Invocation
    |
    v
ToolBoundary Policy Check
    |
    +--> ALLOW --------------> Tool implementation
    +--> DENY ----------------> BoundaryViolation
    +--> APPROVAL REQUIRED ---> Caller / human workflow
```

## Policy Layer

A `Boundary` can evaluate tool identity, access mode, value limits, record limits, rate limits, autonomy level, validity windows, environment restrictions, custom policy hooks, and an emergency kill switch before the guarded operation executes.

## Audit Layer

Each decision produces a structured audit event. The core path can use Python logging, JSONL files, or an optional webhook sink. Audit delivery is best-effort and does not determine whether an operation is allowed.

## Framework Integration

The core package is dependency-free. Framework-specific adapters are optional. The repository currently documents LangChain `BaseTool` wrapping.

## Security Boundary

ToolBoundary protects calls routed through the boundary. It is not a network firewall and does not replace scoped credentials, operating-system permissions, network egress controls, or workload isolation.

## Design Principles

- Fail closed by default.
- Keep the core dependency-free.
- Keep policy version-controlled with application code.
- Raise explicit exceptions for denied actions.
- Keep framework integrations optional.
- Make policy decisions observable through structured audit events.
