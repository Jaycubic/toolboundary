# AI Agent Security with ToolBoundary

ToolBoundary is a Python library for enforcing security policy at the runtime boundary where an AI agent or LLM workflow invokes a tool.

## The Problem

LLM agents can select tools dynamically. A model may be allowed to read data but should not necessarily be allowed to delete records, transfer large amounts, access production systems, or execute unlimited actions.

A prompt or system instruction is not the same thing as an enforceable runtime policy. ToolBoundary places a local policy check in the tool-execution path.

## Runtime Enforcement

```text
LLM / Agent
    |
    v
Tool Call
    |
    v
ToolBoundary
    |
    +---- permission / access mode
    +---- value / record limits
    +---- rate limit
    +---- autonomy level
    +---- environment restriction
    +---- custom policy hooks
    +---- emergency kill switch
    |
    +---- ALLOW --------------> tool executes
    +---- DENY ----------------> BoundaryViolation
    +---- APPROVAL REQUIRED ---> external approval flow
```

## AI Agent Guardrails

ToolBoundary can act as a local guardrail for:

- LLM tool calling
- autonomous agents
- support agents
- data-analysis agents
- workflow agents
- internal developer agents
- automation bots
- LangChain-based agents
- LangGraph-based agents

## Least-Privilege Agent Authorization

Permissions can be defined per tool and per access mode. A developer can make a tool read-only, restrict destructive operations, limit transaction value, or constrain the number of records affected.

## Human Approval

A policy can require approval for sensitive actions. The boundary can raise `ApprovalRequired` instead of allowing the action to continue automatically.

## Rate Limiting

Global and per-tool rate limits can reduce the impact of runaway or repeatedly invoked tools. The default limiter is process-local; distributed applications may use a shared backend when global coordination is required.

## Emergency Kill Switch

The configured kill-switch environment variable can deny future calls for an agent immediately. This provides a simple operational stop mechanism without requiring a separate control service.

## Auditability

Every decision can produce structured audit information. Developers can route those events into existing logging infrastructure or optional JSONL and webhook sinks.

## LangChain

ToolBoundary provides a LangChain adapter that wraps the tool objects used by the execution framework. This keeps the security check at the tool boundary rather than relying on the model's reasoning process to remember to invoke a separate policy function.

## LangGraph

ToolBoundary provides a LangGraph adapter that returns an already-guarded `ToolNode`, built on the same tool-wrapping as the LangChain adapter, so a compiled graph's tool-calling node enforces the policy without extra wiring.

## What ToolBoundary Does Not Provide

ToolBoundary is deliberately narrow:

- It does not provide a network firewall.
- It does not replace API-key or database credential scoping.
- It does not guarantee protection against code paths that bypass the library completely.
- It is not a centralized enterprise AI governance registry.

For stronger security, combine the library with identity controls, scoped credentials, network egress controls, workload isolation, and monitoring appropriate to the threat model.

## Related Topics

AI agent security, LLM security, tool-calling security, AI guardrails, agent authorization, least-privilege AI agents, runtime policy enforcement, human-in-the-loop AI, LangChain security, LangGraph security, Python AI security, autonomous agent controls, and application-layer AI security.
