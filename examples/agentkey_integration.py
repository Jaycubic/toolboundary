"""
examples/agentkey_integration.py
--------------------------------
Runnable example showing ToolBoundary × AgentKey integration.

Flow:
1. ToolBoundary evaluates local policy (tool permitted, access mode, autonomy).
2. On local ALLOW, call is frozen with deterministic SHA-256 call digest.
3. AgentKeyProvider evaluates external authorization in ENFORCE mode.
4. Tool executes safely.
5. Post-dispatch execution evidence is recorded with AgentKey session correlation.
"""

from __future__ import annotations

from toolboundary import (
    AccessMode,
    AutonomyLevel,
    Boundary,
    ProviderMode,
    ToolPermission,
    guarded_tool,
)
from toolboundary.integrations.agentkey import AgentKeyProvider

# In production, pass an authenticated AgentKey client:
#   provider = AgentKeyProvider(client=agentkey_client)
# Without arguments, AgentKeyProvider runs in standalone simulated mode
# for local demos and development without external network credentials.
provider = AgentKeyProvider()

boundary = Boundary(
    agent_name="agentkey-demo",
    autonomy=AutonomyLevel.AUTONOMOUS,
    permissions=[
        ToolPermission(
            "read_ticket",
            access_mode=AccessMode.READ_ONLY,
        ),
    ],
    provider=provider,
    provider_mode=ProviderMode.ENFORCE,
    policy_version="demo-v1",
)


@guarded_tool(
    boundary,
    tool_name="read_ticket",
    access_mode=AccessMode.READ_ONLY,
)
def read_ticket(ticket_id: str) -> str:
    return f"ticket={ticket_id}"


def main() -> None:
    print("--- ToolBoundary × AgentKey Integration Demo ---")
    print(f"Session ID: {provider.session_id}")
    output = read_ticket(ticket_id="INC-1001")
    print(f"Execution Output: {output}")
    print("--- Demo Completed Successfully ---")


if __name__ == "__main__":
    main()
