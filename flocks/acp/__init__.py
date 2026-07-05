"""
ACP (Agent Client Protocol) module

Provides integration with editors like Zed through the Agent Client Protocol.
Based on Flocks' ported src/acp/

The ACP protocol enables AI agents to communicate with IDE clients through:
- JSON-RPC over stdio
- Session management
- Tool execution notifications
- Permission requests
"""

from flocks.acp.types import ACPConfig, ACPSessionState
from flocks.acp.session import ACPSessionManager
from flocks.acp.agent import ACPAgent, ACP


__all__ = [
    "ACPConfig",
    "ACPSessionState",
    "ACPSessionManager",
    "ACPAgent",
    "ACP",
]
