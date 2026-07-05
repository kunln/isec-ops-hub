"""
ACP type definitions

Matches Flocks' ported src/acp/types.ts
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class McpServerLocal:
    """Local MCP server configuration"""
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class McpServerRemote:
    """Remote MCP server configuration"""
    name: str
    type: str  # "http" or "sse"
    url: str
    headers: List[Dict[str, str]] = field(default_factory=list)


# Union type for MCP servers
McpServer = McpServerLocal | McpServerRemote


@dataclass
class ACPSessionState:
    """
    ACP session state
    
    Matches TypeScript ACPSessionState interface
    """
    id: str
    cwd: str
    mcp_servers: List[McpServer] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    model: Optional[Dict[str, str]] = None  # {"providerID": str, "modelID": str}
    mode_id: Optional[str] = None


@dataclass
class ACPConfig:
    """
    ACP configuration
    
    Matches TypeScript ACPConfig interface
    """
    sdk: Any  # FlocksClient instance
    default_model: Optional[Dict[str, str]] = None  # {"providerID": str, "modelID": str}


# ACP Protocol Types

@dataclass
class AuthMethod:
    """Authentication method"""
    id: str
    name: str
    description: str
    meta: Optional[Dict[str, Any]] = None


@dataclass
class AgentCapabilities:
    """Agent capabilities"""
    load_session: bool = True
    mcp_capabilities: Dict[str, bool] = field(default_factory=lambda: {"http": True, "sse": True})
    prompt_capabilities: Dict[str, bool] = field(default_factory=lambda: {"embeddedContext": True, "image": True})


@dataclass
class AgentInfo:
    """Agent information"""
    name: str
    version: str


@dataclass
class InitializeResponse:
    """Response to initialize request"""
    protocol_version: int
    agent_capabilities: AgentCapabilities
    auth_methods: List[AuthMethod]
    agent_info: AgentInfo


@dataclass
class ModelInfo:
    """Model information"""
    model_id: str
    name: str


@dataclass
class ModeInfo:
    """Mode (agent) information"""
    id: str
    name: str
    description: Optional[str] = None


@dataclass
class ModelsResponse:
    """Available models response"""
    current_model_id: str
    available_models: List[ModelInfo] = field(default_factory=list)


@dataclass
class ModesResponse:
    """Available modes response"""
    current_mode_id: str
    available_modes: List[ModeInfo] = field(default_factory=list)


@dataclass
class CommandInfo:
    """Command information"""
    name: str
    description: str


@dataclass
class PermissionOption:
    """Permission option for user selection"""
    option_id: str
    kind: str  # "allow_once", "allow_always", "reject_once"
    name: str


@dataclass
class PlanEntry:
    """Plan/TODO entry"""
    priority: str  # "low", "medium", "high"
    status: str  # "pending", "in_progress", "completed"
    content: str


# Tool-related types

ToolKind = str  # "execute", "fetch", "edit", "search", "read", "other"


@dataclass 
class ToolCallLocation:
    """Location affected by tool call"""
    path: str


@dataclass
class ToolCallContent:
    """Content from tool call result"""
    type: str  # "content" or "diff"
    content: Optional[Dict[str, Any]] = None
    path: Optional[str] = None
    old_text: Optional[str] = None
    new_text: Optional[str] = None


# Session update types

@dataclass
class ToolCallUpdate:
    """Tool call status update"""
    session_update: str = "tool_call"
    tool_call_id: str = ""
    title: str = ""
    kind: ToolKind = "other"
    status: str = "pending"  # "pending", "in_progress", "completed", "failed"
    locations: List[ToolCallLocation] = field(default_factory=list)
    raw_input: Dict[str, Any] = field(default_factory=dict)
    raw_output: Optional[Dict[str, Any]] = None
    content: Optional[List[ToolCallContent]] = None


@dataclass
class MessageChunkUpdate:
    """Message chunk update"""
    session_update: str  # "agent_message_chunk", "user_message_chunk", "agent_thought_chunk"
    content: Dict[str, Any] = field(default_factory=dict)  # {"type": "text", "text": str}


@dataclass
class PlanUpdate:
    """Plan/TODO list update"""
    session_update: str = "plan"
    entries: List[PlanEntry] = field(default_factory=list)


@dataclass
class AvailableCommandsUpdate:
    """Available commands update"""
    session_update: str = "available_commands_update"
    available_commands: List[CommandInfo] = field(default_factory=list)
