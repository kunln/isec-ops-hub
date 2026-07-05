"""
Hook event type definitions

Defines the event models for the hook system.
"""

from typing import Literal, Dict, Any, List, Callable, Union
from datetime import datetime
from pydantic import BaseModel, Field

# Event type enum
HookEventType = Literal["command", "session", "agent", "system"]


class HookEvent(BaseModel):
    """Base hook event model"""
    
    type: HookEventType = Field(..., description="Event type")
    action: str = Field(..., description="Action name (e.g., 'new', 'delete', 'create')")
    session_id: str = Field(..., description="Associated session ID")
    context: Dict[str, Any] = Field(default_factory=dict, description="Event context data")
    timestamp: datetime = Field(default_factory=datetime.now, description="Event timestamp")
    messages: List[str] = Field(default_factory=list, description="Messages to return to user")
    
    class Config:
        arbitrary_types_allowed = True


class CommandHookEvent(HookEvent):
    """Command event (e.g., /new, /help, /reset)"""
    type: Literal["command"] = "command"


class SessionHookEvent(HookEvent):
    """Session lifecycle event (e.g., create, delete, archive)"""
    type: Literal["session"] = "session"


class AgentHookEvent(HookEvent):
    """Agent event (e.g., bootstrap, init, shutdown)"""
    type: Literal["agent"] = "agent"


class SystemHookEvent(HookEvent):
    """System event (e.g., startup, shutdown, config_change)"""
    type: Literal["system"] = "system"


# Hook handler types
HookHandler = Callable[[HookEvent], None]
AsyncHookHandler = Callable[[HookEvent], Any]  # Coroutine
