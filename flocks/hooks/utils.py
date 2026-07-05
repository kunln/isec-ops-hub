"""
Hook utility functions

Helper functions for creating hook events.
"""

from typing import Dict, Any, Optional

from flocks.hooks.types import (
    CommandHookEvent,
    SessionHookEvent,
    AgentHookEvent,
    SystemHookEvent,
)


def create_command_event(
    action: str,
    session_id: str,
    context: Optional[Dict[str, Any]] = None,
) -> CommandHookEvent:
    """
    Create a command event
    
    Args:
        action: Command action (e.g., "new", "help", "reset")
        session_id: Session ID
        context: Optional context data
        
    Returns:
        CommandHookEvent
        
    Example:
        >>> event = create_command_event("new", "session_123", {"previous_session_id": "session_122"})
    """
    return CommandHookEvent(
        action=action,
        session_id=session_id,
        context=context or {},
    )


def create_session_event(
    action: str,
    session_id: str,
    context: Optional[Dict[str, Any]] = None,
) -> SessionHookEvent:
    """
    Create a session lifecycle event
    
    Args:
        action: Session action (e.g., "create", "delete", "archive")
        session_id: Session ID
        context: Optional context data
        
    Returns:
        SessionHookEvent
    """
    return SessionHookEvent(
        action=action,
        session_id=session_id,
        context=context or {},
    )


def create_agent_event(
    action: str,
    session_id: str,
    context: Optional[Dict[str, Any]] = None,
) -> AgentHookEvent:
    """
    Create an agent event
    
    Args:
        action: Agent action (e.g., "bootstrap", "init", "shutdown")
        session_id: Session ID
        context: Optional context data
        
    Returns:
        AgentHookEvent
    """
    return AgentHookEvent(
        action=action,
        session_id=session_id,
        context=context or {},
    )


def create_system_event(
    action: str,
    context: Optional[Dict[str, Any]] = None,
) -> SystemHookEvent:
    """
    Create a system event
    
    Args:
        action: System action (e.g., "startup", "shutdown")
        context: Optional context data
        
    Returns:
        SystemHookEvent
    """
    return SystemHookEvent(
        action=action,
        session_id="system",
        context=context or {},
    )
