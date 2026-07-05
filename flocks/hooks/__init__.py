"""
Hook system for Flocks

Provides an event-driven hook system for extending Flocks functionality.
Inspired by OpenClaw's hook architecture.
"""

from flocks.hooks.registry import (
    HookRegistry,
    register_hook,
    unregister_hook,
    clear_hooks,
    trigger_hook,
    get_hook_stats,
)
from flocks.hooks.types import (
    HookEvent,
    HookEventType,
    CommandHookEvent,
    SessionHookEvent,
    AgentHookEvent,
    SystemHookEvent,
    HookHandler,
    AsyncHookHandler,
)
from flocks.hooks.utils import (
    create_command_event,
    create_session_event,
    create_agent_event,
    create_system_event,
)

__all__ = [
    # Registry
    "HookRegistry",
    "register_hook",
    "unregister_hook",
    "clear_hooks",
    "trigger_hook",
    "get_hook_stats",
    
    # Types
    "HookEvent",
    "HookEventType",
    "CommandHookEvent",
    "SessionHookEvent",
    "AgentHookEvent",
    "SystemHookEvent",
    "HookHandler",
    "AsyncHookHandler",
    
    # Utils
    "create_command_event",
    "create_session_event",
    "create_agent_event",
    "create_system_event",
]
