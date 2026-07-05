"""Workflow tools: facade and default registry (flocks adapter).

Tool execution uses flocks ToolRegistry via FlocksToolAdapter.
Nodes get a `tool` facade that calls adapter.run(name, **kwargs).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .tools_adapter import FlocksToolAdapter
from .tools_spec import DictLikeStr, ToolSpec

__all__ = ["ToolSpec", "DictLikeStr", "get_tool_registry", "tool_facade", "ToolFacade"]


def get_tool_registry(tool_context: Optional[Any] = None) -> FlocksToolAdapter:
    """Return the default tool registry (adapter over flocks tools)."""
    ctx = tool_context
    return FlocksToolAdapter(tool_context=ctx)


@dataclass
class ToolFacade:
    """Facade injected into node execution environment as `tool`."""

    def __init__(self, registry: FlocksToolAdapter):
        self.registry = registry

    def run(self, name: str, /, **kwargs: Any) -> Any:
        return self.registry.run(name, **kwargs)

    def run_safe(self, name: str, /, **kwargs: Any) -> Dict[str, Any]:
        """Run tool and return unified envelope: {success, text, obj, error}."""
        return self.registry.run_safe(name, **kwargs)


def tool_facade(registry: Optional[FlocksToolAdapter] = None) -> ToolFacade:
    return ToolFacade(registry=registry or get_tool_registry())
