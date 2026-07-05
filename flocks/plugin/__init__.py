"""
Unified plugin system for Flocks.

Subsystems register extension points; ``PluginLoader`` scans
``~/.flocks/plugins/{subdir}/`` and dispatches items to each consumer.

Default directory layout::

    ~/.flocks/plugins/
    ├── agents/    # AGENTS: List[AgentInfo]
    ├── tools/     # TOOLS:  List[dict]  or  @ToolRegistry.register_function
    └── hooks/     # HOOKS:  Dict[str, Callable]
"""

from flocks.plugin.loader import (
    DEFAULT_PLUGIN_ROOT,
    ExtensionPoint,
    PluginLoader,
    load_module,
    scan_directory,
)

__all__ = [
    "DEFAULT_PLUGIN_ROOT",
    "ExtensionPoint",
    "PluginLoader",
    "load_module",
    "scan_directory",
]
