"""
MCP Tool Registry

Tracks MCP tool metadata and manages tool registration/deregistration
"""

import time
from typing import Dict, List, Optional
from flocks.mcp.types import McpToolSource
from flocks.utils.log import Log

log = Log.create(service="mcp.registry")


class McpToolRegistry:
    """
    MCP Tool Registry
    
    Tracks MCP tool metadata:
    - Tool source (which MCP server)
    - Mapping between original tool name and Flocks tool name
    - Registration time
    - Schema hash (for detecting changes)
    """
    
    # Tool metadata: Flocks tool name -> McpToolSource
    _tools: Dict[str, McpToolSource] = {}
    
    # Server -> tool list mapping
    _server_tools: Dict[str, List[str]] = {}
    
    @classmethod
    def track(
        cls,
        server_name: str,
        mcp_tool_name: str,
        flocks_tool_name: str,
        schema_hash: Optional[str] = None
    ) -> None:
        """
        Track MCP tool registration
        
        Args:
            server_name: MCP server name
            mcp_tool_name: Original MCP tool name
            flocks_tool_name: Tool name registered in Flocks
            schema_hash: Schema hash value (optional)
        """
        # Record tool metadata
        cls._tools[flocks_tool_name] = McpToolSource(
            mcp_server=server_name,
            mcp_tool=mcp_tool_name,
            flocks_tool=flocks_tool_name,
            registered_at=time.time(),
            schema_hash=schema_hash
        )
        
        # Record server tool list
        if server_name not in cls._server_tools:
            cls._server_tools[server_name] = []
        cls._server_tools[server_name].append(flocks_tool_name)
        
        log.debug("mcp.registry.tracked", {
            "server": server_name,
            "mcp_tool": mcp_tool_name,
            "flocks_tool": flocks_tool_name
        })
    
    @classmethod
    def untrack(cls, flocks_tool_name: str) -> None:
        """
        Untrack a tool
        
        Args:
            flocks_tool_name: Flocks tool name
        """
        if flocks_tool_name in cls._tools:
            source = cls._tools.pop(flocks_tool_name)
            
            # Remove from server tool list
            if source.mcp_server in cls._server_tools:
                try:
                    cls._server_tools[source.mcp_server].remove(flocks_tool_name)
                except ValueError:
                    pass
            
            log.debug("mcp.registry.untracked", {
                "flocks_tool": flocks_tool_name
            })
    
    @classmethod
    def untrack_server(cls, server_name: str) -> List[str]:
        """
        Untrack all tools from a server
        
        Args:
            server_name: Server name
            
        Returns:
            List of untracked tool names
        """
        tool_names = cls._server_tools.get(server_name, []).copy()
        
        for tool_name in tool_names:
            cls._tools.pop(tool_name, None)
        
        cls._server_tools.pop(server_name, None)
        
        log.info("mcp.registry.server_untracked", {
            "server": server_name,
            "tools_count": len(tool_names)
        })
        
        return tool_names
    
    @classmethod
    def get_source(cls, flocks_tool_name: str) -> Optional[McpToolSource]:
        """
        Get tool source information
        
        Args:
            flocks_tool_name: Flocks tool name
            
        Returns:
            Tool source information, or None if not found
        """
        return cls._tools.get(flocks_tool_name)
    
    @classmethod
    def get_server_tools(cls, server_name: str) -> List[str]:
        """
        Get all tools from a server
        
        Args:
            server_name: Server name
            
        Returns:
            List of tool names
        """
        return cls._server_tools.get(server_name, []).copy()
    
    @classmethod
    def is_mcp_tool(cls, flocks_tool_name: str) -> bool:
        """
        Check if a tool is an MCP tool
        
        Args:
            flocks_tool_name: Flocks tool name
            
        Returns:
            True if it's an MCP tool
        """
        return flocks_tool_name in cls._tools
    
    @classmethod
    def get_all_servers(cls) -> List[str]:
        """
        Get all servers that have registered tools
        
        Returns:
            List of server names
        """
        return list(cls._server_tools.keys())
    
    @classmethod
    def get_stats(cls) -> Dict[str, int]:
        """
        Get statistics
        
        Returns:
            Statistics dictionary
        """
        return {
            "total_tools": len(cls._tools),
            "total_servers": len(cls._server_tools),
            "tools_by_server": {
                server: len(tools)
                for server, tools in cls._server_tools.items()
            }
        }
    
    @classmethod
    def clear(cls) -> None:
        """Clear all tracking information (for testing)"""
        cls._tools.clear()
        cls._server_tools.clear()
        log.debug("mcp.registry.cleared")


__all__ = ['McpToolRegistry']
