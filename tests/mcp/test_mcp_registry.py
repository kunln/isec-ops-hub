"""
MCP Tool Registry Unit Tests
"""

import pytest
from flocks.mcp.registry import McpToolRegistry


@pytest.fixture(autouse=True)
def clean_registry():
    """Clear registry before each test"""
    McpToolRegistry.clear()
    yield
    McpToolRegistry.clear()


class TestMcpToolRegistry:
    """Test MCP Tool Registry"""
    
    def test_track_tool(self):
        """Test tracking tool"""
        McpToolRegistry.track(
            server_name="test_server",
            mcp_tool_name="test_tool",
            flocks_tool_name="test_server_test_tool",
            schema_hash="hash123"
        )
        
        source = McpToolRegistry.get_source("test_server_test_tool")
        assert source is not None
        assert source.mcp_server == "test_server"
        assert source.mcp_tool == "test_tool"
        assert source.flocks_tool == "test_server_test_tool"
        assert source.schema_hash == "hash123"
    
    def test_untrack_tool(self):
        """Test untracking tool"""
        McpToolRegistry.track(
            server_name="test_server",
            mcp_tool_name="test_tool",
            flocks_tool_name="test_server_test_tool"
        )
        
        McpToolRegistry.untrack("test_server_test_tool")
        source = McpToolRegistry.get_source("test_server_test_tool")
        assert source is None
    
    def test_get_server_tools(self):
        """Test getting server tools"""
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool1",
            flocks_tool_name="server1_tool1"
        )
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool2",
            flocks_tool_name="server1_tool2"
        )
        McpToolRegistry.track(
            server_name="server2",
            mcp_tool_name="tool3",
            flocks_tool_name="server2_tool3"
        )
        
        tools = McpToolRegistry.get_server_tools("server1")
        assert len(tools) == 2
        assert "server1_tool1" in tools
        assert "server1_tool2" in tools
        assert "server2_tool3" not in tools
    
    def test_untrack_server(self):
        """Test untracking server"""
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool1",
            flocks_tool_name="server1_tool1"
        )
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool2",
            flocks_tool_name="server1_tool2"
        )
        
        removed = McpToolRegistry.untrack_server("server1")
        assert len(removed) == 2
        assert "server1_tool1" in removed
        assert "server1_tool2" in removed
        
        tools = McpToolRegistry.get_server_tools("server1")
        assert len(tools) == 0
    
    def test_is_mcp_tool(self):
        """Test checking if it's an MCP tool"""
        assert not McpToolRegistry.is_mcp_tool("unknown_tool")
        
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool1",
            flocks_tool_name="server1_tool1"
        )
        
        assert McpToolRegistry.is_mcp_tool("server1_tool1")
    
    def test_get_all_servers(self):
        """Test getting all servers"""
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool1",
            flocks_tool_name="server1_tool1"
        )
        McpToolRegistry.track(
            server_name="server2",
            mcp_tool_name="tool2",
            flocks_tool_name="server2_tool2"
        )
        
        servers = McpToolRegistry.get_all_servers()
        assert len(servers) == 2
        assert "server1" in servers
        assert "server2" in servers
    
    def test_get_stats(self):
        """Test getting statistics"""
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool1",
            flocks_tool_name="server1_tool1"
        )
        McpToolRegistry.track(
            server_name="server1",
            mcp_tool_name="tool2",
            flocks_tool_name="server1_tool2"
        )
        McpToolRegistry.track(
            server_name="server2",
            mcp_tool_name="tool3",
            flocks_tool_name="server2_tool3"
        )
        
        stats = McpToolRegistry.get_stats()
        assert stats["total_tools"] == 3
        assert stats["total_servers"] == 2
        assert stats["tools_by_server"]["server1"] == 2
        assert stats["tools_by_server"]["server2"] == 1
