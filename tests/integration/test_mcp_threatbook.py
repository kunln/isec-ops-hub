"""
ThreatBook MCP 集成测试

测试与 ThreatBook MCP 服务器的完整集成
"""

import os
import pytest
import asyncio
from flocks.mcp import MCP, McpStatus, get_manager
from flocks.mcp.registry import McpToolRegistry
from flocks.tool import ToolRegistry
from flocks.config.config import Config

# 从环境变量读取 API Key
THREATBOOK_API_KEY = os.getenv("THREATBOOK_API_KEY")
THREATBOOK_MCP_URL = "https://mcp.threatbook.cn/mcp"

# 如果没有 API Key，跳过所有集成测试
pytestmark = pytest.mark.skipif(
    not THREATBOOK_API_KEY,
    reason="需要设置 THREATBOOK_API_KEY 环境变量"
)


@pytest.fixture
async def threatbook_config():
    """ThreatBook MCP 服务器配置"""
    return {
        "type": "remote",
        "url": THREATBOOK_MCP_URL,
        "enabled": True,
        "timeout": 30.0,
        "auth": {
            "type": "apikey",
            "location": "query",
            "param_name": "apikey",
            "value": THREATBOOK_API_KEY
        }
    }


@pytest.fixture(autouse=True)
async def cleanup():
    """测试前后清理"""
    # 清理前
    McpToolRegistry.clear()
    manager = get_manager()
    await manager.shutdown()
    
    yield
    
    # 清理后
    await manager.shutdown()
    McpToolRegistry.clear()


class TestThreatBookIntegration:
    """ThreatBook MCP 集成测试"""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_connect_to_threatbook(self, threatbook_config):
        """测试连接到 ThreatBook MCP 服务器"""
        success = await MCP.connect("threatbook", threatbook_config)
        assert success
        
        # 检查状态 (直接从管理器获取,避免触发自动初始化)
        manager = get_manager()
        assert "threatbook" in manager._status
        assert manager._status["threatbook"].status == McpStatus.CONNECTED
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_list_threatbook_tools(self, threatbook_config):
        """测试列出 ThreatBook 工具"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取服务器信息
        info = await MCP.get_server_info("threatbook")
        assert info is not None
        assert len(info.tools) > 0
        
        # 检查预期的工具
        tool_names = [t.name for t in info.tools]
        assert "ip_query" in tool_names
        assert "vuln_query" in tool_names
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_tools_registered_in_flocks(self, threatbook_config):
        """测试工具注册到 Flocks"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 检查工具已注册
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        assert len(server_tools) > 0
        
        # 检查预期的工具名称格式
        assert any("ip_query" in t for t in server_tools)
        assert any("vuln_query" in t for t in server_tools)
        
        # 检查可以从 ToolRegistry 获取
        ip_query_tool = next((t for t in server_tools if "ip_query" in t), None)
        assert ip_query_tool is not None
        assert ToolRegistry.get(ip_query_tool) is not None
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_call_ip_query_tool(self, threatbook_config):
        """测试调用 ip_query 工具"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取注册的工具
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        ip_query_tool_name = next((t for t in server_tools if "ip_query" in t), None)
        assert ip_query_tool_name is not None
        
        # 获取工具
        tool = ToolRegistry.get(ip_query_tool_name)
        assert tool is not None
        
        # 调用工具
        from flocks.tool.registry import ToolContext
        ctx = ToolContext(session_id="test_session", message_id="test_message")
        result = await tool.handler(ctx, ip="8.8.8.8")
        
        # 检查结果
        assert result.success
        assert result.output is not None
        assert result.metadata["mcp_server"] == "threatbook"
        assert result.metadata["mcp_tool"] == "ip_query"
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_call_vuln_query_tool(self, threatbook_config):
        """测试调用 vuln_query 工具"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取注册的工具
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        vuln_query_tool_name = next((t for t in server_tools if "vuln_query" in t), None)
        assert vuln_query_tool_name is not None
        
        # 获取工具
        tool = ToolRegistry.get(vuln_query_tool_name)
        assert tool is not None
        
        # 调用工具
        from flocks.tool.registry import ToolContext
        ctx = ToolContext(session_id="test_session", message_id="test_message")
        result = await tool.handler(ctx, vuln_id="CNVD-2021-01627")
        
        # 检查结果
        assert result.success
        assert result.output is not None
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_disconnect_threatbook(self, threatbook_config):
        """测试断开 ThreatBook 连接"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取管理器
        manager = get_manager()
        
        # 断开连接
        success = await MCP.disconnect("threatbook")
        assert success
        
        # 检查状态 (直接从管理器获取,避免触发自动初始化)
        assert "threatbook" not in manager._clients or manager._status.get("threatbook").status == McpStatus.DISCONNECTED
        
        # 检查工具已注销
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        assert len(server_tools) == 0
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_refresh_threatbook_tools(self, threatbook_config):
        """测试刷新 ThreatBook 工具"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取初始工具数量
        initial_tools = McpToolRegistry.get_server_tools("threatbook")
        initial_count = len(initial_tools)
        assert initial_count > 0
        
        # 刷新工具
        refreshed_count = await MCP.refresh_tools("threatbook")
        assert refreshed_count > 0
        
        # 检查工具仍然可用
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        assert len(server_tools) == refreshed_count
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_tool_source_tracking(self, threatbook_config):
        """测试工具来源跟踪"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取工具
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        tool_name = server_tools[0]
        
        # 检查来源信息
        source = MCP.get_tool_source(tool_name)
        assert source is not None
        assert source.mcp_server == "threatbook"
        assert source.flocks_tool == tool_name
        assert source.schema_hash is not None
        assert source.registered_at > 0
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_is_mcp_tool(self, threatbook_config):
        """测试 MCP 工具识别"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取工具
        server_tools = McpToolRegistry.get_server_tools("threatbook")
        tool_name = server_tools[0]
        
        # 检查是否是 MCP 工具
        assert MCP.is_mcp_tool(tool_name)
        assert not MCP.is_mcp_tool("unknown_tool")
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_get_stats(self, threatbook_config):
        """测试获取统计信息"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取统计信息
        stats = MCP.get_stats()
        assert stats["total_servers"] >= 1
        assert stats["total_tools"] > 0
        assert "threatbook" in stats["tools_by_server"]
        assert stats["tools_by_server"]["threatbook"] > 0
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_resources_list(self, threatbook_config):
        """测试列出资源（如果支持）"""
        await MCP.connect("threatbook", threatbook_config)
        
        # 获取服务器信息
        info = await MCP.get_server_info("threatbook")
        assert info is not None
        
        # ThreatBook 可能不提供资源，但不应该报错
        # 只检查 resources 字段存在
        assert hasattr(info, "resources")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_full_lifecycle():
    """测试完整生命周期：初始化 -> 使用 -> 关闭"""
    # 配置
    threatbook_config = {
        "type": "remote",
        "url": THREATBOOK_MCP_URL,
        "enabled": True,
        "timeout": 30.0,
        "auth": {
            "type": "apikey",
            "location": "query",
            "param_name": "apikey",
            "value": THREATBOOK_API_KEY
        }
    }
    
    # 1. 连接
    await MCP.connect("threatbook", threatbook_config)
    
    # 2. 使用工具
    server_tools = McpToolRegistry.get_server_tools("threatbook")
    assert len(server_tools) > 0
    
    # 3. 调用工具
    ip_query_tool_name = next((t for t in server_tools if "ip_query" in t), None)
    if ip_query_tool_name:
        tool = ToolRegistry.get(ip_query_tool_name)
        from flocks.tool.registry import ToolContext
        ctx = ToolContext(session_id="test_session", message_id="test_message")
        result = await tool.handler(ctx, ip="127.0.0.1")
        assert result.success
    
    # 4. 关闭
    await MCP.shutdown()
    
    # 5. 检查清理 (直接检查管理器状态,避免触发自动初始化)
    manager = get_manager()
    assert len(manager._clients) == 0
    assert not manager._initialized
