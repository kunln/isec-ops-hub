"""
MCP Tool Adapter Unit Tests
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from flocks.mcp.types import McpToolDef
from flocks.mcp.adapter import McpToolAdapter
from flocks.tool.registry import ToolParameter, ParameterType


class TestMcpToolAdapter:
    """Test MCP Tool Adapter"""
    
    def test_convert_parameters_basic(self):
        """Test basic parameter conversion"""
        input_schema = {
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address"
                },
                "count": {
                    "type": "integer",
                    "description": "Count"
                }
            },
            "required": ["ip"]
        }
        
        params = McpToolAdapter._convert_parameters(input_schema)
        
        assert len(params) == 2
        
        # Check ip parameter
        ip_param = next(p for p in params if p.name == "ip")
        assert ip_param.type == ParameterType.STRING
        assert ip_param.description == "IP address"
        assert ip_param.required
        
        # Check count parameter
        count_param = next(p for p in params if p.name == "count")
        assert count_param.type == ParameterType.INTEGER
        assert count_param.description == "Count"
        assert not count_param.required
    
    def test_convert_parameters_all_types(self):
        """Test all parameter type conversions"""
        input_schema = {
            "properties": {
                "str_param": {"type": "string"},
                "int_param": {"type": "integer"},
                "num_param": {"type": "number"},
                "bool_param": {"type": "boolean"},
                "arr_param": {"type": "array"},
                "obj_param": {"type": "object"},
            }
        }
        
        params = McpToolAdapter._convert_parameters(input_schema)
        
        type_map = {p.name: p.type for p in params}
        assert type_map["str_param"] == ParameterType.STRING
        assert type_map["int_param"] == ParameterType.INTEGER
        assert type_map["num_param"] == ParameterType.NUMBER
        assert type_map["bool_param"] == ParameterType.BOOLEAN
        assert type_map["arr_param"] == ParameterType.ARRAY
        assert type_map["obj_param"] == ParameterType.OBJECT
    
    def test_convert_parameters_with_default(self):
        """Test parameter with default value"""
        input_schema = {
            "properties": {
                "timeout": {
                    "type": "integer",
                    "default": 30
                }
            }
        }
        
        params = McpToolAdapter._convert_parameters(input_schema)
        assert params[0].default == 30
    
    def test_convert_parameters_with_enum(self):
        """Test parameter with enum values"""
        input_schema = {
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["low", "medium", "high"]
                }
            }
        }
        
        params = McpToolAdapter._convert_parameters(input_schema)
        assert params[0].enum == ["low", "medium", "high"]
    
    def test_convert_parameters_empty(self):
        """Test empty parameters"""
        params = McpToolAdapter._convert_parameters({})
        assert len(params) == 0
        
        params = McpToolAdapter._convert_parameters(None)
        assert len(params) == 0
    
    def test_convert_tool_creates_valid_tool(self):
        """Test tool conversion creates valid Tool object"""
        mcp_tool = McpToolDef(
            name="ip_query",
            description="Query IP",
            input_schema={
                "properties": {
                    "ip": {"type": "string"}
                },
                "required": ["ip"]
            }
        )
        
        # Mock client
        client = MagicMock()
        
        tool = McpToolAdapter.convert_tool("threatbook", mcp_tool, client)
        
        # Check Tool attributes
        assert tool.info.name == "threatbook_ip_query"
        assert "Query IP" in tool.info.description
        assert "threatbook MCP Server" in tool.info.description
        assert len(tool.info.parameters) == 1
        assert tool.handler is not None
    
    @pytest.mark.asyncio
    async def test_tool_handler_success(self):
        """Test tool handler successful invocation"""
        mcp_tool = McpToolDef(
            name="test_tool",
            description="Test",
            input_schema={"properties": {"param": {"type": "string"}}}
        )
        
        # Mock client and result
        client = AsyncMock()
        mock_result = MagicMock()
        mock_result.isError = False
        mock_result.content = [MagicMock(text="result data")]
        client.call_tool = AsyncMock(return_value=mock_result)
        
        tool = McpToolAdapter.convert_tool("test_server", mcp_tool, client)
        
        # Call handler
        from flocks.tool.registry import ToolContext
        ctx = ToolContext(session_id="test_session", message_id="test_message")
        result = await tool.handler(ctx, param="value")
        
        assert result.success
        assert result.output == "result data"
        assert result.metadata["mcp_server"] == "test_server"
        assert result.metadata["mcp_tool"] == "test_tool"
    
    @pytest.mark.asyncio
    async def test_tool_handler_error(self):
        """Test tool handler error handling"""
        mcp_tool = McpToolDef(
            name="test_tool",
            description="Test",
            input_schema={"properties": {"param": {"type": "string"}}}
        )
        
        # Mock client error
        client = AsyncMock()
        client.call_tool = AsyncMock(side_effect=Exception("Connection failed"))
        
        tool = McpToolAdapter.convert_tool("test_server", mcp_tool, client)
        
        # Call handler
        from flocks.tool.registry import ToolContext
        ctx = ToolContext(session_id="test_session", message_id="test_message")
        result = await tool.handler(ctx, param="value")
        
        assert not result.success
        assert "Connection failed" in result.error
    
    def test_get_schema_hash(self):
        """Test getting schema hash"""
        mcp_tool = McpToolDef(
            name="test",
            input_schema={"type": "object", "properties": {"a": {"type": "string"}}}
        )
        
        hash1 = McpToolAdapter.get_schema_hash(mcp_tool)
        assert isinstance(hash1, str)
        assert len(hash1) == 64  # SHA256 hex length
        
        # Same schema produces same hash
        mcp_tool2 = McpToolDef(
            name="test2",
            input_schema={"type": "object", "properties": {"a": {"type": "string"}}}
        )
        hash2 = McpToolAdapter.get_schema_hash(mcp_tool2)
        assert hash1 == hash2
