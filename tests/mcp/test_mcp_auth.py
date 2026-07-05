"""
MCP Authentication Management Unit Tests
"""

import pytest
import time
from flocks.mcp.auth import McpAuth


@pytest.fixture(autouse=True)
def clean_auth():
    """Clear authentication info before each test"""
    McpAuth.clear()
    yield
    McpAuth.clear()


class TestMcpAuth:
    """Test MCP Authentication Management"""
    
    @pytest.mark.asyncio
    async def test_set_and_get(self):
        """Test setting and getting authentication info"""
        tokens = {"access_token": "token123", "refresh_token": "refresh123"}
        await McpAuth.set("test_server", tokens, expires_in=3600)
        
        entry = await McpAuth.get("test_server")
        assert entry is not None
        assert entry.server_name == "test_server"
        assert entry.tokens == tokens
        assert entry.expires_at is not None
    
    @pytest.mark.asyncio
    async def test_get_nonexistent(self):
        """Test getting non-existent authentication info"""
        entry = await McpAuth.get("nonexistent")
        assert entry is None
    
    @pytest.mark.asyncio
    async def test_remove(self):
        """Test removing authentication info"""
        tokens = {"access_token": "token123"}
        await McpAuth.set("test_server", tokens)
        
        await McpAuth.remove("test_server")
        entry = await McpAuth.get("test_server")
        assert entry is None
    
    @pytest.mark.asyncio
    async def test_is_token_expired(self):
        """Test token expiration check"""
        # Set long-lived token (expires in 3600s, greater than 5-minute buffer)
        tokens = {"access_token": "token123"}
        await McpAuth.set("test_server", tokens, expires_in=3600)
        
        # Check immediately, should not be expired
        expired = await McpAuth.is_token_expired("test_server")
        assert not expired
        
        # Set expiring token (expires in 200s, less than 5-minute buffer)
        await McpAuth.set("test_server_expiring", tokens, expires_in=200)
        expired = await McpAuth.is_token_expired("test_server_expiring")
        assert expired  # Because 200 < 300 (5-minute buffer)
        
        # Set token without expiration
        await McpAuth.set("test_server2", tokens, expires_in=None)
        expired = await McpAuth.is_token_expired("test_server2")
        assert not expired
        
        # Non-existent server
        expired = await McpAuth.is_token_expired("nonexistent")
        assert not expired
    
    @pytest.mark.asyncio
    async def test_list_all(self):
        """Test listing all authentication info"""
        await McpAuth.set("server1", {"token": "1"})
        await McpAuth.set("server2", {"token": "2"})
        
        all_auth = await McpAuth.list_all()
        assert len(all_auth) == 2
        assert "server1" in all_auth
        assert "server2" in all_auth
    
    def test_clear(self):
        """Test clearing all authentication info"""
        McpAuth._auth_storage["test"] = None
        McpAuth.clear()
        assert len(McpAuth._auth_storage) == 0
