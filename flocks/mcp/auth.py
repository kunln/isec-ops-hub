"""
MCP Authentication Management

Handles authentication methods including OAuth 2.0 and API Key
"""

import time
from typing import Optional, Dict, Any
from pathlib import Path
from pydantic import BaseModel

from flocks.config.config import Config
from flocks.utils.log import Log

log = Log.create(service="mcp.auth")


class McpAuthEntry(BaseModel):
    """Authentication information entry"""
    server_name: str
    tokens: Optional[Dict[str, Any]] = None
    created_at: float
    expires_at: Optional[float] = None


class McpAuth:
    """
    MCP Authentication Manager
    
    Manages storage and retrieval of OAuth tokens and API Keys
    Note: P0 simplified implementation, P1 will enhance OAuth flow
    """
    
    # In-memory storage (P0)
    # P1: Migrate to encrypted file storage
    _auth_storage: Dict[str, McpAuthEntry] = {}
    
    @classmethod
    async def get(cls, server_name: str) -> Optional[McpAuthEntry]:
        """
        Get authentication information
        
        Args:
            server_name: Server name
            
        Returns:
            Authentication information, or None if not found
        """
        return cls._auth_storage.get(server_name)
    
    @classmethod
    async def set(
        cls,
        server_name: str,
        tokens: Dict[str, Any],
        expires_in: Optional[int] = None
    ) -> None:
        """
        Set authentication information
        
        Args:
            server_name: Server name
            tokens: Token dictionary
            expires_in: Expiration time in seconds
        """
        entry = McpAuthEntry(
            server_name=server_name,
            tokens=tokens,
            created_at=time.time(),
            expires_at=time.time() + expires_in if expires_in else None
        )
        cls._auth_storage[server_name] = entry
        
        log.info("mcp.auth.stored", {
            "server": server_name,
            "expires_in": expires_in
        })
    
    @classmethod
    async def remove(cls, server_name: str) -> None:
        """
        Remove authentication information
        
        Args:
            server_name: Server name
        """
        if server_name in cls._auth_storage:
            cls._auth_storage.pop(server_name)
            log.info("mcp.auth.removed", {"server": server_name})
    
    @classmethod
    async def is_token_expired(cls, server_name: str) -> bool:
        """
        Check if token is expired
        
        Args:
            server_name: Server name
            
        Returns:
            True if expired
        """
        entry = cls._auth_storage.get(server_name)
        if not entry or not entry.expires_at:
            return False
        
        # Mark as expired 5 minutes early
        return time.time() >= entry.expires_at - 300
    
    @classmethod
    async def list_all(cls) -> Dict[str, McpAuthEntry]:
        """
        List all authentication information
        
        Returns:
            Dictionary mapping server name to authentication info
        """
        return cls._auth_storage.copy()
    
    @classmethod
    def clear(cls) -> None:
        """Clear all authentication information (for testing)"""
        cls._auth_storage.clear()


__all__ = ['McpAuth', 'McpAuthEntry']
