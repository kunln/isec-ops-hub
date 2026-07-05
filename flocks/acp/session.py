"""
ACP Session Manager

Handles ACP session state management.
Matches Flocks' ported src/acp/session.ts
"""

from typing import Optional, Dict, List, Any
from datetime import datetime

from flocks.acp.types import ACPSessionState, McpServer
from flocks.utils.log import Log


log = Log.create(service="acp.session")


class RequestError(Exception):
    """ACP request error"""
    
    def __init__(self, code: int, message: str, data: Optional[Any] = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)
    
    @classmethod
    def invalid_params(cls, message: str) -> "RequestError":
        """Create invalid params error (-32602)"""
        return cls(-32602, message)
    
    @classmethod
    def auth_required(cls) -> "RequestError":
        """Create auth required error"""
        return cls(-32001, "Authentication required")


class ACPSessionManager:
    """
    ACP session manager
    
    Manages ACP sessions and their state.
    Matches TypeScript ACPSessionManager class.
    """
    
    def __init__(self, sdk: Any):
        """
        Initialize session manager
        
        Args:
            sdk: Flocks SDK client instance
        """
        self._sessions: Dict[str, ACPSessionState] = {}
        self._sdk = sdk
        self._current_session_id: Optional[str] = None
    
    def try_get(self, session_id: str) -> Optional[ACPSessionState]:
        """
        Try to get a session by ID
        
        Args:
            session_id: Session ID
            
        Returns:
            Session state or None if not found
        """
        return self._sessions.get(session_id)
    
    def get_current_session_id(self) -> Optional[str]:
        """
        Get current session ID
        
        Returns:
            Current session ID or None
        """
        return self._current_session_id
    
    async def create(
        self,
        cwd: str,
        mcp_servers: List[McpServer],
        model: Optional[Dict[str, str]] = None
    ) -> ACPSessionState:
        """
        Create a new ACP session
        
        Args:
            cwd: Working directory
            mcp_servers: MCP server configurations
            model: Optional default model {"providerID": str, "modelID": str}
            
        Returns:
            Created session state
        """
        import uuid
        
        # Create session via SDK
        session = await self._sdk.session.create(
            title=f"ACP Session {uuid.uuid4()}",
            directory=cwd,
        )
        
        session_id = session.id
        
        state = ACPSessionState(
            id=session_id,
            cwd=cwd,
            mcp_servers=mcp_servers,
            created_at=datetime.now(),
            model=model,
        )
        
        log.info("session.created", {
            "session_id": session_id,
            "cwd": cwd,
            "mcp_servers": len(mcp_servers),
        })
        
        self._sessions[session_id] = state
        self._current_session_id = session_id  # Track current session
        return state
    
    async def load(
        self,
        session_id: str,
        cwd: str,
        mcp_servers: List[McpServer],
        model: Optional[Dict[str, str]] = None
    ) -> ACPSessionState:
        """
        Load an existing ACP session
        
        Args:
            session_id: Session ID to load
            cwd: Working directory
            mcp_servers: MCP server configurations
            model: Optional default model
            
        Returns:
            Loaded session state
        """
        # Load session via SDK
        session = await self._sdk.session.get(
            session_id=session_id,
            directory=cwd,
        )
        
        state = ACPSessionState(
            id=session_id,
            cwd=cwd,
            mcp_servers=mcp_servers,
            created_at=datetime.fromtimestamp(session.time.created / 1000),
            model=model,
        )
        
        log.info("session.loaded", {
            "session_id": session_id,
            "cwd": cwd,
        })
        
        self._sessions[session_id] = state
        self._current_session_id = session_id  # Track current session
        return state
    
    def get(self, session_id: str) -> ACPSessionState:
        """
        Get a session by ID
        
        Args:
            session_id: Session ID
            
        Returns:
            Session state
            
        Raises:
            RequestError: If session not found
        """
        session = self._sessions.get(session_id)
        if not session:
            log.error("session.not_found", {"session_id": session_id})
            raise RequestError.invalid_params(f"Session not found: {session_id}")
        return session
    
    def get_model(self, session_id: str) -> Optional[Dict[str, str]]:
        """
        Get model for a session
        
        Args:
            session_id: Session ID
            
        Returns:
            Model dict or None
        """
        session = self.get(session_id)
        return session.model
    
    def set_model(self, session_id: str, model: Dict[str, str]) -> ACPSessionState:
        """
        Set model for a session
        
        Args:
            session_id: Session ID
            model: Model dict {"providerID": str, "modelID": str}
            
        Returns:
            Updated session state
        """
        session = self.get(session_id)
        session.model = model
        self._sessions[session_id] = session
        return session
    
    def set_mode(self, session_id: str, mode_id: str) -> ACPSessionState:
        """
        Set mode (agent) for a session
        
        Args:
            session_id: Session ID
            mode_id: Mode/agent ID
            
        Returns:
            Updated session state
        """
        session = self.get(session_id)
        session.mode_id = mode_id
        self._sessions[session_id] = session
        return session
    
    def remove(self, session_id: str) -> bool:
        """
        Remove a session
        
        Args:
            session_id: Session ID
            
        Returns:
            True if removed, False if not found
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            log.info("session.removed", {"session_id": session_id})
            return True
        return False
