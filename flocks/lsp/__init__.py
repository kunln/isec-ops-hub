"""
LSP (Language Server Protocol) module

Provides language intelligence features like code completion,
go to definition, find references, diagnostics, etc.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import asyncio
import os
from pathlib import Path
from urllib.parse import quote, unquote

from flocks.utils.log import Log
from flocks.lsp.language import (
    LANGUAGE_EXTENSIONS,
    get_language_id,
    get_language_for_file,
    SymbolKind,
    SEARCHABLE_SYMBOL_KINDS,
    DiagnosticSeverity,
)
from flocks.lsp.client import (
    LSPClient,
    LSPClientInfo,
    LSPServerHandle,
    Diagnostic,
    Range,
)
from flocks.lsp.server import (
    LSPServer,
    LSPServerInfo,
    SERVERS,
)


log = Log.create(service="lsp")


@dataclass
class LSPState:
    """Global LSP state"""
    clients: List[LSPClientInfo] = field(default_factory=list)
    servers: Dict[str, LSPServerInfo] = field(default_factory=dict)
    broken: Set[str] = field(default_factory=set)
    spawning: Dict[str, asyncio.Task] = field(default_factory=dict)
    enabled: bool = True


# Global state
_state: Optional[LSPState] = None


async def init(config: Optional[Dict[str, Any]] = None) -> LSPState:
    """
    Initialize LSP subsystem
    
    Args:
        config: Optional LSP configuration
        
    Returns:
        LSP state
    """
    global _state
    
    if _state is not None:
        return _state
    
    _state = LSPState()
    
    # Check if LSP is disabled
    if config and config.get("lsp") is False:
        log.info("lsp.disabled")
        _state.enabled = False
        return _state
    
    # Load default servers
    _state.servers = LSPServer.list()
    
    # Apply custom configuration
    if config and isinstance(config.get("lsp"), dict):
        for name, server_config in config["lsp"].items():
            if server_config.get("disabled"):
                log.info("lsp.server.disabled", {"server_id": name})
                _state.servers.pop(name, None)
                continue
            
            # Register custom server
            if "command" in server_config:
                LSPServer.register(
                    server_id=name,
                    extensions=server_config.get("extensions", []),
                    command=server_config["command"],
                    env=server_config.get("env"),
                    initialization=server_config.get("initialization"),
                )
                _state.servers[name] = LSPServer.get(name)
    
    log.info("lsp.initialized", {
        "servers": list(_state.servers.keys()),
    })
    
    return _state


async def shutdown() -> None:
    """Shutdown all LSP clients"""
    global _state
    
    if _state is None:
        return
    
    log.info("lsp.shutting_down")
    
    # Shutdown all clients
    for client in _state.clients:
        await LSPClient.shutdown(client)
    
    _state = None


async def _get_clients(file: str) -> List[LSPClientInfo]:
    """Get or create LSP clients for a file"""
    global _state
    
    if _state is None or not _state.enabled:
        return []
    
    extension = os.path.splitext(file)[1] or file
    result: List[LSPClientInfo] = []
    
    for server in _state.servers.values():
        # Check if server handles this extension
        if server.extensions and extension not in server.extensions:
            continue
        
        # Find project root
        root = await server.root(file)
        if not root:
            continue
        
        key = f"{root}:{server.id}"
        
        # Skip if known broken
        if key in _state.broken:
            continue
        
        # Check for existing client
        existing = next(
            (c for c in _state.clients if c.root == root and c.server_id == server.id),
            None
        )
        if existing:
            result.append(existing)
            continue
        
        # Check if already spawning
        if key in _state.spawning:
            try:
                client = await _state.spawning[key]
                if client:
                    result.append(client)
            except Exception:
                pass
            continue
        
        # Spawn new client
        async def spawn_client():
            try:
                handle = await server.spawn(root)
                if not handle:
                    _state.broken.add(key)
                    return None
                
                client = await LSPClient.create(
                    server_id=server.id,
                    server=handle,
                    root=root,
                )
                
                if client:
                    _state.clients.append(client)
                    return client
                else:
                    _state.broken.add(key)
                    return None
                    
            except Exception as e:
                log.error("lsp.spawn_failed", {"server_id": server.id, "error": str(e)})
                _state.broken.add(key)
                return None
        
        task = asyncio.create_task(spawn_client())
        _state.spawning[key] = task
        
        try:
            client = await task
            if client:
                result.append(client)
        finally:
            _state.spawning.pop(key, None)
    
    return result


async def status() -> List[Dict[str, Any]]:
    """
    Get status of all active LSP clients
    
    Returns:
        List of status objects
    """
    global _state
    
    if _state is None:
        return []
    
    result = []
    for client in _state.clients:
        server = _state.servers.get(client.server_id)
        result.append({
            "id": client.server_id,
            "name": server.id if server else client.server_id,
            "root": client.root,
            "status": "connected",
        })
    
    return result


async def touch_file(file: str, wait_for_diagnostics: bool = False) -> None:
    """
    Notify LSP servers that a file was opened/changed
    
    Args:
        file: File path
        wait_for_diagnostics: Wait for diagnostics to be computed
    """
    log.info("lsp.touch_file", {"file": file})
    
    clients = await _get_clients(file)
    
    for client in clients:
        try:
            if wait_for_diagnostics:
                wait_task = asyncio.create_task(
                    LSPClient.wait_for_diagnostics(client, file)
                )
            
            await LSPClient.open_file(client, file)
            
            if wait_for_diagnostics:
                await wait_task
                
        except Exception as e:
            log.error("lsp.touch_file.error", {"file": file, "error": str(e)})


async def diagnostics() -> Dict[str, List[Diagnostic]]:
    """
    Get all diagnostics from all clients
    
    Returns:
        Dict mapping file paths to diagnostics
    """
    global _state
    
    if _state is None:
        return {}
    
    result: Dict[str, List[Diagnostic]] = {}
    
    for client in _state.clients:
        for path, diags in client.diagnostics.items():
            if path not in result:
                result[path] = []
            result[path].extend(diags)
    
    return result


async def hover(file: str, line: int, character: int) -> Optional[Dict[str, Any]]:
    """
    Get hover information at position
    
    Args:
        file: File path
        line: Line number (0-based)
        character: Character offset (0-based)
        
    Returns:
        Hover information or None
    """
    clients = await _get_clients(file)
    
    for client in clients:
        result = await LSPClient.hover(client, file, line, character)
        if result:
            return result
    
    return None


async def definition(file: str, line: int, character: int) -> List[Dict[str, Any]]:
    """
    Get definition locations
    
    Args:
        file: File path
        line: Line number (0-based)
        character: Character offset (0-based)
        
    Returns:
        List of location objects
    """
    clients = await _get_clients(file)
    results = []
    
    for client in clients:
        locs = await LSPClient.definition(client, file, line, character)
        results.extend(locs)
    
    return results


async def references(file: str, line: int, character: int) -> List[Dict[str, Any]]:
    """
    Get reference locations
    
    Args:
        file: File path
        line: Line number (0-based)
        character: Character offset (0-based)
        
    Returns:
        List of location objects
    """
    clients = await _get_clients(file)
    results = []
    
    for client in clients:
        refs = await LSPClient.references(client, file, line, character)
        results.extend(refs)
    
    return results


async def workspace_symbol(query: str) -> List[Dict[str, Any]]:
    """
    Search for symbols in workspace
    
    Args:
        query: Search query
        
    Returns:
        List of symbol objects
    """
    global _state
    
    if _state is None:
        return []
    
    results = []
    
    for client in _state.clients:
        symbols = await LSPClient.workspace_symbol(client, query)
        # Filter to searchable kinds
        filtered = [s for s in symbols if s.get("kind") in SEARCHABLE_SYMBOL_KINDS]
        results.extend(filtered[:10])  # Limit per client
    
    return results


async def document_symbol(file: str) -> List[Dict[str, Any]]:
    """
    Get symbols in document
    
    Args:
        file: File path
        
    Returns:
        List of symbol objects
    """
    # Convert file URI if needed
    if file.startswith("file://"):
        file = unquote(file[7:])
    
    clients = await _get_clients(file)
    results = []
    
    for client in clients:
        symbols = await LSPClient.document_symbol(client, file)
        results.extend(symbols)
    
    return [s for s in results if s]


async def has_clients(file: str) -> bool:
    """
    Check if any LSP servers can handle the file
    
    Args:
        file: File path
        
    Returns:
        True if clients available
    """
    global _state
    
    if _state is None or not _state.enabled:
        return False
    
    extension = os.path.splitext(file)[1] or file
    
    for server in _state.servers.values():
        if server.extensions and extension not in server.extensions:
            continue
        
        root = await server.root(file)
        if root:
            key = f"{root}:{server.id}"
            if key not in _state.broken:
                return True
    
    return False


# Re-export commonly used items
__all__ = [
    # Functions
    "init",
    "shutdown",
    "status",
    "touch_file",
    "diagnostics",
    "hover",
    "definition",
    "references",
    "workspace_symbol",
    "document_symbol",
    "has_clients",
    # Types
    "Diagnostic",
    "Range",
    "LSPServerInfo",
    "LSPClientInfo",
    # Constants
    "SymbolKind",
    "DiagnosticSeverity",
    "LANGUAGE_EXTENSIONS",
]
