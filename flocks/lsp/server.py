"""
LSP Server management

Defines and manages Language Server configurations.
Based on Flocks' ported src/lsp/server.ts
"""

from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
import subprocess
import shutil
import os
from pathlib import Path

from flocks.utils.log import Log
from flocks.lsp.client import LSPServerHandle

log = Log.create(service="lsp.server")


@dataclass
class LSPServerInfo:
    """LSP Server configuration"""
    id: str
    extensions: List[str]
    root: Callable[[str], Awaitable[Optional[str]]]
    spawn: Callable[[str], Awaitable[Optional[LSPServerHandle]]]


async def find_root_up(start: str, markers: List[str]) -> Optional[str]:
    """
    Find project root by searching up for marker files
    
    Args:
        start: Starting directory
        markers: List of marker files/directories to look for
        
    Returns:
        Root directory path or None
    """
    current = Path(start).resolve()
    
    while True:
        for marker in markers:
            if (current / marker).exists():
                return str(current)
        
        parent = current.parent
        if parent == current:
            break
        current = parent
    
    return None


def which(command: str) -> Optional[str]:
    """Find command in PATH"""
    return shutil.which(command)


async def spawn_process(
    command: List[str],
    cwd: str,
    env: Optional[Dict[str, str]] = None,
    initialization: Optional[Dict[str, Any]] = None,
) -> Optional[LSPServerHandle]:
    """
    Spawn an LSP server process
    
    Args:
        command: Command and arguments
        cwd: Working directory
        env: Environment variables
        initialization: Initialization options
        
    Returns:
        LSPServerHandle or None if failed
    """
    try:
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_env,
        )
        
        return LSPServerHandle(
            process=process,
            initialization=initialization,
        )
    except Exception as e:
        log.error("lsp.server.spawn_failed", {"command": command[0], "error": str(e)})
        return None


# TypeScript LSP Server
async def typescript_root(file: str) -> Optional[str]:
    """Find TypeScript project root"""
    return await find_root_up(os.path.dirname(file), [
        "tsconfig.json", "jsconfig.json", "package.json"
    ])


async def typescript_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn TypeScript language server"""
    # Try npx first
    if which("npx"):
        return await spawn_process(
            ["npx", "typescript-language-server", "--stdio"],
            root,
            initialization={
                "preferences": {
                    "includeInlayParameterNameHints": "all",
                    "includeInlayPropertyDeclarationTypeHints": True,
                    "includeInlayFunctionLikeReturnTypeHints": True,
                }
            }
        )
    
    # Try global installation
    cmd = which("typescript-language-server")
    if cmd:
        return await spawn_process([cmd, "--stdio"], root)
    
    return None


# Python LSP Server (Pyright)
async def pyright_root(file: str) -> Optional[str]:
    """Find Python project root"""
    return await find_root_up(os.path.dirname(file), [
        "pyproject.toml", "setup.py", "requirements.txt",
        "pyrightconfig.json", ".venv", "venv"
    ])


async def pyright_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn Pyright language server"""
    # Try npx
    if which("npx"):
        return await spawn_process(
            ["npx", "pyright-langserver", "--stdio"],
            root,
        )
    
    # Try pip installed
    cmd = which("pyright-langserver")
    if cmd:
        return await spawn_process([cmd, "--stdio"], root)
    
    return None


# Go LSP Server (gopls)
async def go_root(file: str) -> Optional[str]:
    """Find Go project root"""
    return await find_root_up(os.path.dirname(file), [
        "go.mod", "go.sum"
    ])


async def gopls_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn gopls language server"""
    cmd = which("gopls")
    if cmd:
        return await spawn_process([cmd], root)
    return None


# Rust LSP Server (rust-analyzer)
async def rust_root(file: str) -> Optional[str]:
    """Find Rust project root"""
    return await find_root_up(os.path.dirname(file), [
        "Cargo.toml"
    ])


async def rust_analyzer_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn rust-analyzer language server"""
    cmd = which("rust-analyzer")
    if cmd:
        return await spawn_process([cmd], root)
    return None


# Java LSP Server (jdtls)
async def java_root(file: str) -> Optional[str]:
    """Find Java project root"""
    return await find_root_up(os.path.dirname(file), [
        "pom.xml", "build.gradle", "build.gradle.kts", ".project"
    ])


async def jdtls_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn Eclipse JDT language server"""
    cmd = which("jdtls")
    if cmd:
        return await spawn_process([cmd], root)
    return None


# C/C++ LSP Server (clangd)
async def cpp_root(file: str) -> Optional[str]:
    """Find C/C++ project root"""
    return await find_root_up(os.path.dirname(file), [
        "compile_commands.json", "CMakeLists.txt", "Makefile",
        ".clangd", ".clang-format"
    ])


async def clangd_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn clangd language server"""
    cmd = which("clangd")
    if cmd:
        return await spawn_process([cmd], root)
    return None


# Ruby LSP Server (solargraph)
async def ruby_root(file: str) -> Optional[str]:
    """Find Ruby project root"""
    return await find_root_up(os.path.dirname(file), [
        "Gemfile", ".ruby-version"
    ])


async def solargraph_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn Solargraph language server"""
    cmd = which("solargraph")
    if cmd:
        return await spawn_process([cmd, "stdio"], root)
    return None


# Vue LSP Server (volar)
async def vue_root(file: str) -> Optional[str]:
    """Find Vue project root"""
    return await find_root_up(os.path.dirname(file), [
        "vite.config.ts", "vite.config.js", "vue.config.js", "package.json"
    ])


async def volar_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn Vue Language Server"""
    if which("npx"):
        return await spawn_process(
            ["npx", "@vue/language-server", "--stdio"],
            root,
        )
    return None


# Svelte LSP Server
async def svelte_root(file: str) -> Optional[str]:
    """Find Svelte project root"""
    return await find_root_up(os.path.dirname(file), [
        "svelte.config.js", "svelte.config.ts", "package.json"
    ])


async def svelte_spawn(root: str) -> Optional[LSPServerHandle]:
    """Spawn Svelte language server"""
    if which("npx"):
        return await spawn_process(
            ["npx", "svelte-language-server", "--stdio"],
            root,
        )
    return None


# Default LSP servers
SERVERS: Dict[str, LSPServerInfo] = {
    "typescript": LSPServerInfo(
        id="typescript",
        extensions=[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
        root=typescript_root,
        spawn=typescript_spawn,
    ),
    "pyright": LSPServerInfo(
        id="pyright",
        extensions=[".py"],
        root=pyright_root,
        spawn=pyright_spawn,
    ),
    "gopls": LSPServerInfo(
        id="gopls",
        extensions=[".go"],
        root=go_root,
        spawn=gopls_spawn,
    ),
    "rust-analyzer": LSPServerInfo(
        id="rust-analyzer",
        extensions=[".rs"],
        root=rust_root,
        spawn=rust_analyzer_spawn,
    ),
    "jdtls": LSPServerInfo(
        id="jdtls",
        extensions=[".java"],
        root=java_root,
        spawn=jdtls_spawn,
    ),
    "clangd": LSPServerInfo(
        id="clangd",
        extensions=[".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"],
        root=cpp_root,
        spawn=clangd_spawn,
    ),
    "solargraph": LSPServerInfo(
        id="solargraph",
        extensions=[".rb", ".rake"],
        root=ruby_root,
        spawn=solargraph_spawn,
    ),
    "volar": LSPServerInfo(
        id="volar",
        extensions=[".vue"],
        root=vue_root,
        spawn=volar_spawn,
    ),
    "svelte": LSPServerInfo(
        id="svelte",
        extensions=[".svelte"],
        root=svelte_root,
        spawn=svelte_spawn,
    ),
}


class LSPServer:
    """
    LSP Server management namespace
    """
    
    @classmethod
    def list(cls) -> Dict[str, LSPServerInfo]:
        """Get all registered LSP servers"""
        return SERVERS.copy()
    
    @classmethod
    def get(cls, server_id: str) -> Optional[LSPServerInfo]:
        """Get LSP server by ID"""
        return SERVERS.get(server_id)
    
    @classmethod
    def get_for_extension(cls, extension: str) -> List[LSPServerInfo]:
        """Get all LSP servers that handle the given extension"""
        result = []
        for server in SERVERS.values():
            if extension in server.extensions:
                result.append(server)
        return result
    
    @classmethod
    def register(
        cls,
        server_id: str,
        extensions: List[str],
        command: List[str],
        env: Optional[Dict[str, str]] = None,
        initialization: Optional[Dict[str, Any]] = None,
        root_markers: Optional[List[str]] = None,
    ) -> None:
        """
        Register a custom LSP server
        
        Args:
            server_id: Server identifier
            extensions: File extensions to handle
            command: Command to spawn server
            env: Environment variables
            initialization: Initialization options
            root_markers: Files/dirs to find project root
        """
        async def custom_root(file: str) -> Optional[str]:
            markers = root_markers or [".git", "package.json"]
            return await find_root_up(os.path.dirname(file), markers)
        
        async def custom_spawn(root: str) -> Optional[LSPServerHandle]:
            return await spawn_process(command, root, env, initialization)
        
        SERVERS[server_id] = LSPServerInfo(
            id=server_id,
            extensions=extensions,
            root=custom_root,
            spawn=custom_spawn,
        )
        
        log.info("lsp.server.registered", {"server_id": server_id, "extensions": extensions})
    
    @classmethod
    def unregister(cls, server_id: str) -> bool:
        """
        Unregister an LSP server
        
        Args:
            server_id: Server identifier
            
        Returns:
            True if unregistered
        """
        if server_id in SERVERS:
            del SERVERS[server_id]
            return True
        return False
