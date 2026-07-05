"""
Project Bootstrap module

Handles project initialization and subsystem startup
"""

import asyncio
from typing import Optional, Callable, Awaitable, List

from flocks.utils.log import Log
from flocks.project.instance import Instance
from flocks.project.vcs import Vcs

log = Log.create(service="project.bootstrap")


class Bootstrap:
    """
    Project bootstrap namespace
    
    Handles initialization of various subsystems when a project instance
    is created or resumed.
    """
    
    # Registry of bootstrap handlers
    _handlers: List[Callable[[], Awaitable[None]]] = []
    _initialized: bool = False
    
    @classmethod
    def register(cls, handler: Callable[[], Awaitable[None]]) -> None:
        """
        Register a bootstrap handler
        
        Handlers are called during instance bootstrap to initialize subsystems.
        
        Args:
            handler: Async function to call during bootstrap
        """
        cls._handlers.append(handler)
    
    @classmethod
    async def run(cls) -> None:
        """
        Run all bootstrap handlers
        
        This should be called after an Instance is created to initialize
        all registered subsystems.
        """
        if cls._initialized:
            return
        
        directory = Instance.get_directory()
        log.info("bootstrap.starting", {"directory": directory})
        
        # Run all handlers
        for handler in cls._handlers:
            try:
                await handler()
            except Exception as e:
                log.error("bootstrap.handler.error", {
                    "handler": handler.__name__,
                    "error": str(e)
                })
        
        cls._initialized = True
        log.info("bootstrap.complete", {"directory": directory})
    
    @classmethod
    def reset(cls) -> None:
        """Reset bootstrap state (for testing)"""
        cls._initialized = False


async def _init_vcs() -> None:
    """Initialize VCS subsystem"""
    worktree = Instance.get_worktree()
    if not worktree:
        return
    
    # Get initial branch
    branch = await Vcs.get_branch(worktree)
    log.info("vcs.initialized", {"branch": branch})


# Register default handlers
Bootstrap.register(_init_vcs)


async def instance_bootstrap() -> None:
    """
    Bootstrap a new project instance
    
    This function initializes all subsystems for a project instance.
    It should be called as the init function when creating an Instance.
    
    Initializes:
    - VCS (version control)
    - MCP (Model Context Protocol)
    - LSP (language server)
    - File watcher
    """
    directory = Instance.get_directory()
    log.info("bootstrapping", {"directory": directory})
    
    # Run registered bootstrap handlers
    await Bootstrap.run()
    
    # Initialize MCP subsystem (per-instance)
    try:
        from flocks.mcp import MCP
        await MCP.init()
        log.info("mcp.initialized", {"directory": directory})
    except Exception as e:
        log.warn("mcp.init.failed", {"directory": directory, "error": str(e)})
    
    log.info("bootstrap.finished", {"directory": directory})


async def detect_project_type(directory: str) -> dict:
    """
    Detect project type and characteristics
    
    Args:
        directory: Project directory
        
    Returns:
        Dict with project type information
    """
    import os
    from pathlib import Path
    
    info = {
        "languages": [],
        "frameworks": [],
        "package_managers": [],
        "has_git": False,
        "has_docker": False,
        "has_tests": False,
    }
    
    path = Path(directory)
    
    # Check for Git
    if (path / ".git").exists():
        info["has_git"] = True
    
    # Check for Docker
    if (path / "Dockerfile").exists() or (path / "docker-compose.yml").exists():
        info["has_docker"] = True
    
    # Python detection
    if (path / "requirements.txt").exists():
        info["languages"].append("python")
        info["package_managers"].append("pip")
    
    if (path / "pyproject.toml").exists():
        info["languages"].append("python")
        info["package_managers"].append("poetry" if "poetry" in (path / "pyproject.toml").read_text() else "pip")
    
    if (path / "setup.py").exists():
        info["languages"].append("python")
        info["package_managers"].append("pip")
    
    # JavaScript/TypeScript detection
    if (path / "package.json").exists():
        content = (path / "package.json").read_text()
        
        if ".ts" in content or (path / "tsconfig.json").exists():
            info["languages"].append("typescript")
        else:
            info["languages"].append("javascript")
        
        if (path / "yarn.lock").exists():
            info["package_managers"].append("yarn")
        elif (path / "pnpm-lock.yaml").exists():
            info["package_managers"].append("pnpm")
        elif (path / "bun.lockb").exists():
            info["package_managers"].append("bun")
        else:
            info["package_managers"].append("npm")
        
        # Framework detection
        if "react" in content:
            info["frameworks"].append("react")
        if "vue" in content:
            info["frameworks"].append("vue")
        if "next" in content:
            info["frameworks"].append("nextjs")
        if "express" in content:
            info["frameworks"].append("express")
        if "fastify" in content:
            info["frameworks"].append("fastify")
    
    # Go detection
    if (path / "go.mod").exists():
        info["languages"].append("go")
        info["package_managers"].append("go mod")
    
    # Rust detection
    if (path / "Cargo.toml").exists():
        info["languages"].append("rust")
        info["package_managers"].append("cargo")
    
    # Java detection
    if (path / "pom.xml").exists():
        info["languages"].append("java")
        info["package_managers"].append("maven")
    elif (path / "build.gradle").exists():
        info["languages"].append("java")
        info["package_managers"].append("gradle")
    
    # Ruby detection
    if (path / "Gemfile").exists():
        info["languages"].append("ruby")
        info["package_managers"].append("bundler")
    
    # Test detection
    test_dirs = ["tests", "test", "spec", "__tests__"]
    for test_dir in test_dirs:
        if (path / test_dir).exists():
            info["has_tests"] = True
            break
    
    # De-duplicate
    info["languages"] = list(set(info["languages"]))
    info["frameworks"] = list(set(info["frameworks"]))
    info["package_managers"] = list(set(info["package_managers"]))
    
    return info


async def analyze_dependencies(directory: str) -> dict:
    """
    Analyze project dependencies
    
    Args:
        directory: Project directory
        
    Returns:
        Dict with dependency information
    """
    from pathlib import Path
    import json
    
    deps = {
        "production": [],
        "development": [],
        "total": 0,
    }
    
    path = Path(directory)
    
    # Python dependencies
    requirements_file = path / "requirements.txt"
    if requirements_file.exists():
        content = requirements_file.read_text()
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract package name
                name = line.split('==')[0].split('>=')[0].split('<=')[0].split('[')[0]
                deps["production"].append(name)
    
    # JavaScript dependencies
    package_json = path / "package.json"
    if package_json.exists():
        try:
            content = json.loads(package_json.read_text())
            
            if "dependencies" in content:
                deps["production"].extend(content["dependencies"].keys())
            
            if "devDependencies" in content:
                deps["development"].extend(content["devDependencies"].keys())
        except Exception:
            pass
    
    deps["total"] = len(deps["production"]) + len(deps["development"])
    
    return deps
