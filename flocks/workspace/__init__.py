"""
Workspace module

Manages the user-facing workspace directory (~/.flocks/workspace/).
Provides file management for uploads, agent outputs, and knowledge base files.
"""

from flocks.workspace.manager import WorkspaceManager

__all__ = ["WorkspaceManager"]
