"""
Workspace Manager

Manages ~/.flocks/workspace/ — the user-facing file storage for:
- outputs/     : agent-generated task artifacts (organized by session_id)
- knowledge/   : user-curated knowledge base (future: vector indexing)

Memory files stay in ~/.flocks/data/memory/ (agent-managed, not migrated).
This manager provides a read-only view into data/memory/ for the WebUI.
"""

import os
from pathlib import Path
from typing import Optional

from flocks.utils.log import Log

log = Log.create(service="workspace.manager")

# Extensions treated as plain-text (previewable + editable in WebUI).
# Note: dotfiles like .gitignore have suffix='' in Python, so they are NOT
# matched here; they will fall through to the binary-file path (download only).
TEXT_EXTENSIONS = {
    ".md", ".txt", ".log", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".py", ".js", ".ts",
    ".sh", ".bash", ".csv", ".xml", ".html", ".css",
    ".tsx", ".jsx", ".env",
    ".sql", ".rs", ".go", ".java", ".c", ".cpp", ".h",
}

# Conventional subdirectories (created on init, not enforced)
CONVENTION_DIRS = ["outputs", "knowledge"]


def _get_workspace_dir() -> Path:
    """
    Resolve workspace directory.

    Priority:
    1. FLOCKS_WORKSPACE_DIR environment variable
    2. ~/.flocks/workspace (default, adjacent to data/ logs/ plugins/)
    """
    override = os.getenv("FLOCKS_WORKSPACE_DIR")
    if override:
        return Path(override)

    from flocks.config.config import Config
    # data_dir is ~/.flocks/data; workspace is sibling of data/
    return Config.get_data_path().parent / "workspace"


class WorkspaceManager:
    """
    Singleton manager for the workspace directory.

    All path arguments accepted by public methods are relative to the
    workspace root (or memory root for memory methods).  Absolute paths
    are rejected to prevent path traversal attacks.
    """

    _instance: Optional["WorkspaceManager"] = None

    def __init__(self) -> None:
        self._workspace_dir: Optional[Path] = None
        self._memory_dir: Optional[Path] = None
        self._dirs_ensured: bool = False

    @classmethod
    def get_instance(cls) -> "WorkspaceManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------ #
    # Directory resolution
    # ------------------------------------------------------------------ #

    def get_workspace_dir(self) -> Path:
        if self._workspace_dir is None:
            self._workspace_dir = _get_workspace_dir()
        return self._workspace_dir

    def get_memory_dir(self) -> Path:
        """Return path to agent-managed memory directory (read-only view)."""
        if self._memory_dir is None:
            from flocks.config.config import Config
            self._memory_dir = Config.get_data_path() / "memory"
        return self._memory_dir

    def ensure_dirs(self) -> None:
        """Create workspace root and conventional subdirectories if absent.

        Idempotent: a boolean flag prevents redundant syscalls after the
        first successful call within the same process lifetime.
        """
        if self._dirs_ensured:
            return
        workspace = self.get_workspace_dir()
        workspace.mkdir(parents=True, exist_ok=True)
        for name in CONVENTION_DIRS:
            (workspace / name).mkdir(exist_ok=True)
        self._dirs_ensured = True
        log.info("workspace.dirs.ensured", {"path": str(workspace)})

    # ------------------------------------------------------------------ #
    # Path safety
    # ------------------------------------------------------------------ #

    def resolve_workspace_path(self, rel_path: str) -> Path:
        """
        Resolve a relative path inside the workspace root.

        Raises ValueError if the resolved path escapes the workspace.
        Uses Path.is_relative_to() (Python 3.9+) to avoid the prefix-match
        pitfall where '/tmp/ws_evil' would wrongly pass a startswith check
        against '/tmp/ws'.
        """
        workspace = self.get_workspace_dir().resolve()
        if Path(rel_path).is_absolute():
            raise ValueError(f"Absolute paths not allowed: {rel_path}")
        resolved = (workspace / rel_path).resolve()
        if not resolved.is_relative_to(workspace):
            raise ValueError(f"Path traversal detected: {rel_path}")
        return resolved

    def resolve_memory_path(self, rel_path: str) -> Path:
        """
        Resolve a relative path inside the memory root (read-only).

        Raises ValueError if the resolved path escapes memory root.
        Uses Path.is_relative_to() (Python 3.9+) for safe boundary checks.
        """
        memory = self.get_memory_dir().resolve()
        if Path(rel_path).is_absolute():
            raise ValueError(f"Absolute paths not allowed: {rel_path}")
        resolved = (memory / rel_path).resolve()
        if not resolved.is_relative_to(memory):
            raise ValueError(f"Path traversal detected: {rel_path}")
        return resolved

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def is_text_file(path: Path) -> bool:
        return path.suffix.lower() in TEXT_EXTENSIONS
