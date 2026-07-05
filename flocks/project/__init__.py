"""
Project management module

Provides project discovery, instance management, VCS integration, and bootstrapping
"""

from flocks.project.project import Project, ProjectInfo, ProjectIcon, ProjectTime
from flocks.project.instance import (
    Instance,
    InstanceContext,
    StateManager,
    get_current_directory,
    get_current_worktree,
    get_current_project,
)
from flocks.project.vcs import Vcs, VcsInfo, VcsDiff, VcsCommit, VcsStatus
from flocks.project.bootstrap import (
    Bootstrap,
    instance_bootstrap,
    detect_project_type,
    analyze_dependencies,
)

__all__ = [
    # Project
    "Project",
    "ProjectInfo",
    "ProjectIcon",
    "ProjectTime",
    # Instance
    "Instance",
    "InstanceContext",
    "StateManager",
    "get_current_directory",
    "get_current_worktree",
    "get_current_project",
    # VCS
    "Vcs",
    "VcsInfo",
    "VcsDiff",
    "VcsCommit",
    "VcsStatus",
    # Bootstrap
    "Bootstrap",
    "instance_bootstrap",
    "detect_project_type",
    "analyze_dependencies",
]
