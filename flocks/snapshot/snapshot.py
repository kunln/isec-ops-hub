"""
Snapshot system

Git-based snapshot functionality for tracking and reverting file changes.
Based on Flocks' ported src/snapshot/index.ts

The snapshot system uses a separate Git repository (stored in data directory)
to track file changes independently of the project's main Git repository.
"""

import asyncio
import os
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field

from flocks.utils.log import Log
from flocks.config.config import Config

log = Log.create(service="snapshot")

# Constants
PRUNE_DAYS = "7.days"
CLEANUP_INTERVAL_HOURS = 1


class SnapshotPatch(BaseModel):
    """Snapshot patch information"""
    hash: str = Field(..., description="Git tree hash")
    files: List[str] = Field(default_factory=list, description="Changed file paths")


class FileDiff(BaseModel):
    """File diff information"""
    file: str = Field(..., description="File path relative to worktree")
    before: str = Field("", description="Content before change")
    after: str = Field("", description="Content after change")
    additions: int = Field(0, description="Lines added")
    deletions: int = Field(0, description="Lines deleted")


class Snapshot:
    """
    Snapshot namespace for Git-based file tracking
    
    Uses a separate Git repository to track file changes, allowing
    for independent versioning and rollback capabilities.
    """
    
    # Class-level state
    _initialized: bool = False
    _cleanup_task: Optional[asyncio.Task] = None
    
    @classmethod
    def init(cls, project_id: str, worktree: str) -> None:
        """
        Initialize snapshot system with cleanup scheduler
        
        Args:
            project_id: Project ID for snapshot storage
            worktree: Working tree directory
        """
        if cls._initialized:
            return
        
        cls._initialized = True
        log.info("snapshot.init", {"project_id": project_id})
    
    @classmethod
    async def cleanup(cls, project_id: str, worktree: str) -> None:
        """
        Clean up old snapshots using git gc
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
        """
        cfg = await Config.get()
        if cfg.snapshot is False:
            return
        
        git_dir = cls._gitdir(project_id)
        
        # Check if git directory exists
        if not os.path.exists(git_dir):
            return
        
        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                f"--git-dir={git_dir}",
                f"--work-tree={worktree}",
                "gc",
                f"--prune={PRUNE_DAYS}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=worktree,
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                log.warn("snapshot.cleanup.failed", {
                    "exit_code": process.returncode,
                    "stderr": stderr.decode("utf-8", errors="replace"),
                })
                return
            
            log.info("snapshot.cleanup", {"prune": PRUNE_DAYS})
            
        except Exception as e:
            log.error("snapshot.cleanup.error", {"error": str(e)})
    
    @classmethod
    async def track(cls, project_id: str, worktree: str, vcs: str = "git") -> Optional[str]:
        """
        Track current state and return tree hash
        
        Creates a Git tree object representing the current file state.
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
            vcs: VCS type (only 'git' supported)
            
        Returns:
            Git tree hash or None if failed
        """
        if vcs != "git":
            return None
        
        cfg = await Config.get()
        if cfg.snapshot is False:
            return None
        
        git_dir = cls._gitdir(project_id)
        
        # Initialize git repository if needed
        if not os.path.exists(git_dir):
            os.makedirs(git_dir, exist_ok=True)
            
            # Initialize bare-like git repo
            process = await asyncio.create_subprocess_exec(
                "git", "init",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "GIT_DIR": git_dir, "GIT_WORK_TREE": worktree},
            )
            await process.communicate()
            
            # Configure git to not convert line endings
            await cls._run_git(
                ["config", "core.autocrlf", "false"],
                git_dir, worktree
            )
            
            log.info("snapshot.initialized", {"git_dir": git_dir})
        
        # Add all files
        await cls._run_git(["add", "."], git_dir, worktree)
        
        # Create tree object
        result = await cls._run_git(["write-tree"], git_dir, worktree)
        
        if result is None:
            return None
        
        tree_hash = result.strip()
        log.info("snapshot.tracking", {"hash": tree_hash, "worktree": worktree})
        
        return tree_hash
    
    @classmethod
    async def patch(cls, project_id: str, worktree: str, hash: str) -> SnapshotPatch:
        """
        Get list of changed files since snapshot
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
            hash: Git tree hash to compare against
            
        Returns:
            Patch information with changed files
        """
        git_dir = cls._gitdir(project_id)
        
        # Add all files first
        await cls._run_git(["add", "."], git_dir, worktree)
        
        # Get changed files
        result = await cls._run_git(
            ["-c", "core.autocrlf=false", "diff", "--no-ext-diff", "--name-only", hash, "--", "."],
            git_dir, worktree
        )
        
        if result is None:
            log.warn("snapshot.patch.failed", {"hash": hash})
            return SnapshotPatch(hash=hash, files=[])
        
        files = [
            os.path.join(worktree, f.strip())
            for f in result.strip().split("\n")
            if f.strip()
        ]
        
        return SnapshotPatch(hash=hash, files=files)
    
    @classmethod
    async def restore(cls, project_id: str, worktree: str, snapshot: str) -> bool:
        """
        Restore files to a snapshot state
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
            snapshot: Git tree hash to restore
            
        Returns:
            True if successful
        """
        log.info("snapshot.restore", {"snapshot": snapshot})
        git_dir = cls._gitdir(project_id)
        
        # Read tree and checkout
        # Combined command: read-tree + checkout-index
        result = await cls._run_git(["read-tree", snapshot], git_dir, worktree)
        if result is None:
            log.error("snapshot.restore.read_tree.failed", {"snapshot": snapshot})
            return False
        
        result = await cls._run_git(["checkout-index", "-a", "-f"], git_dir, worktree)
        if result is None:
            log.error("snapshot.restore.checkout.failed", {"snapshot": snapshot})
            return False
        
        return True
    
    @classmethod
    async def revert(cls, project_id: str, worktree: str, patches: List[SnapshotPatch]) -> None:
        """
        Revert specific files to their snapshot states
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
            patches: List of patches to revert
        """
        reverted_files = set()
        git_dir = cls._gitdir(project_id)
        
        for patch in patches:
            for file in patch.files:
                if file in reverted_files:
                    continue
                
                log.info("snapshot.reverting", {"file": file, "hash": patch.hash})
                
                # Try to checkout file from snapshot
                result = await cls._run_git(
                    ["checkout", patch.hash, "--", file],
                    git_dir, worktree
                )
                
                if result is None:
                    # Check if file existed in snapshot
                    relative_path = os.path.relpath(file, worktree)
                    check_result = await cls._run_git(
                        ["ls-tree", patch.hash, "--", relative_path],
                        git_dir, worktree
                    )
                    
                    if check_result and check_result.strip():
                        log.info("snapshot.revert.file_existed_but_failed", {"file": file})
                    else:
                        # File didn't exist in snapshot, delete it
                        log.info("snapshot.revert.deleting", {"file": file})
                        try:
                            os.unlink(file)
                        except OSError:
                            pass
                
                reverted_files.add(file)
    
    @classmethod
    async def diff(cls, project_id: str, worktree: str, hash: str) -> str:
        """
        Get diff between snapshot and current state
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
            hash: Git tree hash to compare against
            
        Returns:
            Diff text
        """
        git_dir = cls._gitdir(project_id)
        
        # Add all files first
        await cls._run_git(["add", "."], git_dir, worktree)
        
        # Get diff
        result = await cls._run_git(
            ["-c", "core.autocrlf=false", "diff", "--no-ext-diff", hash, "--", "."],
            git_dir, worktree
        )
        
        if result is None:
            log.warn("snapshot.diff.failed", {"hash": hash})
            return ""
        
        return result.strip()
    
    @classmethod
    async def diff_full(
        cls,
        project_id: str,
        worktree: str,
        from_hash: str,
        to_hash: str
    ) -> List[FileDiff]:
        """
        Get full file diffs between two snapshots
        
        Args:
            project_id: Project ID
            worktree: Working tree directory
            from_hash: Starting Git tree hash
            to_hash: Ending Git tree hash
            
        Returns:
            List of file diffs with before/after content
        """
        git_dir = cls._gitdir(project_id)
        result: List[FileDiff] = []
        
        # Get numstat diff
        numstat = await cls._run_git(
            ["-c", "core.autocrlf=false", "diff", "--no-ext-diff", "--no-renames",
             "--numstat", from_hash, to_hash, "--", "."],
            git_dir, worktree
        )
        
        if numstat is None:
            return result
        
        for line in numstat.strip().split("\n"):
            if not line:
                continue
            
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            
            additions_str, deletions_str, file_path = parts[0], parts[1], parts[2]
            
            # Handle binary files
            is_binary = additions_str == "-" and deletions_str == "-"
            
            if is_binary:
                before = ""
                after = ""
                additions = 0
                deletions = 0
            else:
                # Get file content at each revision
                before = await cls._run_git(
                    ["show", f"{from_hash}:{file_path}"],
                    git_dir, worktree
                ) or ""
                
                after = await cls._run_git(
                    ["show", f"{to_hash}:{file_path}"],
                    git_dir, worktree
                ) or ""
                
                try:
                    additions = int(additions_str)
                    deletions = int(deletions_str)
                except ValueError:
                    additions = 0
                    deletions = 0
            
            result.append(FileDiff(
                file=file_path,
                before=before,
                after=after,
                additions=additions,
                deletions=deletions,
            ))
        
        return result
    
    @classmethod
    def _gitdir(cls, project_id: str) -> str:
        """
        Get git directory path for project
        
        Args:
            project_id: Project ID
            
        Returns:
            Path to git directory
        """
        data_path = Config.get_data_path()
        return os.path.join(data_path, "snapshot", project_id)
    
    @classmethod
    async def _run_git(
        cls,
        args: List[str],
        git_dir: str,
        worktree: str,
        timeout: float = 30.0
    ) -> Optional[str]:
        """
        Run a Git command with custom git-dir and work-tree
        
        Args:
            args: Git command arguments
            git_dir: Git directory path
            worktree: Working tree path
            timeout: Command timeout in seconds
            
        Returns:
            Command output or None if failed
        """
        try:
            cmd = ["git", f"--git-dir={git_dir}", f"--work-tree={worktree}"] + args
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=worktree,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if process.returncode != 0:
                log.debug("snapshot.git.error", {
                    "args": args,
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "returncode": process.returncode,
                })
                return None
            
            return stdout.decode("utf-8", errors="replace")
            
        except asyncio.TimeoutError:
            log.warn("snapshot.git.timeout", {"args": args})
            return None
        except FileNotFoundError:
            log.warn("snapshot.git.not_found")
            return None
        except Exception as e:
            log.error("snapshot.git.error", {"args": args, "error": str(e)})
            return None
