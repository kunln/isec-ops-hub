"""
VCS (Version Control System) module

Handles Git operations and version control integration
"""

import asyncio
import subprocess
from typing import Optional, List, Dict, Any
from pathlib import Path
from pydantic import BaseModel

from flocks.utils.log import Log

log = Log.create(service="vcs")


class VcsInfo(BaseModel):
    """VCS information"""
    branch: Optional[str] = None


class VcsDiff(BaseModel):
    """VCS diff information"""
    additions: int = 0
    deletions: int = 0
    files: List[str] = []
    diff: Optional[str] = None


class VcsCommit(BaseModel):
    """VCS commit information"""
    hash: str
    short_hash: str
    message: str
    author: str
    date: str


class VcsStatus(BaseModel):
    """VCS status information"""
    branch: Optional[str] = None
    clean: bool = True
    staged: List[str] = []
    unstaged: List[str] = []
    untracked: List[str] = []


class Vcs:
    """
    VCS namespace for version control operations
    
    Provides Git integration for project version control.
    """
    
    @classmethod
    async def get_branch(cls, worktree: str) -> Optional[str]:
        """
        Get the current branch name
        
        Args:
            worktree: Git worktree directory
            
        Returns:
            Branch name or None
        """
        try:
            result = await cls._run_git(
                ["rev-parse", "--abbrev-ref", "HEAD"],
                cwd=worktree
            )
            return result.strip() if result else None
        except Exception as e:
            log.warn("vcs.branch.error", {"error": str(e)})
            return None
    
    @classmethod
    async def get_status(cls, worktree: str) -> VcsStatus:
        """
        Get Git status
        
        Args:
            worktree: Git worktree directory
            
        Returns:
            VCS status information
        """
        status = VcsStatus()
        
        # Get branch
        status.branch = await cls.get_branch(worktree)
        
        # Get status
        try:
            result = await cls._run_git(
                ["status", "--porcelain", "-u"],
                cwd=worktree
            )
            
            if not result:
                status.clean = True
                return status
            
            status.clean = False
            
            for line in result.strip().split('\n'):
                if not line:
                    continue
                
                # Parse status line (XY filename)
                xy = line[:2]
                filename = line[3:]
                
                index_status = xy[0]
                worktree_status = xy[1]
                
                # Staged changes
                if index_status in 'MADRC':
                    status.staged.append(filename)
                
                # Unstaged changes
                if worktree_status in 'MD':
                    status.unstaged.append(filename)
                
                # Untracked files
                if xy == '??':
                    status.untracked.append(filename)
            
        except Exception as e:
            log.warn("vcs.status.error", {"error": str(e)})
        
        return status
    
    @classmethod
    async def get_diff(
        cls,
        worktree: str,
        staged: bool = False,
        files: Optional[List[str]] = None
    ) -> VcsDiff:
        """
        Get Git diff
        
        Args:
            worktree: Git worktree directory
            staged: If True, get staged changes; otherwise unstaged
            files: Optional list of files to diff
            
        Returns:
            VCS diff information
        """
        diff_info = VcsDiff()
        
        try:
            # Build command
            cmd = ["diff"]
            if staged:
                cmd.append("--cached")
            cmd.append("--numstat")
            
            if files:
                cmd.extend(["--"] + files)
            
            result = await cls._run_git(cmd, cwd=worktree)
            
            if result:
                for line in result.strip().split('\n'):
                    if not line:
                        continue
                    
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        try:
                            add = int(parts[0]) if parts[0] != '-' else 0
                            delete = int(parts[1]) if parts[1] != '-' else 0
                            filename = parts[2]
                            
                            diff_info.additions += add
                            diff_info.deletions += delete
                            diff_info.files.append(filename)
                        except ValueError:
                            pass
            
            # Get actual diff text
            cmd = ["diff"]
            if staged:
                cmd.append("--cached")
            if files:
                cmd.extend(["--"] + files)
            
            diff_info.diff = await cls._run_git(cmd, cwd=worktree)
            
        except Exception as e:
            log.warn("vcs.diff.error", {"error": str(e)})
        
        return diff_info
    
    @classmethod
    async def get_log(
        cls,
        worktree: str,
        count: int = 10,
        since: Optional[str] = None
    ) -> List[VcsCommit]:
        """
        Get Git log
        
        Args:
            worktree: Git worktree directory
            count: Number of commits to retrieve
            since: Optional date/commit to start from
            
        Returns:
            List of commits
        """
        commits = []
        
        try:
            cmd = [
                "log",
                f"-{count}",
                "--pretty=format:%H|%h|%s|%an|%ai"
            ]
            
            if since:
                cmd.append(f"--since={since}")
            
            result = await cls._run_git(cmd, cwd=worktree)
            
            if result:
                for line in result.strip().split('\n'):
                    if not line:
                        continue
                    
                    parts = line.split('|', 4)
                    if len(parts) >= 5:
                        commits.append(VcsCommit(
                            hash=parts[0],
                            short_hash=parts[1],
                            message=parts[2],
                            author=parts[3],
                            date=parts[4]
                        ))
            
        except Exception as e:
            log.warn("vcs.log.error", {"error": str(e)})
        
        return commits
    
    @classmethod
    async def get_root(cls, directory: str) -> Optional[str]:
        """
        Get Git repository root
        
        Args:
            directory: Starting directory
            
        Returns:
            Root directory or None
        """
        try:
            result = await cls._run_git(
                ["rev-parse", "--show-toplevel"],
                cwd=directory
            )
            return result.strip() if result else None
        except Exception:
            return None
    
    @classmethod
    async def is_git_repo(cls, directory: str) -> bool:
        """
        Check if directory is a Git repository
        
        Args:
            directory: Directory to check
            
        Returns:
            True if Git repository
        """
        try:
            result = await cls._run_git(
                ["rev-parse", "--git-dir"],
                cwd=directory
            )
            return bool(result)
        except Exception:
            return False
    
    @classmethod
    async def stage_files(cls, worktree: str, files: List[str]) -> bool:
        """
        Stage files for commit
        
        Args:
            worktree: Git worktree directory
            files: Files to stage
            
        Returns:
            True if successful
        """
        try:
            await cls._run_git(["add"] + files, cwd=worktree)
            log.info("vcs.staged", {"files": len(files)})
            return True
        except Exception as e:
            log.error("vcs.stage.error", {"error": str(e)})
            return False
    
    @classmethod
    async def unstage_files(cls, worktree: str, files: List[str]) -> bool:
        """
        Unstage files
        
        Args:
            worktree: Git worktree directory
            files: Files to unstage
            
        Returns:
            True if successful
        """
        try:
            await cls._run_git(["reset", "HEAD"] + files, cwd=worktree)
            log.info("vcs.unstaged", {"files": len(files)})
            return True
        except Exception as e:
            log.error("vcs.unstage.error", {"error": str(e)})
            return False
    
    @classmethod
    async def commit(
        cls,
        worktree: str,
        message: str,
        author: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a commit
        
        Args:
            worktree: Git worktree directory
            message: Commit message
            author: Optional author string
            
        Returns:
            Commit hash or None
        """
        try:
            cmd = ["commit", "-m", message]
            
            if author:
                cmd.extend(["--author", author])
            
            await cls._run_git(cmd, cwd=worktree)
            
            # Get the commit hash
            result = await cls._run_git(
                ["rev-parse", "HEAD"],
                cwd=worktree
            )
            
            commit_hash = result.strip() if result else None
            log.info("vcs.committed", {"hash": commit_hash})
            
            return commit_hash
            
        except Exception as e:
            log.error("vcs.commit.error", {"error": str(e)})
            return None
    
    @classmethod
    async def get_file_at_revision(
        cls,
        worktree: str,
        filepath: str,
        revision: str = "HEAD"
    ) -> Optional[str]:
        """
        Get file contents at a specific revision
        
        Args:
            worktree: Git worktree directory
            filepath: File path relative to worktree
            revision: Git revision (default: HEAD)
            
        Returns:
            File contents or None
        """
        try:
            result = await cls._run_git(
                ["show", f"{revision}:{filepath}"],
                cwd=worktree
            )
            return result
        except Exception:
            return None
    
    @classmethod
    async def generate_commit_message(
        cls,
        worktree: str,
        diff: Optional[str] = None
    ) -> str:
        """
        Generate a commit message from staged changes
        
        This is a placeholder that returns a basic message.
        In a full implementation, this would use LLM to generate
        a meaningful commit message.
        
        Args:
            worktree: Git worktree directory
            diff: Optional diff string
            
        Returns:
            Generated commit message
        """
        # Get staged diff if not provided
        if not diff:
            diff_info = await cls.get_diff(worktree, staged=True)
            diff = diff_info.diff
        
        if not diff:
            return "Update files"
        
        # Count changes
        additions = diff.count('\n+') - diff.count('\n+++')
        deletions = diff.count('\n-') - diff.count('\n---')
        
        # Basic message generation
        if additions > deletions:
            action = "Add"
        elif deletions > additions:
            action = "Remove"
        else:
            action = "Update"
        
        # Get changed files
        status = await cls.get_status(worktree)
        files = status.staged
        
        if len(files) == 1:
            return f"{action} {files[0]}"
        elif len(files) <= 3:
            return f"{action} {', '.join(files)}"
        else:
            return f"{action} {len(files)} files"
    
    @classmethod
    async def _run_git(
        cls,
        args: List[str],
        cwd: str,
        timeout: float = 30.0
    ) -> Optional[str]:
        """
        Run a Git command
        
        Args:
            args: Git command arguments
            cwd: Working directory
            timeout: Command timeout in seconds
            
        Returns:
            Command output or None
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "git", *args,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='replace')
                log.debug("git.error", {
                    "args": args,
                    "stderr": error_msg,
                    "returncode": process.returncode
                })
                return None
            
            return stdout.decode('utf-8', errors='replace')
            
        except asyncio.TimeoutError:
            log.warn("git.timeout", {"args": args})
            return None
        except FileNotFoundError:
            log.warn("git.not_found")
            return None
        except Exception as e:
            log.error("git.error", {"args": args, "error": str(e)})
            return None
