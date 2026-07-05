"""
Debug CLI commands

Provides debugging utilities for Flocks
"""

import asyncio
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from flocks import __version__
from flocks.config.config import Config
from flocks.utils.log import Log
from flocks.snapshot import Snapshot

debug_app = typer.Typer(
    name="debug",
    help="Debug utilities for Flocks",
    no_args_is_help=True,
)

snapshot_app = typer.Typer(
    name="snapshot",
    help="Snapshot debugging utilities",
    no_args_is_help=True,
)

debug_app.add_typer(snapshot_app, name="snapshot")

console = Console()


@debug_app.command("info")
def info():
    """
    Show debug information
    """
    console.print(Panel("[bold cyan]Flocks Debug Information[/bold cyan]"))
    console.print(f"[bold]Version:[/bold] {__version__}")
    console.print(f"[bold]Config dir:[/bold] {Config.get_config_path()}")
    console.print(f"[bold]Data dir:[/bold] {Config.get_data_path()}")
    console.print(f"[bold]Log dir:[/bold] {Config.get_log_path()}")
    console.print(f"[bold]Log file:[/bold] {Log.file()}")


@debug_app.command("config")
def show_config():
    """
    Show current configuration
    """
    async def _show_config():
        cfg = await Config.get()
        console.print(Panel("[bold cyan]Current Configuration[/bold cyan]"))
        console.print(cfg.model_dump_json(indent=2))
    
    asyncio.run(_show_config())


@snapshot_app.command("track")
def snapshot_track(
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Project directory"
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        "-p",
        help="Project ID (defaults to directory name)"
    ),
):
    """
    Track current snapshot state
    
    Creates a Git tree object representing the current file state.
    """
    async def _track():
        worktree = str(directory or Path.cwd())
        proj_id = project_id or Path(worktree).name
        
        console.print(f"[cyan]Tracking snapshot...[/cyan]")
        console.print(f"[dim]Worktree:[/dim] {worktree}")
        console.print(f"[dim]Project ID:[/dim] {proj_id}")
        
        tree_hash = await Snapshot.track(proj_id, worktree)
        
        if tree_hash:
            console.print(f"\n[green]Snapshot created:[/green] {tree_hash}")
        else:
            console.print("[yellow]Snapshot tracking disabled or failed[/yellow]")
    
    asyncio.run(_track())


@snapshot_app.command("patch")
def snapshot_patch(
    hash: str = typer.Argument(..., help="Git tree hash to compare against"),
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Project directory"
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        "-p",
        help="Project ID (defaults to directory name)"
    ),
):
    """
    Show changed files since a snapshot hash
    """
    async def _patch():
        worktree = str(directory or Path.cwd())
        proj_id = project_id or Path(worktree).name
        
        console.print(f"[cyan]Getting patch for hash:[/cyan] {hash}")
        
        patch = await Snapshot.patch(proj_id, worktree, hash)
        
        if patch.files:
            console.print(f"\n[bold]Changed files ({len(patch.files)}):[/bold]")
            for f in patch.files:
                console.print(f"  • {f}")
        else:
            console.print("[dim]No changes found[/dim]")
    
    asyncio.run(_patch())


@snapshot_app.command("diff")
def snapshot_diff(
    hash: str = typer.Argument(..., help="Git tree hash to compare against"),
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Project directory"
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        "-p",
        help="Project ID (defaults to directory name)"
    ),
):
    """
    Show diff between snapshot and current state
    """
    async def _diff():
        worktree = str(directory or Path.cwd())
        proj_id = project_id or Path(worktree).name
        
        console.print(f"[cyan]Getting diff for hash:[/cyan] {hash}")
        
        diff_text = await Snapshot.diff(proj_id, worktree, hash)
        
        if diff_text:
            console.print()
            syntax = Syntax(diff_text, "diff", theme="monokai", line_numbers=False)
            console.print(syntax)
        else:
            console.print("[dim]No changes found[/dim]")
    
    asyncio.run(_diff())


@snapshot_app.command("restore")
def snapshot_restore(
    hash: str = typer.Argument(..., help="Git tree hash to restore"),
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Project directory"
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        "-p",
        help="Project ID (defaults to directory name)"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force restore without confirmation"
    ),
):
    """
    Restore files to a snapshot state
    
    WARNING: This will overwrite current files!
    """
    async def _restore():
        worktree = str(directory or Path.cwd())
        proj_id = project_id or Path(worktree).name
        
        if not force:
            confirm = typer.confirm(
                f"This will restore files to snapshot {hash[:8]}. Continue?"
            )
            if not confirm:
                console.print("[yellow]Aborted[/yellow]")
                return
        
        console.print(f"[cyan]Restoring to snapshot:[/cyan] {hash}")
        
        success = await Snapshot.restore(proj_id, worktree, hash)
        
        if success:
            console.print("[green]Snapshot restored successfully[/green]")
        else:
            console.print("[red]Failed to restore snapshot[/red]")
    
    asyncio.run(_restore())


@snapshot_app.command("cleanup")
def snapshot_cleanup(
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Project directory"
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        "-p",
        help="Project ID (defaults to directory name)"
    ),
):
    """
    Clean up old snapshots using git gc
    """
    async def _cleanup():
        worktree = str(directory or Path.cwd())
        proj_id = project_id or Path(worktree).name
        
        console.print(f"[cyan]Cleaning up snapshots...[/cyan]")
        
        await Snapshot.cleanup(proj_id, worktree)
        
        console.print("[green]Cleanup complete[/green]")
    
    asyncio.run(_cleanup())
