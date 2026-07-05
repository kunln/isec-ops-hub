"""
background_cancel tool - cancel background tasks.
"""

from typing import Optional

from flocks.tool.registry import (
    ToolRegistry,
    ToolCategory,
    ToolParameter,
    ParameterType,
    ToolResult,
    ToolContext,
)
from flocks.task.background import get_background_manager


@ToolRegistry.register_function(
    name="background_cancel",
    description="Cancel a background task by task_id or cancel all.",
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="task_id",
            type=ParameterType.STRING,
            description="Background task ID to cancel",
            required=False,
        ),
        ToolParameter(
            name="all",
            type=ParameterType.BOOLEAN,
            description="Cancel all background tasks",
            required=False,
        ),
    ],
)
async def background_cancel_tool(
    ctx: ToolContext,
    task_id: Optional[str] = None,
    all: Optional[bool] = False,
) -> ToolResult:
    await ctx.ask(
        permission="background_cancel",
        patterns=[task_id or "*"],
        always=["*"],
        metadata={"task_id": task_id, "all": all},
    )
    manager = get_background_manager()
    cancelled = manager.cancel(task_id=task_id, all_tasks=bool(all))
    return ToolResult(
        success=True,
        output=f"Cancelled {cancelled} task(s).",
        title="background_cancel",
        metadata={"cancelled": cancelled},
    )
