"""
Background Task management routes

Routes for listing and managing background tasks spawned by agents.
Moved from agent.py to avoid route conflict with /api/agent/{name}.
"""

from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from flocks.utils.log import Log

router = APIRouter()
log = Log.create(service="routes.background_task")


class BackgroundTaskResponse(BaseModel):
    """Background task response"""

    id: str = Field(..., description="Task ID")
    status: str = Field(..., description="Task status")
    description: str = Field(..., description="Task description")
    prompt: str = Field(..., description="Task prompt")
    agent: str = Field(..., description="Agent name")
    parentSessionId: Optional[str] = Field(None, description="Parent session ID")
    parentMessageId: Optional[str] = Field(None, description="Parent message ID")
    sessionId: Optional[str] = Field(None, description="Session ID")
    error: Optional[str] = Field(None, description="Error message")
    output: Optional[str] = Field(None, description="Task output")
    createdAt: int = Field(..., description="Created timestamp (ms)")
    startedAt: Optional[int] = Field(None, description="Started timestamp (ms)")
    completedAt: Optional[int] = Field(None, description="Completed timestamp (ms)")


def _get_background_manager():
    """Return the background manager from the current Instance, or None."""
    from flocks.project.instance import Instance
    instance = Instance.get()
    if not instance or not hasattr(instance, "background_manager"):
        return None
    return instance.background_manager


def _task_to_response(task) -> BackgroundTaskResponse:
    return BackgroundTaskResponse(
        id=task.id,
        status=task.status,
        description=task.description,
        prompt=task.prompt,
        agent=task.agent,
        parentSessionId=task.parent_session_id,
        parentMessageId=task.parent_message_id,
        sessionId=task.session_id,
        error=task.error,
        output=task.output,
        createdAt=task.created_at,
        startedAt=task.started_at,
        completedAt=task.completed_at,
    )


@router.get("", response_model=List[BackgroundTaskResponse], summary="List background tasks")
async def list_background_tasks():
    """
    List background tasks

    Returns list of all background tasks (pending, running, completed).
    """
    try:
        manager = _get_background_manager()
        if not manager:
            return []
        return [_task_to_response(t) for t in manager.list_tasks()]
    except Exception as e:
        log.error("background_task.list.error", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}", response_model=BackgroundTaskResponse, summary="Get background task")
async def get_background_task(task_id: str):
    """
    Get background task details

    Returns detailed information about a specific background task.
    """
    try:
        manager = _get_background_manager()
        if not manager:
            raise HTTPException(status_code=404, detail="Background manager not available")
        task = manager.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        return _task_to_response(task)
    except HTTPException:
        raise
    except Exception as e:
        log.error("background_task.get.error", {"error": str(e), "task_id": task_id})
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{task_id}/cancel", summary="Cancel background task")
async def cancel_background_task(task_id: str):
    """
    Cancel a background task

    Cancels a running or pending background task.
    """
    try:
        manager = _get_background_manager()
        if not manager:
            raise HTTPException(status_code=404, detail="Background manager not available")
        cancelled = manager.cancel(task_id=task_id)
        if cancelled == 0:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found or already completed")
        log.info("background_task.cancelled", {"task_id": task_id})
        return {"status": "success", "message": f"Task {task_id} cancelled", "cancelled": cancelled}
    except HTTPException:
        raise
    except Exception as e:
        log.error("background_task.cancel.error", {"error": str(e), "task_id": task_id})
        raise HTTPException(status_code=500, detail=str(e))
