"""
TUI control routes for Flocks TUI compatibility

Provides /tui/* endpoints for remote control of TUI from external processes.

Endpoints:
- POST /tui/append-prompt - Append text to TUI prompt
- POST /tui/execute-command - Execute a TUI command
- POST /tui/publish - Publish a TUI event
- POST /tui/open-help - Open help dialog
- POST /tui/open-sessions - Open sessions dialog  
- POST /tui/open-themes - Open themes dialog
- POST /tui/open-models - Open models dialog
- POST /tui/submit-prompt - Submit current prompt
- POST /tui/clear-prompt - Clear current prompt
- POST /tui/show-toast - Show a toast notification
- POST /tui/select-session - Select/navigate to a session
- POST /tui/control/next - Get next control event (for TUI polling)
- POST /tui/control/response - Send response to control request
"""

import asyncio
from typing import Dict, Any, Optional, List, Literal, Union
from datetime import datetime

from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field

from flocks.utils.log import Log
from flocks.server.routes.event import publish_event


router = APIRouter()
log = Log.create(service="tui-routes")


# Control event queue for TUI polling
_control_events: asyncio.Queue = asyncio.Queue()
_control_responses: Dict[str, asyncio.Future] = {}


# Request/Response Models

class AppendPromptRequest(BaseModel):
    """Request to append text to TUI prompt"""
    text: str = Field(..., description="Text to append to prompt")


class ExecuteCommandRequest(BaseModel):
    """Request to execute a TUI command"""
    command: str = Field(..., description="Command to execute (e.g. agent_cycle)")


class ShowToastRequest(BaseModel):
    """Request to show a toast notification"""
    title: Optional[str] = Field(None, description="Toast title")
    message: str = Field(..., description="Toast message")
    variant: Literal["info", "success", "warning", "error"] = Field("info", description="Toast variant")
    duration: Optional[int] = Field(None, description="Duration in milliseconds")


class SelectSessionRequest(BaseModel):
    """Request to select/navigate to a session"""
    sessionID: str = Field(..., description="Session ID to navigate to")


# TUI Event types for /tui/publish
class EventTuiPromptAppend(BaseModel):
    """Event to append text to TUI prompt"""
    type: Literal["tui.prompt.append"] = "tui.prompt.append"
    properties: Dict[str, Any] = Field(default_factory=dict)
    
class EventTuiCommandExecute(BaseModel):
    """Event to execute a TUI command"""
    type: Literal["tui.command.execute"] = "tui.command.execute"
    properties: Dict[str, Any] = Field(default_factory=dict)

class EventTuiToastShow(BaseModel):
    """Event to show a toast notification"""
    type: Literal["tui.toast.show"] = "tui.toast.show"
    properties: Dict[str, Any] = Field(default_factory=dict)

class EventTuiSessionSelect(BaseModel):
    """Event to select a session"""
    type: Literal["tui.session.select"] = "tui.session.select"
    properties: Dict[str, Any] = Field(default_factory=dict)


TuiEvent = Union[EventTuiPromptAppend, EventTuiCommandExecute, EventTuiToastShow, EventTuiSessionSelect]


class ControlResponse(BaseModel):
    """Response to a control request"""
    requestID: str
    response: Any


# Helper to publish TUI events
async def publish_tui_event(event_type: str, properties: dict = None):
    """Publish a TUI event to SSE and queue for control polling"""
    await publish_event(event_type, properties)
    # Also queue for control/next polling
    await _control_events.put({
        "type": event_type,
        "properties": properties or {},
        "timestamp": int(datetime.now().timestamp() * 1000),
    })


# Endpoints

@router.post(
    "/append-prompt",
    summary="Append TUI prompt",
    description="Append text to the TUI prompt"
)
async def append_prompt(
    request: AppendPromptRequest,
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Append text to TUI prompt"""
    log.info("tui.append_prompt", {"text_length": len(request.text)})
    
    await publish_tui_event("tui.prompt.append", {
        "text": request.text,
    })
    
    return True


@router.post(
    "/execute-command",
    summary="Execute TUI command",
    description="Execute a TUI command (e.g. agent_cycle)"
)
async def execute_command(
    request: ExecuteCommandRequest,
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Execute a TUI command"""
    log.info("tui.execute_command", {"command": request.command})
    
    await publish_tui_event("tui.command.execute", {
        "command": request.command,
    })
    
    return True


@router.post(
    "/publish",
    summary="Publish TUI event",
    description="Publish a TUI event"
)
async def publish_tui_event_endpoint(
    request: TuiEvent,
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Publish a TUI event"""
    log.info("tui.publish", {"type": request.type})
    
    await publish_tui_event(request.type, request.properties)
    
    return True


@router.post(
    "/open-help",
    summary="Open help dialog",
    description="Open the TUI help dialog"
)
async def open_help(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Open help dialog"""
    log.info("tui.open_help")
    
    await publish_tui_event("tui.dialog.open", {
        "dialog": "help",
    })
    
    return True


@router.post(
    "/open-sessions",
    summary="Open sessions dialog",
    description="Open the TUI sessions dialog"
)
async def open_sessions(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Open sessions dialog"""
    log.info("tui.open_sessions")
    
    await publish_tui_event("tui.dialog.open", {
        "dialog": "sessions",
    })
    
    return True


@router.post(
    "/open-themes",
    summary="Open themes dialog",
    description="Open the TUI themes dialog"
)
async def open_themes(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Open themes dialog"""
    log.info("tui.open_themes")
    
    await publish_tui_event("tui.dialog.open", {
        "dialog": "themes",
    })
    
    return True


@router.post(
    "/open-models",
    summary="Open models dialog",
    description="Open the TUI models dialog"
)
async def open_models(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Open models dialog"""
    log.info("tui.open_models")
    
    await publish_tui_event("tui.dialog.open", {
        "dialog": "models",
    })
    
    return True


@router.post(
    "/submit-prompt",
    summary="Submit TUI prompt",
    description="Submit the current TUI prompt"
)
async def submit_prompt(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Submit current prompt"""
    log.info("tui.submit_prompt")
    
    await publish_tui_event("tui.prompt.submit", {})
    
    return True


@router.post(
    "/clear-prompt",
    summary="Clear TUI prompt",
    description="Clear the current TUI prompt"
)
async def clear_prompt(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Clear current prompt"""
    log.info("tui.clear_prompt")
    
    await publish_tui_event("tui.prompt.clear", {})
    
    return True


@router.post(
    "/show-toast",
    summary="Show toast notification",
    description="Show a toast notification in the TUI"
)
async def show_toast(
    request: ShowToastRequest,
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Show a toast notification"""
    log.info("tui.show_toast", {"message": request.message, "variant": request.variant})
    
    await publish_tui_event("tui.toast.show", {
        "title": request.title,
        "message": request.message,
        "variant": request.variant,
        "duration": request.duration,
    })
    
    return True


@router.post(
    "/select-session",
    summary="Select session",
    description="Select/navigate to a session in the TUI"
)
async def select_session(
    request: SelectSessionRequest,
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """Select/navigate to a session"""
    log.info("tui.select_session", {"sessionID": request.sessionID})
    
    await publish_tui_event("tui.session.select", {
        "sessionID": request.sessionID,
    })
    
    return True


@router.post(
    "/control/next",
    summary="Get next control event",
    description="Long-poll for next TUI control event"
)
async def control_next(
    directory: Optional[str] = Query(None, description="Project directory"),
) -> Optional[Dict[str, Any]]:
    """
    Get next control event (long-poll).
    
    TUI polls this endpoint to receive control commands from external processes.
    """
    try:
        # Wait for event with timeout (30 seconds)
        event = await asyncio.wait_for(_control_events.get(), timeout=30.0)
        return event
    except asyncio.TimeoutError:
        # Return None on timeout (client should retry)
        return None


@router.post(
    "/control/response",
    summary="Send control response",
    description="Send response to a control request"
)
async def control_response(
    request: ControlResponse,
    directory: Optional[str] = Query(None, description="Project directory"),
) -> bool:
    """
    Send response to a control request.
    
    Used by TUI to respond to requests that need a response.
    """
    log.info("tui.control_response", {"requestID": request.requestID})
    
    if request.requestID in _control_responses:
        future = _control_responses.pop(request.requestID)
        future.set_result(request.response)
    
    return True


# Export
__all__ = ["router", "publish_tui_event"]
