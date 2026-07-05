"""
Message management routes - Flocks compatible

Routes for creating and managing messages within sessions.
Uses Flocks MessageV2 format.

Note: This is a simplified message API. Most message operations
should go through the /session/{sessionID}/message endpoints.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict

from flocks.utils.log import Log

router = APIRouter()
log = Log.create(service="routes.message")


# Simplified response for compatibility
class MessageResponse(BaseModel):
    """
    Message response - Flocks compatible
    
    Returns MessageV2.WithParts format
    """
    model_config = ConfigDict(populate_by_name=True, by_alias=True)
    
    info: Dict[str, Any] = Field(..., description="Message information")
    parts: List[Dict[str, Any]] = Field(default_factory=list, description="Message parts")


@router.get("/", summary="List messages (deprecated)")
async def list_messages_deprecated():
    """
    List messages (deprecated)
    
    Note: This endpoint is deprecated. Use /session/{sessionID}/message instead.
    Kept for backwards compatibility.
    """
    return []
