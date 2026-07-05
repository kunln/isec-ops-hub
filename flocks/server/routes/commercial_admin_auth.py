"""Commercial admin fixed-account auth routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from flocks.server.commercial_admin_auth import (
    clear_commercial_admin_cookie,
    commercial_admin_user,
    require_commercial_admin,
    set_commercial_admin_cookie,
    validate_credentials,
)

router = APIRouter()


class CommercialAdminLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class CommercialAdminMeResponse(BaseModel):
    id: str
    username: str
    role: str
    status: str
    must_reset_password: bool = False


def _to_response() -> CommercialAdminMeResponse:
    user = commercial_admin_user()
    return CommercialAdminMeResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        status=user.status,
        must_reset_password=user.must_reset_password,
    )


@router.post("/login", response_model=CommercialAdminMeResponse)
async def login(payload: CommercialAdminLoginRequest, response: Response, request: Request) -> CommercialAdminMeResponse:
    if not validate_credentials(payload.username, payload.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="商业化后台账号或密码错误")
    set_commercial_admin_cookie(response, request)
    return _to_response()


@router.get("/me", response_model=CommercialAdminMeResponse)
async def me(request: Request) -> CommercialAdminMeResponse:
    require_commercial_admin(request)
    return _to_response()


@router.post("/logout")
async def logout(response: Response) -> dict:
    clear_commercial_admin_cookie(response)
    return {"success": True}
