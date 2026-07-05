"""Commercial admin fixed-account authentication helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from fastapi import HTTPException, Request, Response, status

from flocks.auth.context import AuthUser
from flocks.server.auth import should_use_secure_cookie

COMMERCIAL_ADMIN_COOKIE_NAME = "flocks_commercial_admin_session"
COMMERCIAL_ADMIN_USERNAME = os.getenv("FLOCKS_COMMERCIAL_ADMIN_USERNAME", "admini")
COMMERCIAL_ADMIN_PASSWORD = os.getenv("FLOCKS_COMMERCIAL_ADMIN_PASSWORD", "Mv7XTdJtLLeJ-sgD")
COMMERCIAL_ADMIN_SESSION_MAX_AGE = 7 * 24 * 3600


def _session_secret() -> str:
    return os.getenv("FLOCKS_COMMERCIAL_ADMIN_SESSION_SECRET") or COMMERCIAL_ADMIN_PASSWORD


def _sign(payload: str) -> str:
    return hmac.new(_session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _build_token(username: str, expires_at: int) -> str:
    payload = f"{username}:{expires_at}"
    return f"{payload}:{_sign(payload)}"


def _parse_token(token: str) -> tuple[str, int] | None:
    username, sep, rest = token.partition(":")
    if not sep:
        return None
    expires_text, sep, signature = rest.partition(":")
    if not sep:
        return None
    try:
        expires_at = int(expires_text)
    except ValueError:
        return None
    payload = f"{username}:{expires_at}"
    if not hmac.compare_digest(signature, _sign(payload)):
        return None
    if expires_at <= int(time.time()):
        return None
    return username, expires_at


def validate_credentials(username: str, password: str) -> bool:
    return hmac.compare_digest(username, COMMERCIAL_ADMIN_USERNAME) and hmac.compare_digest(
        password,
        COMMERCIAL_ADMIN_PASSWORD,
    )


def commercial_admin_user() -> AuthUser:
    return AuthUser(
        id=f"commercial-admin:{COMMERCIAL_ADMIN_USERNAME}",
        username=COMMERCIAL_ADMIN_USERNAME,
        role="commercial_admin",
        status="active",
        must_reset_password=False,
    )


def commercial_admin_user_from_request(request: Request) -> AuthUser | None:
    token = request.cookies.get(COMMERCIAL_ADMIN_COOKIE_NAME)
    if not token:
        return None
    parsed = _parse_token(token)
    if not parsed:
        return None
    username, _ = parsed
    if not hmac.compare_digest(username, COMMERCIAL_ADMIN_USERNAME):
        return None
    return commercial_admin_user()


def set_commercial_admin_cookie(response: Response, request: Request) -> None:
    expires_at = int(time.time()) + COMMERCIAL_ADMIN_SESSION_MAX_AGE
    response.set_cookie(
        key=COMMERCIAL_ADMIN_COOKIE_NAME,
        value=_build_token(COMMERCIAL_ADMIN_USERNAME, expires_at),
        httponly=True,
        secure=should_use_secure_cookie(request),
        samesite="lax",
        max_age=COMMERCIAL_ADMIN_SESSION_MAX_AGE,
        path="/",
    )


def clear_commercial_admin_cookie(response: Response) -> None:
    response.delete_cookie(key=COMMERCIAL_ADMIN_COOKIE_NAME, path="/")


def commercial_admin_cookie_allowed_for_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    return (
        normalized == "/api/commercial"
        or normalized.startswith("/api/commercial/")
        or normalized == "/api/security"
        or normalized.startswith("/api/security/")
    )


def require_commercial_admin(request: Request) -> AuthUser:
    user = commercial_admin_user_from_request(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录商业化后台")
    return user
