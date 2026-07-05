from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from flocks.server.auth import apply_auth_for_request, clear_auth_context, set_session_cookie
from flocks.server.routes.commercial import router as commercial_router
from flocks.server.routes.commercial_admin_auth import router as commercial_admin_auth_router
from flocks.server.routes.security import router as security_router


def _make_app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        token = None
        try:
            _, token, _ = await apply_auth_for_request(request)
            return await call_next(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        finally:
            if token is not None:
                clear_auth_context(token)

    app.include_router(commercial_admin_auth_router, prefix="/api/commercial-admin/auth")
    app.include_router(commercial_router, prefix="/api/commercial")
    app.include_router(security_router, prefix="/api/security")
    return app


@pytest.mark.asyncio
async def test_commercial_admin_fixed_login_and_protected_routes():
    async with AsyncClient(
        transport=ASGITransport(app=_make_app()),
        base_url="http://test",
        headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
    ) as client:
        rejected = await client.post(
            "/api/commercial-admin/auth/login",
            json={"username": "admini", "password": "wrong-password"},
        )
        assert rejected.status_code == 401

        accepted = await client.post(
            "/api/commercial-admin/auth/login",
            json={"username": "admini", "password": "Mv7XTdJtLLeJ-sgD"},
        )
        assert accepted.status_code == 200
        assert accepted.json()["role"] == "commercial_admin"

        license_info = await client.get("/api/commercial/license")
        assert license_info.status_code == 200

        security_health = await client.get("/api/security/health")
        assert security_health.status_code == 200


@pytest.mark.asyncio
async def test_commercial_admin_routes_reject_missing_or_regular_user_cookie():
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
    ) as client:
        missing = await client.get("/api/commercial/license")
        assert missing.status_code == 401

        from flocks.auth.service import AuthService
        from starlette.responses import Response

        await AuthService.bootstrap_admin("front-admin", "FrontAdminPassword123")
        user = await AuthService._create_user_internal("front-member", "FrontMemberPassword123", role="member")
        _, session_id = await AuthService.login(user.username, "FrontMemberPassword123")
        response = Response()
        set_session_cookie(response, session_id, secure=False)
        session_cookie = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]

        regular = await client.get("/api/commercial/license", cookies={"flocks_session": session_cookie})
        assert regular.status_code == 403
