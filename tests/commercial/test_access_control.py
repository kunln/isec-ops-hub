from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from flocks.auth.context import AuthUser
from flocks.commercial.access_control import (
    capability_for_api_request,
    capabilities_for_role,
    require_capability_for_request,
)
from flocks.storage.storage import Storage


@pytest.mark.asyncio
async def test_api_capability_mapping_handles_global_surfaces():
    assert capability_for_api_request("/api/channel/list", "GET") == "channels.read"
    assert capability_for_api_request("/api/channel/dingtalk/bind", "POST") == "channels.manage"
    assert capability_for_api_request("/api/channel/dingtalk/webhook/", "POST") is None
    assert capability_for_api_request("/api/config", "GET") == "system.config.read"
    assert capability_for_api_request("/api/config", "PATCH") == "system.config.write"
    assert capability_for_api_request("/api/security/assets", "POST") == "security.ops.write"
    assert capability_for_api_request("/api/security/connectors/tdp/sync-schedule", "PUT") == "security.schedules.manage"
    assert capability_for_api_request("/api/workflow/demo/run", "POST") == "workflows.run"
    assert capability_for_api_request("/api/commercial-admin/auth/login", "POST") is None


def test_role_capabilities_are_backward_compatible():
    assert "*" in capabilities_for_role("admin")
    assert "channels.send" in capabilities_for_role("member")
    assert "commercial.admin" not in capabilities_for_role("member")
    assert "security.admin" in capabilities_for_role("security_admin")


@pytest.mark.asyncio
async def test_capability_dependency_denies_and_audits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")

    app = FastAPI()

    @app.middleware("http")
    async def inject_viewer(request: Request, call_next):
        request.state.auth_user = AuthUser(
            id="viewer-user",
            username="viewer-user",
            role="viewer",
            status="active",
            must_reset_password=False,
        )
        return await call_next(request)

    @app.post("/api/channel/restart-all")
    async def restart_all(request: Request):
        await require_capability_for_request(
            request,
            "channels.manage",
            action="channel.restart_all",
            target="channels",
        )
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        denied = await client.post("/api/channel/restart-all")

    assert denied.status_code == 403

    from flocks.commercial.store import default_store

    events = await default_store.list_audit_events()
    assert events[0].action == "channel.restart_all"
    assert events[0].status == "denied"
    assert events[0].metadata["capability"] == "channels.manage"

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
