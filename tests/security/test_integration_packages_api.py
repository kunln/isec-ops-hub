"""Tests for read-only Integration Package metadata APIs."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.storage.storage import Storage


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.security import secrets as secrets_module
    from flocks.security.connectors.registry import connector_registry

    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")

    from fastapi import FastAPI, Request
    from flocks.auth.context import AuthUser
    from flocks.server.routes.security import router as security_router

    app = FastAPI()

    @app.middleware("http")
    async def inject_admin(request: Request, call_next):
        request.state.auth_user = AuthUser(
            id="admin-user",
            username="admin-user",
            role="admin",
            status="active",
            must_reset_password=False,
        )
        return await call_next(request)

    app.include_router(security_router, prefix="/api/security")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests()


@pytest.mark.asyncio
async def test_list_integration_packages_returns_builtin_metadata(client: AsyncClient) -> None:
    response = await client.get("/api/security/integrations/packages")

    assert response.status_code == 200
    packages = response.json()
    by_id = {package["package_id"]: package for package in packages}

    assert "asiainfo.tda" in by_id
    assert "dbappsecurity.mingyu_apt" in by_id
    assert "alert.search" in by_id["asiainfo.tda"]["capabilities"]
    assert "risk.search" in by_id["dbappsecurity.mingyu_apt"]["capabilities"]
    for package in packages:
        assert package["raw_response_policy"] == "transient_only"
        assert package["raw_log_storage"] == "forbidden"
        for field_name in package["sensitive_fields"]:
            lowered = field_name.lower()
            assert "=" not in field_name
            assert not any(secret_hint in lowered for secret_hint in ("secret=", "token=", "password=", "api_key="))


@pytest.mark.asyncio
async def test_get_integration_package_by_id_and_unknown_404(client: AsyncClient) -> None:
    tda = await client.get("/api/security/integrations/packages/asiainfo.tda")
    missing = await client.get("/api/security/integrations/packages/unknown.package")

    assert tda.status_code == 200
    assert tda.json()["package_id"] == "asiainfo.tda"
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_list_integration_capabilities_returns_both_builtin_packages(client: AsyncClient) -> None:
    response = await client.get("/api/security/integrations/capabilities")

    assert response.status_code == 200
    capabilities = response.json()
    pairs = {(item["package_id"], item["capability"]) for item in capabilities}

    assert ("asiainfo.tda", "alert.search") in pairs
    assert ("dbappsecurity.mingyu_apt", "risk.search") in pairs


@pytest.mark.asyncio
async def test_integration_package_api_has_no_connector_or_security_object_side_effects(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("read-only integration package API must not call connectors")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail_if_called)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", fail_if_called)

    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    packages = await client.get("/api/security/integrations/packages")
    capabilities = await client.get("/api/security/integrations/capabilities")

    after_cases = (await client.get("/api/security/analysis-cases")).json()
    after_incidents = (await client.get("/api/security/incidents")).json()

    assert packages.status_code == 200
    assert capabilities.status_code == 200
    assert after_cases == before_cases == []
    assert after_incidents == before_incidents == []
