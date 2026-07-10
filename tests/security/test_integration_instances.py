"""Tests for Integration Instance metadata skeleton APIs."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations import (
    IntegrationInstanceCreate,
    build_capability_run_request_from_instance,
)
from flocks.security.integrations.instance_store import IntegrationInstanceStore
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


async def create_instance(client: AsyncClient, package_id: str = "asiainfo.tda", **extra: object) -> dict[str, object]:
    payload = {"package_id": package_id, "display_name": "TDA-测试环境", "base_url": "https://tda.example.test"}
    payload.update(extra)
    response = await client.post("/api/security/integrations/instances", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_create_tda_instance_success(client: AsyncClient) -> None:
    instance = await create_instance(client)

    assert instance["instance_id"].startswith("intinst_")
    assert instance["package_id"] == "asiainfo.tda"
    assert instance["vendor"] == "AsiaInfo"
    assert instance["product"] == "TDA"
    assert instance["health_status"] == "unknown"


@pytest.mark.asyncio
async def test_create_mingyu_apt_instance_success(client: AsyncClient) -> None:
    instance = await create_instance(
        client,
        package_id="dbappsecurity.mingyu_apt",
        display_name="明御APT-某客户",
        base_url="https://apt.example.test",
    )

    assert instance["package_id"] == "dbappsecurity.mingyu_apt"
    assert instance["product"] == "Mingyu APT"


@pytest.mark.asyncio
async def test_create_unknown_package_returns_400(client: AsyncClient) -> None:
    response = await client.post("/api/security/integrations/instances", json={"package_id": "unknown.package", "display_name": "Unknown"})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_list_instances_returns_created_instances(client: AsyncClient) -> None:
    created = await create_instance(client)

    response = await client.get("/api/security/integrations/instances")

    assert response.status_code == 200
    assert [item["instance_id"] for item in response.json()] == [created["instance_id"]]


@pytest.mark.asyncio
async def test_package_id_filter(client: AsyncClient) -> None:
    tda = await create_instance(client)
    await create_instance(client, package_id="dbappsecurity.mingyu_apt", display_name="Mingyu")

    response = await client.get("/api/security/integrations/instances", params={"package_id": "asiainfo.tda"})

    assert response.status_code == 200
    assert [item["instance_id"] for item in response.json()] == [tda["instance_id"]]


@pytest.mark.asyncio
async def test_get_instance_success(client: AsyncClient) -> None:
    created = await create_instance(client)

    response = await client.get(f"/api/security/integrations/instances/{created['instance_id']}")

    assert response.status_code == 200
    assert response.json()["display_name"] == "TDA-测试环境"


@pytest.mark.asyncio
async def test_get_unknown_instance_returns_404(client: AsyncClient) -> None:
    response = await client.get("/api/security/integrations/instances/intinst_missing")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_patch_display_name_enabled_health_status(client: AsyncClient) -> None:
    created = await create_instance(client)

    response = await client.patch(
        f"/api/security/integrations/instances/{created['instance_id']}",
        json={"display_name": "TDA-renamed", "enabled": False, "health_status": "degraded"},
    )

    assert response.status_code == 200
    patched = response.json()
    assert patched["display_name"] == "TDA-renamed"
    assert patched["enabled"] is False
    assert patched["health_status"] == "degraded"


@pytest.mark.asyncio
async def test_delete_instance_success(client: AsyncClient) -> None:
    created = await create_instance(client)

    deleted = await client.delete(f"/api/security/integrations/instances/{created['instance_id']}")
    fetched = await client.get(f"/api/security/integrations/instances/{created['instance_id']}")

    assert deleted.status_code == 200
    assert fetched.status_code == 404


@pytest.mark.asyncio
async def test_base_url_must_be_http_or_https(client: AsyncClient) -> None:
    response = await client.post(
        "/api/security/integrations/instances",
        json={"package_id": "asiainfo.tda", "display_name": "TDA", "base_url": "ftp://example.test"},
    )

    assert response.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("secret_key", ["api_key", "secret", "token", "password"])
async def test_metadata_rejects_secret_like_keys(client: AsyncClient, secret_key: str) -> None:
    response = await client.post(
        "/api/security/integrations/instances",
        json={"package_id": "asiainfo.tda", "display_name": "TDA", "metadata": {secret_key: "plain-value"}},
    )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_api_response_contains_no_credential_value(client: AsyncClient) -> None:
    instance = await create_instance(client, credential_profile_id="cred-profile-a", metadata={"region": "cn"})

    serialized = str(instance)
    assert "plain-secret" not in serialized
    assert "api_key" not in serialized
    assert instance["credential_profile_id"] == "cred-profile-a"


@pytest.mark.asyncio
async def test_credential_profile_id_is_reference_only(client: AsyncClient) -> None:
    instance = await create_instance(client, credential_profile_id="missing-but-accepted")

    assert instance["credential_profile_id"] == "missing-but-accepted"


@pytest.mark.asyncio
async def test_instance_api_does_not_call_v1_connector(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Integration Instance skeleton must not call v1 connectors")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail_if_called)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", fail_if_called)

    response = await client.post("/api/security/integrations/instances", json={"package_id": "asiainfo.tda", "display_name": "TDA"})

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_instance_api_does_not_create_security_objects(client: AsyncClient) -> None:
    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    response = await client.post("/api/security/integrations/instances", json={"package_id": "asiainfo.tda", "display_name": "TDA"})

    after_alerts = (await client.get("/api/security/alerts")).json()
    after_cases = (await client.get("/api/security/analysis-cases")).json()
    after_incidents = (await client.get("/api/security/incidents")).json()
    assert response.status_code == 200
    assert after_alerts == before_alerts == []
    assert after_cases == before_cases == []
    assert after_incidents == before_incidents == []


def test_build_capability_run_request_from_instance_is_dry_run() -> None:
    store = IntegrationInstanceStore()
    instance = store.create_instance(
        IntegrationInstanceCreate(package_id="asiainfo.tda", display_name="TDA", metadata={"limit": 10})
    )

    request = build_capability_run_request_from_instance(instance, "alert.search", params={"page": 1})

    assert request.package_id == "asiainfo.tda"
    assert request.capability == "alert.search"
    assert request.dry_run is True
    assert request.params == {"limit": 10, "page": 1}


def test_generated_request_params_drop_secret_like_values_and_keep_safe_values() -> None:
    store = IntegrationInstanceStore()
    instance = store.create_instance(
        IntegrationInstanceCreate(package_id="asiainfo.tda", display_name="TDA", metadata={"region": "cn"})
    )

    request = build_capability_run_request_from_instance(
        instance,
        "alert.search",
        params={"note": "Bearer abc", "safe": "visible"},
    )

    serialized = str(request.params)
    assert "Bearer abc" not in serialized
    assert request.params["safe"] == "visible"
    assert request.params["region"] == "cn"


def test_generated_request_params_drop_nested_secret_like_keys_and_values() -> None:
    store = IntegrationInstanceStore()
    instance = store.create_instance(IntegrationInstanceCreate(package_id="asiainfo.tda", display_name="TDA"))

    request = build_capability_run_request_from_instance(
        instance,
        "alert.search",
        params={"headers": {"Authorization": "Bearer abc", "Accept": "application/json"}},
    )

    serialized = str(request.params)
    assert "Authorization" not in serialized
    assert "Bearer abc" not in serialized
    assert request.params == {"headers": {"Accept": "application/json"}}


def test_instance_metadata_rejects_secret_like_values() -> None:
    store = IntegrationInstanceStore()

    with pytest.raises(ValueError):
        store.create_instance(
            IntegrationInstanceCreate(package_id="asiainfo.tda", display_name="TDA", metadata={"note": "Bearer abc"})
        )
