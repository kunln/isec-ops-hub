"""Persistence tests for Integration Instance metadata APIs."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations.instance_store import PersistentIntegrationInstanceStore
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
    payload = {"package_id": package_id, "display_name": "TDA", "base_url": "https://tda.example.test"}
    payload.update(extra)
    response = await client.post("/api/security/integrations/instances", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_create_get_list_and_filters_persisted(client: AsyncClient) -> None:
    tda = await create_instance(client, enabled=True)
    mingyu = await create_instance(
        client,
        package_id="dbappsecurity.mingyu_apt",
        display_name="Mingyu",
        base_url="https://apt.example.test",
        enabled=False,
    )

    fetched = await client.get(f"/api/security/integrations/instances/{tda['instance_id']}")
    listed = await client.get("/api/security/integrations/instances")
    package_filtered = await client.get("/api/security/integrations/instances", params={"package_id": "asiainfo.tda"})
    enabled_filtered = await client.get("/api/security/integrations/instances", params={"enabled": "false"})

    assert fetched.status_code == 200
    assert fetched.json()["instance_id"] == tda["instance_id"]
    assert listed.status_code == 200
    assert {item["instance_id"] for item in listed.json()} == {tda["instance_id"], mingyu["instance_id"]}
    assert [item["instance_id"] for item in package_filtered.json()] == [tda["instance_id"]]
    assert [item["instance_id"] for item in enabled_filtered.json()] == [mingyu["instance_id"]]


@pytest.mark.asyncio
async def test_update_changes_updated_at_and_delete_removes_metadata(client: AsyncClient) -> None:
    created = await create_instance(client, metadata={"region": "cn"})
    before_updated_at = created["updated_at"]

    patched = await client.patch(
        f"/api/security/integrations/instances/{created['instance_id']}",
        json={"display_name": "TDA renamed", "metadata": {"region": "us"}},
    )
    deleted = await client.delete(f"/api/security/integrations/instances/{created['instance_id']}")
    fetched = await client.get(f"/api/security/integrations/instances/{created['instance_id']}")

    assert patched.status_code == 200
    assert patched.json()["updated_at"] != before_updated_at
    assert patched.json()["metadata"] == {"region": "us"}
    assert deleted.status_code == 200
    assert fetched.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "method"),
    [
        ({"package_id": "unknown.package", "display_name": "Unknown"}, "post"),
        ({"package_id": "asiainfo.tda", "display_name": "TDA", "base_url": "ftp://example.test"}, "post"),
        ({"package_id": "asiainfo.tda", "display_name": "TDA", "metadata": {"nested": {"api_key": "x"}}}, "post"),
        ({"package_id": "asiainfo.tda", "display_name": "TDA", "metadata": {"nested": ["Bearer abc"]}}, "post"),
    ],
)
async def test_create_validation_errors_return_400(client: AsyncClient, payload: dict[str, object], method: str) -> None:
    response = await client.post("/api/security/integrations/instances", json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata", [{"nested": {"token": "x"}}, {"note": "password=abc"}])
async def test_update_metadata_secret_like_key_or_value_returns_400(client: AsyncClient, metadata: dict[str, object]) -> None:
    created = await create_instance(client)
    response = await client.patch(
        f"/api/security/integrations/instances/{created['instance_id']}",
        json={"metadata": metadata},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_credential_profile_id_is_reference_and_response_has_no_credential_values(client: AsyncClient) -> None:
    created = await create_instance(client, credential_profile_id="cred-profile-a", metadata={"safe": "value"})
    serialized = str(created)

    assert created["credential_profile_id"] == "cred-profile-a"
    assert "plain-secret" not in serialized
    for forbidden in ("api_key", "secret", "token", "password"):
        assert forbidden not in serialized.lower()


@pytest.mark.asyncio
async def test_reinstantiated_store_reads_previously_created_instance(client: AsyncClient) -> None:
    created = await create_instance(client, metadata={"region": "cn"})

    reinstantiated_store = PersistentIntegrationInstanceStore()
    fetched = await reinstantiated_store.get_instance(str(created["instance_id"]))

    assert fetched is not None
    assert fetched.instance_id == created["instance_id"]
    assert fetched.metadata == {"region": "cn"}


@pytest.mark.asyncio
async def test_no_connector_call_or_security_object_creation(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Integration Instance persistence must not call v1 connectors")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail_if_called)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", fail_if_called)
    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    response = await client.post("/api/security/integrations/instances", json={"package_id": "asiainfo.tda", "display_name": "TDA"})

    assert response.status_code == 200
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    assert (await client.get("/api/security/incidents")).json() == before_incidents == []
