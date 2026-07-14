"""Sync Profile metadata API tests."""

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


async def create_instance(client: AsyncClient, **extra: object) -> dict[str, object]:
    payload = {"package_id": "asiainfo.tda", "display_name": "TDA Instance", "metadata": {"region": "test"}}
    payload.update(extra)
    response = await client.post("/api/security/integrations/instances", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


async def create_sync_profile(client: AsyncClient, instance_id: str, **extra: object) -> dict[str, object]:
    payload = {
        "display_name": "TDA Alert Sync",
        "instance_id": instance_id,
        "capability": "alert.search",
        "params": {"limit": 10},
        "cursor": {"since": "2026-01-01T00:00:00Z"},
        "metadata": {"owner": "secops"},
    }
    payload.update(extra)
    response = await client.post("/api/security/integrations/sync-profiles", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_create_get_list_filters_update_and_delete(client: AsyncClient) -> None:
    tda_instance = await create_instance(client)
    mingyu_instance = await create_instance(
        client, package_id="dbappsecurity.mingyu_apt", display_name="Mingyu Instance", enabled=False
    )
    tda_profile = await create_sync_profile(client, str(tda_instance["instance_id"]))
    mingyu_profile = await create_sync_profile(
        client,
        str(mingyu_instance["instance_id"]),
        display_name="Mingyu Risk Sync",
        capability="risk.search",
        enabled=False,
    )

    fetched = await client.get(f"/api/security/integrations/sync-profiles/{tda_profile['sync_profile_id']}")
    listed = await client.get("/api/security/integrations/sync-profiles")
    instance_filtered = await client.get(
        "/api/security/integrations/sync-profiles", params={"instance_id": tda_instance["instance_id"]}
    )
    package_filtered = await client.get("/api/security/integrations/sync-profiles", params={"package_id": "asiainfo.tda"})
    capability_filtered = await client.get(
        "/api/security/integrations/sync-profiles", params={"capability": "risk.search"}
    )
    enabled_filtered = await client.get("/api/security/integrations/sync-profiles", params={"enabled": "false"})
    patched = await client.patch(
        f"/api/security/integrations/sync-profiles/{tda_profile['sync_profile_id']}",
        json={"display_name": "Updated Sync", "enabled": False, "schedule": "0 * * * *"},
    )
    deleted = await client.delete(f"/api/security/integrations/sync-profiles/{tda_profile['sync_profile_id']}")
    missing_after_delete = await client.get(f"/api/security/integrations/sync-profiles/{tda_profile['sync_profile_id']}")

    assert tda_profile["sync_profile_id"].startswith("syncprof_")
    assert tda_profile["package_id"] == tda_instance["package_id"]
    assert tda_profile["create_analysis_cases"] is False
    assert tda_profile["run_initial_analysis"] is False
    assert fetched.status_code == 200
    assert fetched.json()["sync_profile_id"] == tda_profile["sync_profile_id"]
    assert {item["sync_profile_id"] for item in listed.json()} == {
        tda_profile["sync_profile_id"],
        mingyu_profile["sync_profile_id"],
    }
    assert [item["sync_profile_id"] for item in instance_filtered.json()] == [tda_profile["sync_profile_id"]]
    assert [item["sync_profile_id"] for item in package_filtered.json()] == [tda_profile["sync_profile_id"]]
    assert [item["sync_profile_id"] for item in capability_filtered.json()] == [mingyu_profile["sync_profile_id"]]
    assert [item["sync_profile_id"] for item in enabled_filtered.json()] == [mingyu_profile["sync_profile_id"]]
    assert patched.status_code == 200
    assert patched.json()["display_name"] == "Updated Sync"
    assert patched.json()["enabled"] is False
    assert patched.json()["schedule"] == "0 * * * *"
    assert deleted.status_code == 200
    assert missing_after_delete.status_code == 404


@pytest.mark.asyncio
async def test_unknown_sync_profile_returns_404(client: AsyncClient) -> None:
    assert (await client.get("/api/security/integrations/sync-profiles/syncprof_missing")).status_code == 404
    assert (await client.patch("/api/security/integrations/sync-profiles/syncprof_missing", json={})).status_code == 404
    assert (await client.delete("/api/security/integrations/sync-profiles/syncprof_missing")).status_code == 404


@pytest.mark.asyncio
async def test_unknown_instance_id_returns_400(client: AsyncClient) -> None:
    payload = {"display_name": "Missing", "instance_id": "intinst_missing", "capability": "alert.search"}
    assert (await client.post("/api/security/integrations/sync-profiles", json=payload)).status_code == 400
    assert (
        await client.get("/api/security/integrations/sync-profiles", params={"instance_id": "intinst_missing"})
    ).status_code == 400


@pytest.mark.asyncio
async def test_unknown_capability_returns_400(client: AsyncClient) -> None:
    instance = await create_instance(client)
    payload = {"display_name": "Bad", "instance_id": instance["instance_id"], "capability": "missing.search"}
    assert (await client.post("/api/security/integrations/sync-profiles", json=payload)).status_code == 400


@pytest.mark.asyncio
async def test_create_payload_cannot_override_package_id(client: AsyncClient) -> None:
    instance = await create_instance(client)
    payload = {
        "display_name": "Bad Package Override",
        "instance_id": instance["instance_id"],
        "package_id": "dbappsecurity.mingyu_apt",
        "capability": "alert.search",
    }
    response = await client.post("/api/security/integrations/sync-profiles", json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("params", {"api_key": "redacted"}),
        ("params", {"query": "Bearer secret-value"}),
        ("cursor", {"token": "redacted"}),
        ("cursor", {"next": "password=abc"}),
        ("metadata", {"authorization": "redacted"}),
        ("metadata", {"note": "api_key=abc"}),
    ],
)
async def test_secret_like_key_or_value_returns_400(client: AsyncClient, field: str, bad: dict[str, object]) -> None:
    instance = await create_instance(client)
    payload = {"display_name": "Bad", "instance_id": instance["instance_id"], "capability": "alert.search", field: bad}
    response = await client.post("/api/security/integrations/sync-profiles", json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_safe_credential_references_are_allowed_without_accepting_plaintext(client: AsyncClient) -> None:
    instance = await create_instance(client)
    safe = await client.post(
        "/api/security/integrations/sync-profiles",
        json={
            "display_name": "Safe References",
            "instance_id": instance["instance_id"],
            "capability": "alert.search",
            "params": {
                "secret_ref": "device-integration://device-tda-1",
                "credential_profile_id": "credprof_reference_only",
                "has_secret": True,
            },
        },
    )
    unsafe = await client.post(
        "/api/security/integrations/sync-profiles",
        json={
            "display_name": "Unsafe Reference",
            "instance_id": instance["instance_id"],
            "capability": "alert.search",
            "params": {"secret_ref": "REAL_TOKEN_SHOULD_NOT_LEAK"},
        },
    )

    assert safe.status_code == 200, safe.text
    assert safe.json()["params"]["secret_ref"] == "device-integration://device-tda-1"
    assert unsafe.status_code == 400
    assert "REAL_TOKEN_SHOULD_NOT_LEAK" not in unsafe.text


@pytest.mark.asyncio
async def test_no_connector_http_credential_read_or_security_object_creation(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Sync Profile APIs must not perform side effects")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail_if_called)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", fail_if_called)
    monkeypatch.setattr("flocks.security.integrations.credential_store.resolve_credential_profile_ref", fail_if_called)
    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    instance = await create_instance(client, credential_profile_id="credprof_reference_only")
    profile = await create_sync_profile(client, str(instance["instance_id"]))

    assert profile["instance_id"] == instance["instance_id"]
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    assert (await client.get("/api/security/incidents")).json() == before_incidents == []


@pytest.mark.asyncio
async def test_storage_rebuild_can_read_profile(client: AsyncClient) -> None:
    instance = await create_instance(client)
    profile = await create_sync_profile(client, str(instance["instance_id"]))
    from flocks.security.integrations.sync_profile_store import SyncProfileStore

    rebuilt = SyncProfileStore()
    fetched = await rebuilt.get_profile(str(profile["sync_profile_id"]))

    assert fetched is not None
    assert fetched.sync_profile_id == profile["sync_profile_id"]


def test_integrations_init_exports_existing_and_sync_profile_symbols() -> None:
    import flocks.security.integrations as integrations

    for name in [
        "MappingRule",
        "IntegrationInstance",
        "CredentialProfile",
        "EvidenceDispatchRequest",
        "IntegrationCapabilityRuntime",
        "SyncProfile",
        "SyncProfileCreate",
        "SyncProfileUpdate",
        "SyncProfileStore",
        "default_sync_profile_store",
    ]:
        assert hasattr(integrations, name)
