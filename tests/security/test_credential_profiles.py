"""Credential Profile metadata API tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations.credential_store import resolve_credential_profile_ref
from flocks.security.integrations.instances import IntegrationInstance
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


async def create_profile(client: AsyncClient, **extra: object) -> dict[str, object]:
    payload = {
        "display_name": "TDA Credential Profile",
        "profile_type": "api_key",
        "package_id": "asiainfo.tda",
        "secret_ref": "vault://integration/tda/default",
        "required_fields": ["api_key"],
        "configured_fields": ["api_key"],
        "metadata": {"owner": "secops"},
    }
    payload.update(extra)
    response = await client.post("/api/security/integrations/credential-profiles", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_create_get_list_filters_update_and_delete(client: AsyncClient) -> None:
    tda = await create_profile(client, instance_id="intinst_a")
    mingyu = await create_profile(
        client,
        display_name="Mingyu Credential Profile",
        package_id="dbappsecurity.mingyu_apt",
        instance_id="intinst_b",
        status="ignored-on-create",
    )
    patched_mingyu = await client.patch(
        f"/api/security/integrations/credential-profiles/{mingyu['credential_profile_id']}",
        json={"display_name": "Mingyu Updated", "status": "active"},
    )

    fetched = await client.get(f"/api/security/integrations/credential-profiles/{tda['credential_profile_id']}")
    listed = await client.get("/api/security/integrations/credential-profiles")
    package_filtered = await client.get("/api/security/integrations/credential-profiles", params={"package_id": "asiainfo.tda"})
    instance_filtered = await client.get("/api/security/integrations/credential-profiles", params={"instance_id": "intinst_b"})
    status_filtered = await client.get("/api/security/integrations/credential-profiles", params={"status": "active"})
    deleted = await client.delete(f"/api/security/integrations/credential-profiles/{tda['credential_profile_id']}")
    missing_after_delete = await client.get(f"/api/security/integrations/credential-profiles/{tda['credential_profile_id']}")

    assert fetched.status_code == 200
    assert fetched.json()["credential_profile_id"] == tda["credential_profile_id"]
    assert listed.status_code == 200
    assert {item["credential_profile_id"] for item in listed.json()} == {tda["credential_profile_id"], mingyu["credential_profile_id"]}
    assert [item["credential_profile_id"] for item in package_filtered.json()] == [tda["credential_profile_id"]]
    assert [item["credential_profile_id"] for item in instance_filtered.json()] == [mingyu["credential_profile_id"]]
    assert patched_mingyu.status_code == 200
    assert patched_mingyu.json()["display_name"] == "Mingyu Updated"
    assert patched_mingyu.json()["status"] == "active"
    assert [item["credential_profile_id"] for item in status_filtered.json()] == [mingyu["credential_profile_id"]]
    assert deleted.status_code == 200
    assert missing_after_delete.status_code == 404


@pytest.mark.asyncio
async def test_unknown_profile_returns_404(client: AsyncClient) -> None:
    response = await client.get("/api/security/integrations/credential-profiles/credprof_missing")
    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"display_name": "Unknown", "package_id": "unknown.package"},
        {"display_name": "Bad metadata key", "metadata": {"api_key": "redacted"}},
        {"display_name": "Bad metadata value", "metadata": {"note": "Bearer secret-value"}},
        {"display_name": "Bad required field", "required_fields": ["api_key=abc"]},
        {"display_name": "Bad configured field equals", "configured_fields": ["api_key=abc"]},
        {"display_name": "Bad configured field colon", "configured_fields": ["secret:abc"]},
        {"display_name": "Bad configured field bearer", "configured_fields": ["Bearer abc"]},
        {"display_name": "Bad secret ref", "secret_ref": "Bearer abc"},
        {"display_name": "Bad secret ref password", "secret_ref": "password=abc"},
    ],
)
async def test_validation_errors_return_400(client: AsyncClient, payload: dict[str, object]) -> None:
    response = await client.post("/api/security/integrations/credential-profiles", json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_response_contains_no_credential_values(client: AsyncClient) -> None:
    profile = await create_profile(client, configured_fields=["api_key", "secret", "token", "password"])
    serialized = str(profile)

    assert "plain-api-key-value" not in serialized
    assert "plain-secret-value" not in serialized
    assert "plain-token-value" not in serialized
    assert "plain-password-value" not in serialized
    assert profile["configured_fields"] == ["api_key", "secret", "token", "password"]


@pytest.mark.asyncio
async def test_no_connector_http_or_security_object_creation(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Credential Profile APIs must not call connectors or outbound HTTP")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail_if_called)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", fail_if_called)
    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    response = await client.post("/api/security/integrations/credential-profiles", json={"display_name": "Safe"})

    assert response.status_code == 200
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    assert (await client.get("/api/security/incidents")).json() == before_incidents == []


@pytest.mark.asyncio
async def test_integration_instance_can_reference_profile_id_without_secret_resolution(client: AsyncClient) -> None:
    profile = await create_profile(client)
    instance = IntegrationInstance(
        instance_id="intinst_reference_only",
        package_id="asiainfo.tda",
        display_name="TDA Instance",
        credential_profile_id=str(profile["credential_profile_id"]),
    )
    resolved = await resolve_credential_profile_ref(instance.credential_profile_id or "")

    assert instance.credential_profile_id == profile["credential_profile_id"]
    assert resolved is not None
    assert resolved.credential_profile_id == profile["credential_profile_id"]
    assert not hasattr(resolved, "api_key")
    assert "plain-secret" not in str(resolved)
