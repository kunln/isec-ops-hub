"""Device Integration to Runtime v2 reference bridge tests."""

from __future__ import annotations

from pathlib import Path
import socket
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations.credential_store import default_credential_profile_store
from flocks.security.integrations.device_bridge import DeviceBridgeRequest, default_device_integration_bridge
from flocks.security.integrations.instance_store import default_integration_instance_store
from flocks.security.integrations.run_store import default_integration_run_store
from flocks.security.integrations.sync_profile_store import default_sync_profile_store
from flocks.storage.storage import Storage
from flocks.tool.device.models import DEFAULT_GROUP_ID
from flocks.tool.device.store import fetch_device, insert_device

SENSITIVE_VALUES = (
    "REAL_TOKEN_SHOULD_NOT_LEAK",
    "REAL_API_KEY_SHOULD_NOT_LEAK",
    "REAL_PASSWORD_SHOULD_NOT_LEAK",
    "Bearer REAL_AUTH_SHOULD_NOT_LEAK",
)


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


async def seed_device(
    device_id: str = "device-tda-1",
    *,
    storage_key: str = "asiainfo_tda_api_v7_0",
    service_id: str = "asiainfo_tda_api",
    name: str = "TDA Production",
) -> None:
    await insert_device(
        device_id=device_id,
        group_id=DEFAULT_GROUP_ID,
        name=name,
        storage_key=storage_key,
        service_id=service_id,
        enabled=True,
        verify_ssl=True,
        db_fields={
            "token": SENSITIVE_VALUES[0],
            "api_key": SENSITIVE_VALUES[1],
            "password": SENSITIVE_VALUES[2],
            "authorization": SENSITIVE_VALUES[3],
            "base_url": "https://tda.example.test",
        },
        status="ok",
    )


def assert_no_plaintext_credentials(*payloads: Any) -> None:
    serialized = " ".join(
        payload.model_dump_json() if hasattr(payload, "model_dump_json") else str(payload) for payload in payloads
    )
    for sensitive_value in SENSITIVE_VALUES:
        assert sensitive_value not in serialized


@pytest.mark.asyncio
async def test_dry_run_plan_is_read_only_and_does_not_read_device_fields(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed_device()
    before_row = await fetch_device("device-tda-1")
    assert before_row is not None
    before = dict(before_row)

    def fail_if_masking_fields(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Bridge must not read or mask Device Integration credential fields")

    monkeypatch.setattr("flocks.tool.device.store.mask_for_display", fail_if_masking_fields)
    result = await default_device_integration_bridge.bridge_device_integration(
        DeviceBridgeRequest(device_id="device-tda-1")
    )
    after_row = await fetch_device("device-tda-1")

    assert result.status == "planned"
    assert result.package_id == "asiainfo.tda"
    assert result.supported_capabilities == ["alert.search"]
    assert result.instance_id is None
    assert result.credential_profile_id is None
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []
    assert after_row is not None and dict(after_row) == before
    assert_no_plaintext_credentials(result)


@pytest.mark.asyncio
async def test_missing_and_unsupported_devices_return_safe_statuses(client: AsyncClient) -> None:
    missing = await default_device_integration_bridge.bridge_device_integration(
        DeviceBridgeRequest(device_id="device-missing")
    )
    await seed_device(
        "device-unsupported",
        storage_key="unsupported_product_v1",
        service_id="unsupported_product",
        name="Unsupported Product",
    )
    unsupported = await default_device_integration_bridge.bridge_device_integration(
        DeviceBridgeRequest(device_id="device-unsupported")
    )

    assert missing.status == "not_found"
    assert unsupported.status == "unsupported"
    assert unsupported.package_id is None
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []


@pytest.mark.asyncio
async def test_plan_api_forces_dry_run_without_creating_runtime_objects(client: AsyncClient) -> None:
    await seed_device()
    response = await client.post(
        "/api/security/integrations/device-bridge/plan",
        json={"device_id": "device-tda-1", "dry_run": False},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "planned"
    assert response.json()["safety_summary"]["dry_run"] is True
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []


@pytest.mark.asyncio
async def test_confirm_api_requires_explicit_confirmation(client: AsyncClient) -> None:
    await seed_device()

    response = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": "device-tda-1", "confirmed": False},
    )

    assert response.status_code == 400
    assert "confirmed=True" in response.json()["detail"]
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []


@pytest.mark.asyncio
async def test_confirm_creates_safe_linked_instance_and_credential_reference(client: AsyncClient) -> None:
    await seed_device()
    response = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": "device-tda-1", "confirmed": True, "dry_run": True},
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "bridged"
    assert result["package_id"] == "asiainfo.tda"
    assert result["instance_id"].startswith("intinst_")
    assert result["credential_profile_id"].startswith("credprof_")
    assert result["safety_summary"]["dry_run"] is False

    instance = await default_integration_instance_store.get_instance(result["instance_id"])
    profile = await default_credential_profile_store.get_profile(result["credential_profile_id"])
    assert instance is not None
    assert profile is not None
    assert instance.credential_profile_id == profile.credential_profile_id
    assert profile.instance_id == instance.instance_id
    assert instance.metadata == {
        "source": "device_integration_bridge",
        "device_id": "device-tda-1",
        "device_name": "TDA Production",
        "device_storage_key": "asiainfo_tda_api_v7_0",
        "device_service_id": "asiainfo_tda_api",
        "package_id": "asiainfo.tda",
        "bridge_version": "v1",
    }
    assert profile.profile_type == "device_integration_reference"
    assert profile.secret_ref == "device-integration://device-tda-1"
    assert profile.metadata["source"] == "device_integration"
    assert profile.metadata["device_id"] == "device-tda-1"
    assert_no_plaintext_credentials(result, instance, profile)


@pytest.mark.asyncio
async def test_confirm_is_idempotent_and_does_not_create_sync_profile_or_run(client: AsyncClient) -> None:
    await seed_device()
    first = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": "device-tda-1", "confirmed": True},
    )
    second = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": "device-tda-1", "confirmed": True},
    )

    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == "bridged"
    assert second.json()["status"] == "already_bridged"
    assert second.json()["instance_id"] == first.json()["instance_id"]
    assert second.json()["credential_profile_id"] == first.json()["credential_profile_id"]
    assert len(await default_integration_instance_store.list_instances()) == 1
    assert len(await default_credential_profile_store.list_profiles()) == 1
    assert await default_sync_profile_store.list_profiles() == []
    assert await default_integration_run_store.list_runs() == []


@pytest.mark.asyncio
async def test_status_api_reports_linked_unlinked_unsupported_and_unknown(client: AsyncClient) -> None:
    await seed_device("device-linked", name="Linked TDA")
    await seed_device("device-unlinked", name="Unlinked TDA")
    await seed_device(
        "device-unsupported",
        storage_key="unsupported_product_v1",
        service_id="unsupported_product",
        name="Unsupported Product",
    )
    confirmed = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": "device-linked", "confirmed": True},
    )
    assert confirmed.status_code == 200

    response = await client.get("/api/security/integrations/device-bridge/status")
    missing = await client.get(
        "/api/security/integrations/device-bridge/status", params={"device_id": "device-missing"}
    )
    by_id = {item["device_id"]: item for item in response.json()}

    assert response.status_code == 200
    assert by_id["device-linked"]["bridge_state"] == "linked"
    assert by_id["device-unlinked"]["bridge_state"] == "unlinked"
    assert by_id["device-unsupported"]["bridge_state"] == "unsupported"
    assert missing.status_code == 200
    assert missing.json()[0]["bridge_state"] == "unknown"


@pytest.mark.asyncio
async def test_bridge_calls_no_adapter_connector_network_or_evidence_dispatcher(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed_device()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Bridge crossed its Integration Layer reference-only boundary")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr("flocks.security.integrations.adapter_registry.AdapterRegistry.get_adapter", forbidden)
    monkeypatch.setattr("flocks.security.integrations.evidence_dispatcher.dispatch_evidence_events", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()
    response = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": "device-tda-1", "confirmed": True},
    )

    assert response.status_code == 200, response.text
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    assert (await client.get("/api/security/incidents")).json() == before_incidents == []
    assert await default_sync_profile_store.list_profiles() == []
    assert await default_integration_run_store.list_runs() == []
