"""Runtime v2 Sync Profile creation from a connected product."""

from __future__ import annotations

from pathlib import Path
import socket
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations.credential_store import default_credential_profile_store
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


async def bridge_device(client: AsyncClient, device_id: str = "device-tda-1") -> dict[str, Any]:
    response = await client.post(
        "/api/security/integrations/device-bridge/confirm",
        json={"device_id": device_id, "confirmed": True},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] in {"bridged", "already_bridged"}
    return response.json()


def assert_no_plaintext_credentials(*payloads: Any) -> None:
    serialized = " ".join(
        payload.model_dump_json() if hasattr(payload, "model_dump_json") else str(payload) for payload in payloads
    )
    for sensitive_value in SENSITIVE_VALUES:
        assert sensitive_value not in serialized


@pytest.mark.asyncio
async def test_status_reports_not_found_bridge_required_and_ready_capability(client: AsyncClient) -> None:
    missing = await client.get(
        "/api/security/integrations/device-sync-profile/status",
        params={"device_id": "device-missing"},
    )
    await seed_device()
    unlinked = await client.get(
        "/api/security/integrations/device-sync-profile/status",
        params={"device_id": "device-tda-1"},
    )
    bridge = await bridge_device(client)
    ready = await client.get(
        "/api/security/integrations/device-sync-profile/status",
        params={"device_id": "device-tda-1"},
    )

    assert missing.status_code == 200
    assert missing.json()[0]["status"] == "not_found"
    assert missing.json()[0]["bridge_state"] == "unknown"
    assert unlinked.status_code == 200
    assert unlinked.json()[0]["status"] == "bridge_required"
    assert unlinked.json()[0]["bridge_state"] == "unlinked"
    assert ready.status_code == 200
    assert ready.json()[0]["status"] == "ready"
    assert ready.json()[0]["instance_id"] == bridge["instance_id"]
    assert ready.json()[0]["supported_capabilities"] == [
        {
            "capability": "alert.search",
            "display_name": "Alert Search",
            "description": "Configure Runtime v2 metadata for alert synchronization.",
            "supported": True,
            "default_mode": "manual",
            "limitations": [
                "Capability execution is not part of Sync Profile creation.",
                "Vendor requests and Adapter Registry resolution remain outside this operation.",
            ],
        }
    ]
    assert ready.json()[0]["existing_sync_profiles"] == []
    assert_no_plaintext_credentials(missing.json(), unlinked.json(), ready.json())


@pytest.mark.asyncio
async def test_plan_requires_bridge_and_never_auto_bridges(client: AsyncClient) -> None:
    await seed_device()
    response = await client.post(
        "/api/security/integrations/device-sync-profile/plan",
        json={"device_id": "device-tda-1", "capability": "alert.search"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "bridge_required"
    assert response.json()["safety_summary"]["automatic_bridge"] is False
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []
    assert await default_sync_profile_store.list_profiles() == []
    assert await default_integration_run_store.list_runs() == []


@pytest.mark.asyncio
async def test_plan_forces_dry_run_and_modifies_no_runtime_metadata(client: AsyncClient) -> None:
    await seed_device()
    bridge = await bridge_device(client)
    before_instance = await default_integration_instance_store.get_instance(bridge["instance_id"])
    before_credential = await default_credential_profile_store.get_profile(bridge["credential_profile_id"])

    response = await client.post(
        "/api/security/integrations/device-sync-profile/plan",
        json={
            "device_id": "device-tda-1",
            "capability": "alert.search",
            "dry_run": False,
            "params": {"severity": "high", "limit": 50, "time_range": "24h"},
            "schedule": {"interval_seconds": 3600},
        },
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["sync_profile_id"] is None
    assert result["plan_summary"]["schedule_requested"] is True
    assert result["plan_summary"]["schedule_applied"] is False
    assert result["plan_summary"]["automatic_scheduling_started"] is False
    assert await default_integration_instance_store.get_instance(bridge["instance_id"]) == before_instance
    assert await default_credential_profile_store.get_profile(bridge["credential_profile_id"]) == before_credential
    assert await default_sync_profile_store.list_profiles() == []
    assert await default_integration_run_store.list_runs() == []


@pytest.mark.asyncio
async def test_confirm_requires_explicit_confirmation(client: AsyncClient) -> None:
    await seed_device()
    await bridge_device(client)

    response = await client.post(
        "/api/security/integrations/device-sync-profile/confirm",
        json={"device_id": "device-tda-1", "confirmed": False},
    )

    assert response.status_code == 400
    assert "confirmed=True" in response.json()["detail"]
    assert await default_sync_profile_store.list_profiles() == []
    assert await default_integration_run_store.list_runs() == []


@pytest.mark.asyncio
async def test_confirm_unbridged_device_does_not_create_bridge_or_profile(client: AsyncClient) -> None:
    await seed_device()
    response = await client.post(
        "/api/security/integrations/device-sync-profile/confirm",
        json={"device_id": "device-tda-1", "confirmed": True},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "bridge_required"
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []
    assert await default_sync_profile_store.list_profiles() == []


@pytest.mark.asyncio
async def test_confirm_rejects_unsupported_capability(client: AsyncClient) -> None:
    await seed_device()
    await bridge_device(client)
    response = await client.post(
        "/api/security/integrations/device-sync-profile/confirm",
        json={
            "device_id": "device-tda-1",
            "capability": "asset.search",
            "confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "unsupported"
    assert await default_sync_profile_store.list_profiles() == []
    assert await default_integration_run_store.list_runs() == []


@pytest.mark.asyncio
async def test_confirm_creates_safe_profile_and_reuses_it_idempotently(client: AsyncClient) -> None:
    await seed_device()
    bridge = await bridge_device(client)
    payload = {
        "device_id": "device-tda-1",
        "capability": "alert.search",
        "confirmed": True,
        "params": {
            "severity": "high",
            "limit": 50,
            "secret_ref": "device-integration://device-tda-1",
            "credential_profile_id": bridge["credential_profile_id"],
            "has_secret": True,
        },
        "schedule": {"interval_seconds": 3600},
    }
    first = await client.post("/api/security/integrations/device-sync-profile/confirm", json=payload)
    second = await client.post("/api/security/integrations/device-sync-profile/confirm", json=payload)

    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == "created"
    assert second.json()["status"] == "already_exists"
    assert second.json()["sync_profile_id"] == first.json()["sync_profile_id"]
    profiles = await default_sync_profile_store.list_profiles()
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.sync_profile_id == first.json()["sync_profile_id"]
    assert profile.display_name == "TDA Production alert.search sync"
    assert profile.instance_id == bridge["instance_id"]
    assert profile.package_id == "asiainfo.tda"
    assert profile.capability == "alert.search"
    assert profile.mode == "manual"
    assert profile.enabled is True
    assert profile.schedule is None
    assert profile.params == payload["params"]
    assert profile.metadata == {
        "source": "device_sync_profile",
        "device_id": "device-tda-1",
        "device_name": "TDA Production",
        "package_id": "asiainfo.tda",
        "instance_id": bridge["instance_id"],
        "capability": "alert.search",
        "bridge_source": "device_integration_bridge",
        "bridge_version": "v1",
    }
    assert await default_integration_run_store.list_runs() == []
    assert_no_plaintext_credentials(first.json(), second.json(), profile)

    status = await client.get(
        "/api/security/integrations/device-sync-profile/status",
        params={"device_id": "device-tda-1"},
    )
    assert status.json()[0]["existing_sync_profiles"] == [
        {
            "sync_profile_id": profile.sync_profile_id,
            "display_name": profile.display_name,
            "package_id": profile.package_id,
            "instance_id": profile.instance_id,
            "capability": profile.capability,
            "mode": profile.mode,
            "enabled": True,
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {"token": SENSITIVE_VALUES[0]},
        {"api_key": SENSITIVE_VALUES[1]},
        {"password": SENSITIVE_VALUES[2]},
        {"authorization": SENSITIVE_VALUES[3]},
        {"query": SENSITIVE_VALUES[0]},
        {"nested": {"authorization": SENSITIVE_VALUES[3]}},
    ],
)
async def test_dangerous_params_are_rejected_without_echoing_values(
    client: AsyncClient, params: dict[str, Any]
) -> None:
    await seed_device()
    await bridge_device(client)
    response = await client.post(
        "/api/security/integrations/device-sync-profile/confirm",
        json={"device_id": "device-tda-1", "confirmed": True, "params": params},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "validation_failed"
    assert await default_sync_profile_store.list_profiles() == []
    assert_no_plaintext_credentials(response.json())


@pytest.mark.asyncio
async def test_creation_crosses_no_execution_evidence_or_security_boundary(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed_device()
    bridge = await bridge_device(client)
    before_row = await fetch_device("device-tda-1")
    assert before_row is not None
    before_device = dict(before_row)
    before_instance = await default_integration_instance_store.get_instance(bridge["instance_id"])
    before_credential = await default_credential_profile_store.get_profile(bridge["credential_profile_id"])

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Sync Profile creation crossed its metadata-only boundary")

    monkeypatch.setattr("flocks.tool.device.store.fetch_device", forbidden)
    monkeypatch.setattr("flocks.tool.device.store.mask_for_display", forbidden)
    monkeypatch.setattr("flocks.tool.device.secrets.resolve_for_runtime", forbidden)
    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr("flocks.security.connectors.registry.ConnectorRegistry.sync", forbidden)
    monkeypatch.setattr("flocks.security.integrations.adapter_registry.AdapterRegistry.get_adapter", forbidden)
    monkeypatch.setattr("flocks.security.integrations.evidence_dispatcher.dispatch_evidence_events", forbidden)
    monkeypatch.setattr("flocks.security.integrations.credential_store.resolve_credential_profile_ref", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()
    response = await client.post(
        "/api/security/integrations/device-sync-profile/confirm",
        json={"device_id": "device-tda-1", "confirmed": True},
    )
    after_row = await fetch_device("device-tda-1")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "created"
    assert after_row is not None and dict(after_row) == before_device
    assert await default_integration_instance_store.get_instance(bridge["instance_id"]) == before_instance
    assert await default_credential_profile_store.get_profile(bridge["credential_profile_id"]) == before_credential
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    assert (await client.get("/api/security/incidents")).json() == before_incidents == []
    assert await default_integration_run_store.list_runs() == []
    assert response.json()["safety_summary"] == {
        "metadata_only": True,
        "dry_run": False,
        "automatic_bridge": False,
        "credential_values_read_or_copied": False,
        "vendor_call": False,
        "connector_call": False,
        "adapter_call": False,
        "adapter_registry_call": False,
        "sync_execution": False,
        "preview": False,
        "confirm_ingest": False,
        "integration_run_created": False,
        "evidence_dispatch": False,
        "security_objects_created": False,
        "notification_created": False,
        "remediation": False,
    }
    assert_no_plaintext_credentials(response.json())


def test_integrations_init_exports_device_sync_profile_symbols() -> None:
    import flocks.security.integrations as integrations

    for name in [
        "DeviceSyncCapability",
        "DeviceSyncProfileConfirmRequest",
        "DeviceSyncProfileCreateRequest",
        "DeviceSyncProfileCreateResult",
        "DeviceSyncProfileService",
        "DeviceSyncProfileStatus",
        "default_device_sync_profile_service",
    ]:
        assert hasattr(integrations, name)
