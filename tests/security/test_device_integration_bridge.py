"""Device Integration to Runtime v2 metadata bridge tests."""

from __future__ import annotations

import asyncio
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
from flocks.security.store import default_store
from flocks.storage.storage import Storage
from flocks.tool.device.models import DEFAULT_GROUP_ID
from flocks.tool.device.store import fetch_device, insert_device

SENSITIVE_VALUES = (
    "REAL_TOKEN_SHOULD_NOT_LEAK",
    "REAL_API_KEY_SHOULD_NOT_LEAK",
    "REAL_SECRET_SHOULD_NOT_LEAK",
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
    device_integration_id: str = "device-tda-1",
    *,
    storage_key: str = "asiainfo_tda_api_v7_0",
    service_id: str = "asiainfo_tda_api",
    name: str = "TDA Production",
    enabled: bool = True,
    status: str = "ok",
) -> None:
    await insert_device(
        device_id=device_integration_id,
        group_id=DEFAULT_GROUP_ID,
        name=name,
        storage_key=storage_key,
        service_id=service_id,
        enabled=enabled,
        verify_ssl=True,
        db_fields={
            "token": SENSITIVE_VALUES[0],
            "api_key": SENSITIVE_VALUES[1],
            "secret": SENSITIVE_VALUES[2],
            "authorization": SENSITIVE_VALUES[3],
            "base_url": "https://tda.example.test",
        },
        status=status,
    )


def assert_no_plaintext_credentials(*payloads: Any) -> None:
    serialized = " ".join(
        payload.model_dump_json() if hasattr(payload, "model_dump_json") else str(payload)
        for payload in payloads
    )
    for sensitive_value in SENSITIVE_VALUES:
        assert sensitive_value not in serialized


@pytest.mark.asyncio
async def test_bridge_api_requires_security_ops_write(client: AsyncClient) -> None:
    await seed_device()
    from fastapi import FastAPI, Request
    from flocks.auth.context import AuthUser
    from flocks.server.routes.security import router as security_router

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

    app.include_router(security_router, prefix="/api/security")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as viewer:
        response = await viewer.post(
            "/api/security/integrations/device-bridge",
            json={"device_integration_id": "device-tda-1", "capability": "alert.search"},
        )

    assert response.status_code == 403
    assert "security.ops.write" in response.json()["detail"]
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []
    assert await default_sync_profile_store.list_profiles() == []


@pytest.mark.asyncio
async def test_bridge_api_creates_instance_credential_reference_and_alert_sync_profile(
    client: AsyncClient,
) -> None:
    await seed_device()

    response = await client.post(
        "/api/security/integrations/device-bridge",
        json={
            "device_integration_id": "device-tda-1",
            "capability": "alert.search",
            "requested_by": "security-operator",
        },
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result == {
        "status": "created",
        "device_integration_id": "device-tda-1",
        "instance_id": result["instance_id"],
        "credential_profile_id": result["credential_profile_id"],
        "sync_profile_id": result["sync_profile_id"],
        "capability": "alert.search",
        "warnings": [],
        "errors": [],
    }
    assert result["instance_id"].startswith("intinst_")
    assert result["credential_profile_id"].startswith("credprof_")
    assert result["sync_profile_id"].startswith("syncprof_")

    instance = await default_integration_instance_store.get_instance(result["instance_id"])
    credential_profile = await default_credential_profile_store.get_profile(
        result["credential_profile_id"]
    )
    sync_profile = await default_sync_profile_store.get_profile(result["sync_profile_id"])

    assert instance is not None
    assert credential_profile is not None
    assert sync_profile is not None
    assert instance.package_id == "asiainfo.tda"
    assert instance.display_name == "TDA Production"
    assert instance.base_url is None
    assert instance.verify_ssl is True
    assert instance.enabled is True
    assert instance.credential_profile_id == credential_profile.credential_profile_id
    assert instance.metadata["source_device_integration_id"] == "device-tda-1"
    assert instance.metadata["base_url_summary"] == "managed_by_device_integration"

    assert credential_profile.instance_id == instance.instance_id
    assert credential_profile.profile_type == "device_integration_reference"
    assert credential_profile.secret_ref == "device-integration:device-tda-1"
    assert credential_profile.required_fields == ["api_key", "secret"]
    assert credential_profile.configured_fields == []
    assert credential_profile.metadata["source_device_integration_id"] == "device-tda-1"

    assert sync_profile.instance_id == instance.instance_id
    assert sync_profile.package_id == "asiainfo.tda"
    assert sync_profile.display_name == "TDA Production 告警同步"
    assert sync_profile.capability == "alert.search"
    assert sync_profile.mode == "manual"
    assert sync_profile.schedule == "manual"
    assert sync_profile.enabled is True
    assert sync_profile.params == {"time_range": "last_24h", "page_size": 100}
    assert sync_profile.create_analysis_cases is False
    assert sync_profile.run_initial_analysis is False
    assert sync_profile.metadata["source_device_integration_id"] == "device-tda-1"
    assert_no_plaintext_credentials(result, instance, credential_profile, sync_profile)


@pytest.mark.asyncio
async def test_bridge_is_idempotent_for_repeated_and_concurrent_requests(client: AsyncClient) -> None:
    await seed_device()
    request = DeviceBridgeRequest(
        device_integration_id="device-tda-1",
        capability="alert.search",
        requested_by="security-operator",
    )

    first, second = await asyncio.gather(
        default_device_integration_bridge.bridge_device_integration(request),
        default_device_integration_bridge.bridge_device_integration(request),
    )
    third = await default_device_integration_bridge.bridge_device_integration(request)

    assert {first.status, second.status} == {"created", "reused"}
    assert third.status == "reused"
    assert first.instance_id == second.instance_id == third.instance_id
    assert first.credential_profile_id == second.credential_profile_id == third.credential_profile_id
    assert first.sync_profile_id == second.sync_profile_id == third.sync_profile_id
    assert len(await default_integration_instance_store.list_instances()) == 1
    assert len(await default_credential_profile_store.list_profiles()) == 1
    assert len(await default_sync_profile_store.list_profiles()) == 1
    assert await default_integration_run_store.list_runs() == []


@pytest.mark.asyncio
async def test_bridge_returns_not_found_or_validation_failed_without_partial_objects(
    client: AsyncClient,
) -> None:
    missing = await client.post(
        "/api/security/integrations/device-bridge",
        json={"device_integration_id": "device-missing", "capability": "alert.search"},
    )
    await seed_device(
        "device-unsupported",
        storage_key="unsupported_product_v1",
        service_id="unsupported_product",
        name="Unsupported Product",
    )
    unsupported = await client.post(
        "/api/security/integrations/device-bridge",
        json={"device_integration_id": "device-unsupported", "capability": "alert.search"},
    )
    unsupported_capability = await client.post(
        "/api/security/integrations/device-bridge",
        json={"device_integration_id": "device-unsupported", "capability": "asset.search"},
    )
    invalid_id = await client.post(
        "/api/security/integrations/device-bridge",
        json={"device_integration_id": "unsafe device id", "capability": "alert.search"},
    )

    assert missing.status_code == 200
    assert missing.json()["status"] == "not_found"
    assert unsupported.json()["status"] == "validation_failed"
    assert unsupported_capability.json()["status"] == "validation_failed"
    assert invalid_id.json()["status"] == "validation_failed"
    assert await default_integration_instance_store.list_instances() == []
    assert await default_credential_profile_store.list_profiles() == []
    assert await default_sync_profile_store.list_profiles() == []


@pytest.mark.asyncio
async def test_bridge_does_not_read_plaintext_or_execute_runtime_and_security_paths(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await seed_device()
    before_row = await fetch_device("device-tda-1")
    assert before_row is not None
    before = dict(before_row)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Device bridge crossed its metadata-only Integration Layer boundary")

    monkeypatch.setattr("flocks.tool.device.store.fetch_device", forbidden)
    monkeypatch.setattr("flocks.tool.device.store.get_device_credentials", forbidden)
    monkeypatch.setattr("flocks.tool.device.store.mask_for_display", forbidden)
    monkeypatch.setattr("flocks.tool.device.store.resolve_for_runtime", forbidden)
    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr("flocks.security.integrations.adapter_registry.AdapterRegistry.get_adapter", forbidden)
    monkeypatch.setattr("flocks.security.integrations.sync_engine.plan_sync_profile_run", forbidden)
    monkeypatch.setattr("flocks.security.integrations.sync_preview.preview_sync_profile_run", forbidden)
    monkeypatch.setattr("flocks.security.integrations.sync_ingest.ingest_sync_profile_run", forbidden)
    monkeypatch.setattr(
        "flocks.security.integrations.evidence_dispatcher.dispatch_evidence_events",
        forbidden,
    )
    monkeypatch.setattr(socket, "create_connection", forbidden)

    before_assets = await default_store.list_assets()
    before_alerts = await default_store.list_alerts()
    before_cases = await default_store.list_analysis_cases()
    before_incidents = await default_store.list_incidents()
    response = await client.post(
        "/api/security/integrations/device-bridge",
        json={"device_integration_id": "device-tda-1", "capability": "alert.search"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "created"
    assert await default_store.list_assets() == before_assets == []
    assert await default_store.list_alerts() == before_alerts == []
    assert await default_store.list_analysis_cases() == before_cases == []
    assert await default_store.list_incidents() == before_incidents == []
    assert await default_integration_run_store.list_runs() == []

    async with Storage.connect(Storage.get_db_path()) as db:
        db.row_factory = None
        async with db.execute("SELECT * FROM device_integrations WHERE id = ?", ("device-tda-1",)) as cursor:
            after_row = await cursor.fetchone()
    assert after_row is not None
    assert tuple(after_row) == tuple(before.values())
    assert_no_plaintext_credentials(response.json())
