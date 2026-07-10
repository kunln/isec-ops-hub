"""Tests for Manual Sync Ingest skeleton."""

from __future__ import annotations

import json
import socket
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
        request.state.auth_user = AuthUser(id="admin", username="admin", role="admin", status="active", must_reset_password=False)
        return await call_next(request)

    app.include_router(security_router, prefix="/api/security")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests()


async def seed_fake_profile(*, instance_id: str = "intinst_fake", sync_profile_id: str = "syncprof_fake", capability: str = "alert.search", package_id: str = "fake.integration"):
    from flocks.security.integrations.instances import IntegrationInstance
    from flocks.security.integrations.sync_profiles import SyncProfile

    instance = IntegrationInstance(
        instance_id=instance_id,
        package_id=package_id,
        display_name="Fake",
        credential_profile_id="cred_ref_only",
        metadata={"region": "test"},
    )
    profile = SyncProfile(
        sync_profile_id=sync_profile_id,
        display_name="Fake Sync",
        instance_id=instance_id,
        package_id=package_id,
        capability=capability,
        cursor={"page": "old"},
        params={"limit": 10},
        last_run_id=None,
    )
    await Storage.set(f"security/integration_instances/{instance_id}", instance, "security.integration_instances")
    await Storage.set(f"security/sync_profiles/{sync_profile_id}", profile, "security.sync_profiles")
    return instance, profile


@pytest.mark.asyncio
async def test_ingest_sync_profile_run_success_records_run_and_preserves_profile(client: AsyncClient) -> None:
    from flocks.security.integrations.adapter import FakeIntegrationAdapter
    from flocks.security.integrations.adapter_registry import AdapterRegistry
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store

    _, profile = await seed_fake_profile()
    registry = AdapterRegistry()
    registry.register_adapter_factory(
        "fake.integration",
        "alert.search",
        lambda: FakeIntegrationAdapter(
            "fake.integration",
            {"alert.search"},
            fake_items=[{"id": "a1", "title": "Safe", "severity": "high", "raw_payload": {"x": 1}, "token": "secret-value"}],
        ),
        adapter_id="fake.integration.adapter",
    )

    result = await ingest_sync_profile_run(
        ManualSyncIngestRequest(
            sync_profile_id=profile.sync_profile_id,
            requested_by="tester",
            params_override={"limit": 2},
            dry_run=False,
            preview_only=True,
            confirmed=True,
            create_analysis_cases=True,
            run_initial_analysis=True,
        ),
        adapter_registry=registry,
    )

    assert result.status == "ingested"
    assert result.dry_run is True
    assert result.preview_only is False
    assert result.confirmed is True
    assert result.fetched_count == result.mapped_count == result.ingested_count == result.created_alerts == 1
    assert result.created_analysis_cases == 0
    assert result.request_summary["params"]["limit"] == 2
    assert result.dispatch_summary["preview_only"] is False
    assert result.dispatch_summary["create_analysis_cases"] is False
    assert result.dispatch_summary["run_initial_analysis"] is False
    exported = json.dumps(result.model_dump(mode="json")).lower()
    assert "raw_payload" not in exported
    assert "secret-value" not in exported
    assert "token" not in exported

    run_response = await client.get(f"/api/security/integrations/runs/{result.run_id}")
    run = run_response.json()
    assert run["status"] == "ingested"
    assert run["run_type"] == "sync_profile_ingest"
    assert run["item_refs"] == [{"id": "a1"}]
    assert run["result_summary"]["created_alerts"] == 1
    assert run["result_summary"]["created_analysis_cases"] == 0

    unchanged = await default_sync_profile_store.get_profile(profile.sync_profile_id)
    assert unchanged.cursor == {"page": "old"}
    assert unchanged.last_run_id is None


@pytest.mark.asyncio
async def test_api_post_ingest_success_forces_safety_flags(client: AsyncClient) -> None:
    _, profile = await seed_fake_profile(sync_profile_id="syncprof_api")
    response = await client.post(
        "/api/security/integrations/sync-engine/ingest",
        json={"sync_profile_id": profile.sync_profile_id, "params_override": {"limit": 3}, "confirmed": True, "dry_run": False, "preview_only": True, "create_analysis_cases": True, "run_initial_analysis": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ingested"
    assert body["dry_run"] is True
    assert body["preview_only"] is False
    assert body["confirmed"] is True
    assert body["created_analysis_cases"] == 0
    assert body["request_summary"]["params"]["limit"] == 3


@pytest.mark.asyncio
async def test_confirmed_missing_or_false_rejected(client: AsyncClient) -> None:
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run

    _, profile = await seed_fake_profile(sync_profile_id="syncprof_confirm")
    result = await ingest_sync_profile_run(ManualSyncIngestRequest(sync_profile_id=profile.sync_profile_id))
    assert result.status == "confirmation_required"
    for payload in [{"sync_profile_id": profile.sync_profile_id}, {"sync_profile_id": profile.sync_profile_id, "confirmed": False}]:
        response = await client.post("/api/security/integrations/sync-engine/ingest", json=payload)
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_unknown_missing_instance_missing_adapter_and_unsupported_capability(client: AsyncClient) -> None:
    response = await client.post("/api/security/integrations/sync-engine/ingest", json={"sync_profile_id": "missing", "confirmed": True})
    assert response.status_code == 404

    from flocks.security.integrations.sync_profiles import SyncProfile

    await Storage.set(
        "security/sync_profiles/syncprof_orphan",
        SyncProfile(sync_profile_id="syncprof_orphan", display_name="Orphan", instance_id="missing", package_id="fake.integration", capability="alert.search"),
        "security.sync_profiles",
    )
    response = await client.post("/api/security/integrations/sync-engine/ingest", json={"sync_profile_id": "syncprof_orphan", "confirmed": True})
    assert response.status_code == 400

    _, profile = await seed_fake_profile(sync_profile_id="syncprof_no_adapter", capability="missing.search")
    response = await client.post("/api/security/integrations/sync-engine/ingest", json={"sync_profile_id": profile.sync_profile_id, "confirmed": True})
    assert response.status_code == 400

    _, unsupported = await seed_fake_profile(sync_profile_id="syncprof_unsupported", capability="unsupported.search")
    response = await client.post("/api/security/integrations/sync-engine/ingest", json={"sync_profile_id": unsupported.sync_profile_id, "confirmed": True})
    assert response.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [{"api_key": "x"}, {"query": "Bearer abcdef"}, {"credential_value": "x"}])
async def test_params_override_secret_like_key_or_value_returns_400(client: AsyncClient, override: dict[str, object]) -> None:
    _, profile = await seed_fake_profile(sync_profile_id="syncprof_secret")
    response = await client.post(
        "/api/security/integrations/sync-engine/ingest",
        json={"sync_profile_id": profile.sync_profile_id, "confirmed": True, "params_override": override},
    )
    assert response.status_code == 400
    assert "abcdef" not in response.text


@pytest.mark.asyncio
async def test_dispatch_flags_and_no_forbidden_side_effects(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from flocks.security.integrations.adapter import FakeIntegrationAdapter
    from flocks.security.integrations.adapter_registry import AdapterRegistry
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr("flocks.security.integrations.credential_store.resolve_credential_profile_ref", forbidden)
    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", forbidden)

    captured = {}

    async def fake_dispatch(request, **_kwargs):
        captured["preview_only"] = request.preview_only
        captured["create_analysis_cases"] = request.create_analysis_cases
        captured["run_initial_analysis"] = request.run_initial_analysis
        captured["events"] = request.events
        from flocks.security.integrations.evidence_dispatcher import EvidenceDispatchResult
        return EvidenceDispatchResult(item_count=len(request.events), preview_only=request.preview_only, created_alerts=len(request.events), created_analysis_cases=0)

    monkeypatch.setattr("flocks.security.integrations.sync_ingest.dispatch_evidence_events", fake_dispatch)
    _, profile = await seed_fake_profile(sync_profile_id="syncprof_safe")
    registry = AdapterRegistry()
    registry.register_adapter_factory(
        "fake.integration",
        "alert.search",
        lambda: FakeIntegrationAdapter("fake.integration", {"alert.search"}, fake_items=[{"id": "a1", "title": "Safe", "severity": "low", "raw_response": {"x": 1}, "password": "hidden", "note": "ok"}]),
    )
    result = await ingest_sync_profile_run(ManualSyncIngestRequest(sync_profile_id=profile.sync_profile_id, confirmed=True), adapter_registry=registry)
    assert result.status == "ingested"
    assert captured["preview_only"] is False
    assert captured["create_analysis_cases"] is False
    assert captured["run_initial_analysis"] is False
    exported_events = json.dumps(captured["events"]).lower()
    assert "raw_response" not in exported_events
    assert "password" not in exported_events
    assert "hidden" not in exported_events
    assert result.safety_summary["credentials_read"] is False
    assert result.safety_summary["secret_ref_resolved"] is False
    assert result.safety_summary["cursor_updated"] is False
    assert result.safety_summary["last_run_id_updated"] is False


def test_init_exports_preserved() -> None:
    import flocks.security.integrations as integrations

    for name in [
        "IntegrationAdapterRequest", "AdapterRegistry", "SyncEnginePlanRequest", "IntegrationRun",
        "SyncProfile", "IntegrationInstance", "CredentialProfile", "MappingRule", "EvidenceDispatchRequest",
        "IntegrationCapabilityRuntime", "ManualSyncPreviewRequest", "ManualSyncPreviewResult", "preview_sync_profile_run",
        "ManualSyncIngestRequest", "ManualSyncIngestResult", "ingest_sync_profile_run",
    ]:
        assert hasattr(integrations, name)
