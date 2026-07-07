import json
from pathlib import Path
import shutil
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.connectors.package_loader import BUILTIN_CONNECTOR_PACKAGE_ROOT
from flocks.security.connectors.registry import connector_registry
from flocks.security.connectors.replay import FIXTURE_ROOT
from flocks.storage.storage import Storage


def _zip_package_bytes(package_root: Path, *, top_level: str | None = None) -> bytes:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package_root.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(package_root)
            archive_name = Path(top_level or package_root.name) / rel
            archive.write(path, archive_name.as_posix())
    return buffer.getvalue()


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.security import secrets as secrets_module

    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    Storage._db_path = None
    Storage._initialized = False
    import flocks.tool.device.models  # noqa: F401 - registers device DDL for this route-only test app

    connector_registry.reset_for_tests(
        package_roots=[BUILTIN_CONNECTOR_PACKAGE_ROOT],
        installed_registry_path=tmp_path / "installed-packages.json",
    )
    await connector_registry.install_package(FIXTURE_ROOT, enabled=True)
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
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"User-Agent": "pytest"},
    ) as ac:
        yield ac

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests()


@pytest.mark.asyncio
async def test_security_routes_sample_load_triage_and_report(client: AsyncClient):
    health = await client.get("/api/security/health")
    assert health.status_code == 200
    assert health.json()["counts"]["connectors"] >= 1

    connectors = await client.get("/api/security/connectors")
    assert connectors.status_code == 200
    connector_ids = [item["id"] for item in connectors.json()]
    assert "mock-security-demo" in connector_ids
    assert "fixture-replay-demo" in connector_ids
    connector_id = "mock-security-demo"

    package_diagnostics = await client.get("/api/security/connectors/package-diagnostics")
    assert package_diagnostics.status_code == 200
    assert package_diagnostics.json()["summary"]["active_packages"] >= 1
    assert "staging_packages" in package_diagnostics.json()
    assert package_diagnostics.json()["packages"][0]["adapters"]["asset.search"]["status"] == "ok"

    customer_summary = await client.get("/api/security/connectors/customer-summary")
    assert customer_summary.status_code == 200
    customer_body = customer_summary.json()
    assert customer_body["version"] == "connector.customer.summary.v1"
    assert "data_sources" in customer_body
    assert "recent_events" in customer_body
    assert "trend" in customer_body
    assert "packages" not in customer_body
    assert "sync_dead_letters" not in json.dumps(customer_body)
    assert "bulk" not in json.dumps(customer_body)
    assert "registry" not in json.dumps(customer_body)
    assert any(item["id"] == "fixture-replay-demo" for item in customer_body["data_sources"])

    tdp_package_root = BUILTIN_CONNECTOR_PACKAGE_ROOT / "tdp-v3-3-10"
    await connector_registry.install_package(tdp_package_root, enabled=True)
    from flocks.tool.device.models import DEFAULT_GROUP_ID
    from flocks.tool.device.store import insert_device

    await insert_device(
        device_id="dev-tdp-1",
        group_id=DEFAULT_GROUP_ID,
        name="TDP device",
        storage_key="tdp_api_v3_3_10",
        service_id="tdp",
        enabled=True,
        verify_ssl=False,
        db_fields={"base_url": "https://192.168.31.182:443"},
    )
    device_sync = await client.post(
        "/api/security/connectors/tdp-v3-3-10/customer-device-sync",
        json={"device_id": "dev-tdp-1", "enabled": True, "capabilities": ["asset.search", "alert.search"]},
    )
    assert device_sync.status_code == 200, device_sync.text
    device_sync_body = device_sync.json()
    assert device_sync_body["device_id"] == "dev-tdp-1"
    assert device_sync_body["profile_id"] == "device_dev_tdp_1"
    assert device_sync_body["capabilities"] == ["asset.search", "alert.search"]
    assert len(device_sync_body["schedules"]) == 2
    assert all(item["credential_profile_id"] == "device_dev_tdp_1" for item in device_sync_body["schedules"])

    connector = await client.get(f"/api/security/connectors/{connector_id}")
    assert connector.status_code == 200
    assert connector.json()["raw_response"]["assets"]

    capabilities = await client.get(f"/api/security/connectors/{connector_id}/capabilities")
    assert capabilities.status_code == 200
    assert "asset.search" in capabilities.json()["capabilities"]

    connector_test = await client.post(f"/api/security/connectors/{connector_id}/test")
    assert connector_test.status_code == 200
    assert connector_test.json()["normalized_data"]

    replay_connector_id = "fixture-replay-demo"
    validation = await client.post(f"/api/security/connectors/{replay_connector_id}/validate")
    assert validation.status_code == 200
    assert validation.json()["adapter_contracts"]["asset.search"]["version"] == "connector.adapter.v1"

    preview = await client.post(
        f"/api/security/connectors/{replay_connector_id}/preview",
        params={"capability": "asset.search"},
    )
    assert preview.status_code == 200
    assert preview.json()["normalized_data"]["assets"][0]["name"] == "Replay Internet Portal"
    assert "items[1].ip" in preview.json()["missing_fields"]
    assert preview.json()["mapping_result"] == preview.json()["normalized_data"]
    assert preview.json()["adapter_contract"]["transport"] == "fixture"
    assert "items[1].ip" in preview.json()["missing_required_fields"]
    assert "unmapped_fields" in preview.json()

    credentials = await client.put(
        f"/api/security/connectors/{replay_connector_id}/credentials",
        json={"values": {"TENANT_ID": "tenant-a", "VENDOR_TOKEN": "secret-token"}, "secret_keys": ["VENDOR_TOKEN"]},
    )
    assert credentials.status_code == 200
    assert credentials.json()["active_profile_id"] == "default"
    assert credentials.json()["profile_count"] == 1
    assert credentials.json()["env"]["TENANT_ID"]["kind"] == "value"
    assert credentials.json()["env"]["VENDOR_TOKEN"]["kind"] == "secret"
    assert "secret-token" not in json.dumps(credentials.json())

    profile_credentials = await client.put(
        f"/api/security/connectors/{replay_connector_id}/credentials",
        json={
            "profile_id": "tenant-b",
            "profile_name": "Tenant B",
            "values": {"TENANT_ID": "tenant-b", "VENDOR_TOKEN": "secret-token-b"},
            "secret_keys": ["VENDOR_TOKEN"],
        },
    )
    assert profile_credentials.status_code == 200
    assert profile_credentials.json()["active_profile_id"] == "tenant_b"
    assert profile_credentials.json()["profile_count"] == 2
    assert profile_credentials.json()["active_profile"]["env"]["VENDOR_TOKEN"]["kind"] == "secret"
    assert "secret-token-b" not in json.dumps(profile_credentials.json())

    profile_test = await client.post(
        f"/api/security/connectors/{replay_connector_id}/credentials/profiles/tenant-b/test",
    )
    assert profile_test.status_code == 200
    assert profile_test.json()["connector_id"] == replay_connector_id

    rotated_profile = await client.post(
        f"/api/security/connectors/{replay_connector_id}/credentials/profiles/tenant-b/rotate",
        json={
            "values": {"TENANT_ID": "tenant-b", "VENDOR_TOKEN": "rotated-secret-token-b"},
            "secret_keys": ["VENDOR_TOKEN"],
        },
    )
    assert rotated_profile.status_code == 200
    rotated_profile_body = rotated_profile.json()
    assert rotated_profile_body["active_profile_id"] == "tenant_b"
    assert next(profile for profile in rotated_profile_body["profiles"] if profile["id"] == "tenant_b")["rotation_count"] == 1
    assert "rotated-secret-token-b" not in json.dumps(rotated_profile_body)

    activated_profile = await client.post(
        f"/api/security/connectors/{replay_connector_id}/credentials/profiles/default/activate",
    )
    assert activated_profile.status_code == 200
    assert activated_profile.json()["active_profile_id"] == "default"

    credential_list = await client.get("/api/security/connectors/credential-bindings")
    assert credential_list.status_code == 200
    assert credential_list.json()["items"][0]["connector_id"] == replay_connector_id

    expiring_profile = await client.put(
        f"/api/security/connectors/{replay_connector_id}/credentials",
        json={
            "profile_id": "tenant-expiring",
            "values": {"TENANT_ID": "tenant-expiring", "VENDOR_TOKEN": "expiring-token"},
            "expires_at": (datetime.now(UTC) + timedelta(days=5)).isoformat(),
            "make_active": False,
        },
    )
    assert expiring_profile.status_code == 200

    expiry_monitor = await client.post(
        "/api/security/connectors/credentials/expiry-monitor",
        json={"days": 14, "notify": True},
    )
    assert expiry_monitor.status_code == 200
    assert expiry_monitor.json()["expiring_soon"] >= 1

    operation_events = await client.get(
        "/api/security/connectors/operations/events",
        params={"kind": "credential_expiring_soon", "status": "open"},
    )
    assert operation_events.status_code == 200
    event = operation_events.json()["items"][0]
    assert event["profile_id"] == "tenant_expiring"

    acknowledged_event = await client.post(f"/api/security/connectors/operations/events/{event['id']}/ack")
    assert acknowledged_event.status_code == 200
    assert acknowledged_event.json()["status"] == "acknowledged"

    bulk_notify = await client.post(
        "/api/security/connectors/credentials/bulk-remediation",
        json={
            "action": "notify",
            "items": [{"connector_id": replay_connector_id, "profile_id": "tenant-expiring"}],
        },
    )
    assert bulk_notify.status_code == 200
    assert bulk_notify.json()["succeeded"] == 1

    deleted_expiring_profile = await client.delete(
        f"/api/security/connectors/{replay_connector_id}/credentials/profiles/tenant-expiring",
    )
    assert deleted_expiring_profile.status_code == 200

    sync = await client.post(
        f"/api/security/connectors/{replay_connector_id}/sync",
        json={"capability": "asset.search", "mode": "full", "credential_profile_id": "tenant-b"},
    )
    assert sync.status_code == 200
    assert sync.json()["status"] == "partial"
    assert sync.json()["credential_profile_id"] == "tenant-b"
    assert sync.json()["counts"]["assets"] == 1
    assert sync.json()["input_counts"]["assets"] == 2
    assert sync.json()["trigger"] == "manual"
    assert sync.json()["package"]["id"] == replay_connector_id
    assert sync.json()["package"]["hash"].startswith("sha256:")
    assert sync.json()["evidence_impact"]["targets"]["assets"]["written"] == 1
    assert sync.json()["quality"]["invalid"] == 1
    assert sync.json()["dead_letter_count"] == 1

    dead_letters = await client.get("/api/security/connectors/sync-dead-letters", params={"connector_id": replay_connector_id})
    assert dead_letters.status_code == 200
    dead_letter = dead_letters.json()["items"][0]
    assert dead_letter["target"] == "assets"
    assert dead_letter["status"] == "invalid"
    assert "items[1].ip" in dead_letter["errors"][0]

    active_runs = await client.get("/api/security/connectors/sync-runs/active", params={"connector_id": replay_connector_id})
    assert active_runs.status_code == 200
    assert active_runs.json()["items"] == []

    cancel_idle = await client.post(
        f"/api/security/connectors/{replay_connector_id}/sync/cancel",
        json={"capability": "asset.search"},
    )
    assert cancel_idle.status_code == 200
    assert cancel_idle.json()["matched"] == 0

    replay = await client.post(
        "/api/security/connectors/sync-dead-letters/replay",
        json={
            "ids": [dead_letter["id"]],
            "payload_updates": {dead_letter["id"]: {"ip": "203.0.113.31"}},
        },
    )
    assert replay.status_code == 200
    assert replay.json()["operation"] == "dead_letter_replay"
    assert replay.json()["status"] == "success"
    assert replay.json()["counts"]["assets"] == 1
    assert replay.json()["replay"]["replayed"] == 1
    assert replay.json()["evidence_impact"]["targets"]["assets"]["written"] == 1

    replayed_dead_letters = await client.get(
        "/api/security/connectors/sync-dead-letters",
        params={"connector_id": replay_connector_id, "status": "replayed"},
    )
    assert replayed_dead_letters.status_code == 200
    assert replayed_dead_letters.json()["items"][0]["id"] == dead_letter["id"]
    assert replayed_dead_letters.json()["items"][0]["replayed_object_id"]

    alert_sync = await client.post(
        f"/api/security/connectors/{replay_connector_id}/sync",
        json={"capability": "alert.search", "mode": "full", "reset_cursor": True},
    )
    assert alert_sync.status_code == 200
    assert alert_sync.json()["status"] == "success"
    assert alert_sync.json()["counts"]["alerts"] == 2
    assert alert_sync.json()["cursor_updated"] is True
    assert alert_sync.json()["cursor_after"] == "2026-06-01T08:20:00Z"

    incremental_sync = await client.post(
        f"/api/security/connectors/{replay_connector_id}/sync",
        json={"capability": "alert.search", "mode": "incremental"},
    )
    assert incremental_sync.status_code == 200
    assert incremental_sync.json()["status"] == "success"
    assert incremental_sync.json()["counts"]["alerts"] == 0
    assert incremental_sync.json()["skipped_counts"]["alerts"] == 2
    assert incremental_sync.json()["cursor_before"] == "2026-06-01T08:20:00Z"

    sync_cursors = await client.get("/api/security/connectors/sync-cursors", params={"connector_id": replay_connector_id})
    assert sync_cursors.status_code == 200
    assert sync_cursors.json()["items"][0]["capability"] == "alert.search"

    reset_cursor = await client.post(
        f"/api/security/connectors/{replay_connector_id}/sync-cursor/reset",
        json={"capability": "alert.search"},
    )
    assert reset_cursor.status_code == 200
    assert reset_cursor.json()["reset"] == 1

    schedule = await client.put(
        f"/api/security/connectors/{replay_connector_id}/sync-schedule",
        json={
            "capability": "alert.search",
            "enabled": True,
            "interval_seconds": 60,
            "mode": "incremental",
            "retry_max_attempts": 2,
            "retry_backoff_seconds": 0,
            "timeout_seconds": 5,
            "credential_profile_id": "default",
        },
    )
    assert schedule.status_code == 200
    schedule_id = schedule.json()["id"]
    assert schedule_id == f"{replay_connector_id}:alert.search"
    assert schedule.json()["runtime_status"] == "enabled"
    assert schedule.json()["credential_profile_id"] == "default"
    assert schedule.json()["next_run_at"]

    schedules = await client.get("/api/security/connectors/sync-schedules", params={"connector_id": replay_connector_id})
    assert schedules.status_code == 200
    assert schedules.json()["items"][0]["id"] == schedule_id

    scheduler_status = await client.get("/api/security/connectors/scheduler/status")
    assert scheduler_status.status_code == 200
    assert "running" in scheduler_status.json()

    schedule_run = await client.post(
        f"/api/security/connectors/sync-schedules/{schedule_id}/run",
        json={"mode": "full"},
    )
    assert schedule_run.status_code == 200
    assert schedule_run.json()["status"] == "success"
    assert schedule_run.json()["run"]["orchestration"]["schedule_id"] == schedule_id
    assert schedule_run.json()["schedule"]["last_status"] == "success"
    assert schedule_run.json()["schedule"]["consecutive_failures"] == 0

    tick = await client.post("/api/security/connectors/scheduler/tick")
    assert tick.status_code == 200
    assert "due" in tick.json()

    disabled_schedule = await client.post(f"/api/security/connectors/sync-schedules/{schedule_id}/disable")
    assert disabled_schedule.status_code == 200
    assert disabled_schedule.json()["enabled"] is False

    enabled_schedule = await client.post(f"/api/security/connectors/sync-schedules/{schedule_id}/enable")
    assert enabled_schedule.status_code == 200
    assert enabled_schedule.json()["enabled"] is True

    deleted_profile = await client.delete(
        f"/api/security/connectors/{replay_connector_id}/credentials/profiles/tenant-b",
    )
    assert deleted_profile.status_code == 200
    assert deleted_profile.json()["profile_count"] == 1
    assert deleted_profile.json()["active_profile_id"] == "default"

    sync_runs = await client.get("/api/security/connectors/sync-runs", params={"connector_id": replay_connector_id})
    assert sync_runs.status_code == 200
    assert sync_runs.json()["items"][0]["capability"] in {"asset.search", "alert.search"}

    synced_assets = await client.get("/api/security/assets", params={"keyword": "Replay Internet Portal"})
    assert synced_assets.status_code == 200
    assert synced_assets.json()[0]["normalized_data"]["connector_sync"]["connector_id"] == replay_connector_id
    assert synced_assets.json()[0]["normalized_data"]["connector_evidence"]["source_object_id"] == "ast_replay_portal"
    synced_asset_id = synced_assets.json()[0]["id"]

    duplicate_asset = await client.post(
        "/api/security/assets",
        json={
            "name": "Replay Internet Portal Clone",
            "asset_type": "web_app",
            "ip": "203.0.113.30",
            "hostname": "replay-portal-shadow",
            "domain": "replay-shadow.example.com",
            "importance": "low",
            "exposure_level": "internal",
            "environment": "production",
        },
    )
    assert duplicate_asset.status_code == 201

    graph_rebuild = await client.post("/api/security/evidence-graph/rebuild")
    assert graph_rebuild.status_code == 200
    graph = graph_rebuild.json()
    assert graph["version"] == "connector.evidence.graph.v1"
    assert graph["summary"]["nodes"] > 0
    assert graph["summary"]["edges"] > 0
    assert graph["summary"]["asset_entities"] >= 1
    assert graph["summary"]["merge_candidates"] >= 1
    assert any(
        {synced_asset_id, duplicate_asset.json()["id"]}.issubset(set(candidate["asset_ids"]))
        for candidate in graph["merge_candidates"]
    )
    assert any(conflict["field"] in {"importance", "exposure_level"} for conflict in graph["conflicts"])

    graph_get = await client.get("/api/security/evidence-graph")
    assert graph_get.status_code == 200
    assert graph_get.json()["summary"]["merge_candidates"] >= 1

    annotated_assets = await client.get("/api/security/assets", params={"keyword": "Replay Internet Portal"})
    assert annotated_assets.status_code == 200
    annotated_asset = next(item for item in annotated_assets.json() if item["id"] == synced_asset_id)
    graph_annotation = annotated_asset["normalized_data"]["evidence_graph"]
    assert graph_annotation["entity_id"]
    assert graph_annotation["edge_ids"]

    diagnostics_after_graph = await client.get("/api/security/connectors/package-diagnostics")
    assert diagnostics_after_graph.status_code == 200
    assert diagnostics_after_graph.json()["summary"]["evidence_graph_nodes"] == graph["summary"]["nodes"]

    loaded = await client.post("/api/security/sample-data/load")
    assert loaded.status_code == 200
    alert_id = loaded.json()["ids"]["alert"]

    assets = await client.get("/api/security/assets", params={"keyword": "portal"})
    assert assets.status_code == 200
    assert any(item["id"] == loaded.json()["ids"]["asset"] for item in assets.json())
    asset_id = loaded.json()["ids"]["asset"]

    profile = await client.get(f"/api/security/assets/{asset_id}/risk-profile")
    assert profile.status_code == 200
    assert profile.json()["risk_score"]["score"] >= 55
    assert profile.json()["normalized_data"]["counts"]["vulnerabilities"] == 1

    priorities = await client.get("/api/security/vulnerabilities/prioritized", params={"asset_id": asset_id})
    assert priorities.status_code == 200
    assert priorities.json()[0]["risk_score"]["score"] >= 80

    triage = await client.post(f"/api/security/triage/alert/{alert_id}")
    assert triage.status_code == 200
    incident_id = triage.json()["incident_id"]
    assert incident_id

    report = await client.post(f"/api/security/reports/incident/{incident_id}")
    assert report.status_code == 200
    assert "安全事件研判报告" in report.json()["content"]

    deleted_schedule = await client.delete(f"/api/security/connectors/sync-schedules/{schedule_id}")
    assert deleted_schedule.status_code == 200
    assert deleted_schedule.json()["deleted_at"]


@pytest.mark.asyncio
async def test_security_connector_package_lifecycle_routes(client: AsyncClient, tmp_path: Path):
    replay_connector_id = "fixture-replay-demo"

    uninstalled = await client.delete(f"/api/security/connectors/packages/{replay_connector_id}")
    assert uninstalled.status_code == 200
    assert uninstalled.json()["uninstalled_at"]

    connectors = await client.get("/api/security/connectors")
    assert replay_connector_id not in [item["id"] for item in connectors.json()]

    installed = await client.post(
        "/api/security/connectors/packages/install",
        json={"package_root": str(FIXTURE_ROOT), "enabled": False},
    )
    assert installed.status_code == 200
    assert installed.json()["enabled"] is False
    assert installed.json()["hash"].startswith("sha256:")

    disabled_preview = await client.post(
        f"/api/security/connectors/{replay_connector_id}/preview",
        params={"capability": "asset.search"},
    )
    assert disabled_preview.status_code == 404

    enabled = await client.post(f"/api/security/connectors/packages/{replay_connector_id}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True

    preview = await client.post(
        f"/api/security/connectors/{replay_connector_id}/preview",
        params={"capability": "asset.search"},
    )
    assert preview.status_code == 200
    assert preview.json()["normalized_data"]["assets"][0]["name"] == "Replay Internet Portal"

    v2_root = tmp_path / "source-v2" / "fixture-replay-demo"
    shutil.copytree(FIXTURE_ROOT, v2_root)
    manifest_path = v2_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["product_version"] = "2026.07"
    manifest["description"] = "Route rollback fixture."
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    installed_v2 = await client.post(
        "/api/security/connectors/packages/install",
        json={"package_root": str(v2_root), "enabled": True},
    )
    assert installed_v2.status_code == 200
    assert installed_v2.json()["version"] == "2026.07"
    assert installed_v2.json()["rollback_available"] is True

    rolled_back = await client.post(f"/api/security/connectors/packages/{replay_connector_id}/rollback")
    assert rolled_back.status_code == 200
    assert rolled_back.json()["version"] == "2026.06"
    assert rolled_back.json()["enabled"] is True

    disabled = await client.post(f"/api/security/connectors/packages/{replay_connector_id}/disable")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    disabled_again = await client.post(
        f"/api/security/connectors/{replay_connector_id}/preview",
        params={"capability": "asset.search"},
    )
    assert disabled_again.status_code == 404


@pytest.mark.asyncio
async def test_security_connector_package_staging_routes(client: AsyncClient):
    replay_connector_id = "fixture-replay-demo"
    await client.delete(f"/api/security/connectors/packages/{replay_connector_id}")

    artifact = _zip_package_bytes(FIXTURE_ROOT)
    uploaded = await client.post(
        "/api/security/connectors/packages/staging/upload",
        files={"file": ("fixture-replay-demo.zip", artifact, "application/zip")},
    )
    assert uploaded.status_code == 200
    staged = uploaded.json()
    assert staged["status"] == "validated"
    assert staged["package_id"] == replay_connector_id
    assert staged["validation_result"]["success"] is True

    staging_list = await client.get("/api/security/connectors/packages/staging")
    assert staging_list.status_code == 200
    assert staging_list.json()["items"][0]["id"] == staged["id"]

    revalidated = await client.post(f"/api/security/connectors/packages/staging/{staged['id']}/validate")
    assert revalidated.status_code == 200
    assert revalidated.json()["status"] == "validated"

    installed = await client.post(
        f"/api/security/connectors/packages/staging/{staged['id']}/install",
        json={"enabled": True},
    )
    assert installed.status_code == 200
    assert installed.json()["id"] == replay_connector_id
    assert installed.json()["enabled"] is True
    assert installed.json()["source"] == "upload"
    assert installed.json()["artifact_hash"] == staged["artifact_hash"]

    connectors = await client.get("/api/security/connectors")
    assert replay_connector_id in [item["id"] for item in connectors.json()]

    discarded = await client.delete(f"/api/security/connectors/packages/staging/{staged['id']}")
    assert discarded.status_code == 200
    assert discarded.json()["discarded_at"]


@pytest.mark.asyncio
async def test_analysis_case_backend_closed_loop(client: AsyncClient):
    payload = {
        "title": "Investigate suspicious login",
        "facts": [
            {
                "fact_type": "alert_signal",
                "statement": "Suspicious login alert fired",
                "source_ref": "alert:manual",
            }
        ],
        "evidence_items": [
            {
                "title": "Raw alert event",
                "description": "Normalized alert payload",
                "source_ref": "alert:manual",
            }
        ],
        "evidence_gaps": [
            {
                "gap_type": "missing_endpoint_telemetry",
                "description": "Endpoint process tree is unavailable",
                "missing_source_type": "edr",
            }
        ],
    }
    created = await client.post("/api/security/analysis-cases", json=payload)
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["id"].startswith("acase_")
    assert not case["id"].startswith("inc_")
    assert case["case_status"] == "new"
    assert case["verdict"] == "insufficient_evidence"
    assert case["severity"] == "medium"
    assert case["confidence"] == "medium"
    assert case["evidence_coverage"] == "ec0_signal"
    assert case["analysis_mode"] == "single_source"
    assert case["notification_decision"] == "no_notify_store_only"
    assert case["incident_decision"] == "continue_monitoring"
    assert case["disposition"] == "open"
    assert case["facts"][0]["id"].startswith("afact_")
    assert case["facts"][0]["created_at"]
    assert case["facts"][0]["confidence"] == "medium"
    assert case["facts"][0]["strength"] == "medium"
    assert case["evidence_items"][0]["id"].startswith("evd_")
    assert case["evidence_items"][0]["created_at"]
    assert case["evidence_gaps"][0]["id"].startswith("egap_")
    assert case["evidence_gaps"][0]["created_at"]

    listed = await client.get("/api/security/analysis-cases")
    assert listed.status_code == 200
    assert any(item["id"] == case["id"] for item in listed.json())

    fetched = await client.get(f"/api/security/analysis-cases/{case['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == case["id"]

    updated = await client.patch(f"/api/security/analysis-cases/{case['id']}", json={"case_status": "analyzing"})
    assert updated.status_code == 200
    assert updated.json()["case_status"] == "analyzing"

    deleted = await client.delete(f"/api/security/analysis-cases/{case['id']}")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


@pytest.mark.asyncio
async def test_analysis_case_filter_matches_primary_asset_id(client: AsyncClient):
    primary_asset_id = "ast_primary_only"
    created = await client.post(
        "/api/security/analysis-cases",
        json={"title": "Primary asset only case", "primary_asset_id": primary_asset_id},
    )
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["primary_asset_id"] == primary_asset_id
    assert case["related_asset_ids"] == []

    filtered = await client.get("/api/security/analysis-cases", params={"asset_id": primary_asset_id})
    assert filtered.status_code == 200
    assert any(item["id"] == case["id"] for item in filtered.json())


@pytest.mark.asyncio
async def test_analysis_case_from_alert_waf_blocked_attack_initial_analysis(client: AsyncClient):
    before = (await client.get("/api/security/incidents")).json()
    alert_response = await client.post("/api/security/alerts", json={
        "asset_id": "ast_waf_blocked",
        "source": "waf",
        "title": "SQL injection attempt blocked",
        "severity": "high",
        "description": "WAF detected SQL injection and action block",
        "raw_event": {"action": "block", "attack": "sqli", "uri": "/login?id=1 union select"},
        "normalized_data": {"action": "block"},
        "occurred_at": "2026-07-06T10:00:00+00:00",
    })
    assert alert_response.status_code == 201, alert_response.text
    alert = alert_response.json()
    response = await client.post(f"/api/security/analysis-cases/from-alert/{alert['id']}")
    assert response.status_code == 201, response.text
    case = response.json()
    fact_types = {fact["fact_type"] for fact in case["facts"]}
    assert {"alert_signal", "attack_pattern_matched", "protection_action_observed"}.issubset(fact_types)
    assert case["verdict"] == "confirmed_attack_attempt_blocked"
    assert case["notification_decision"] == "daily_digest"
    assert case["incident_decision"] == "do_not_escalate"
    assert any(gap["missing_source_type"] in {"edr", "backend_access_log"} for gap in case["evidence_gaps"])
    after = (await client.get("/api/security/incidents")).json()
    assert len(after) == len(before)


@pytest.mark.asyncio
async def test_analysis_case_from_alert_waf_monitor_attack_initial_analysis(client: AsyncClient):
    alert_response = await client.post("/api/security/alerts", json={
        "asset_id": "ast_waf_monitor",
        "source": "waf",
        "title": "RCE attempt monitored",
        "severity": "medium",
        "description": "RCE payload observed with action monitor",
        "raw_event": {"action": "monitor", "attack": "remote code execution"},
        "normalized_data": {"action": "monitor"},
    })
    assert alert_response.status_code == 201, alert_response.text
    alert = alert_response.json()
    response = await client.post(f"/api/security/analysis-cases/from-alert/{alert['id']}")
    assert response.status_code == 201, response.text
    case = response.json()
    assert case["verdict"] == "suspicious_true_positive"
    assert case["notification_decision"] == "confirmation_request"
    assert case["incident_decision"] == "needs_human_confirmation"
    gap_sources = {gap["missing_source_type"] for gap in case["evidence_gaps"]}
    assert {"edr", "backend_access_log"}.issubset(gap_sources)


@pytest.mark.asyncio
async def test_analysis_case_from_alert_edr_suspicious_process_initial_analysis(client: AsyncClient):
    before = (await client.get("/api/security/incidents")).json()
    alert_response = await client.post("/api/security/alerts", json={
        "asset_id": "ast_edr_process",
        "source": "edr",
        "title": "Suspicious Powershell encoded command",
        "severity": "high",
        "description": "web service spawned shell with powershell encoded command",
        "raw_event": {"process_name": "powershell.exe", "command_line": "powershell encoded command"},
    })
    assert alert_response.status_code == 201, alert_response.text
    alert = alert_response.json()
    response = await client.post(f"/api/security/analysis-cases/from-alert/{alert['id']}")
    assert response.status_code == 201, response.text
    case = response.json()
    assert "process_execution_observed" in {fact["fact_type"] for fact in case["facts"]}
    assert case["verdict"] in {"suspicious_true_positive", "confirmed_incident"}
    assert case["severity"] in {"high", "critical"}
    assert case["notification_decision"] == "realtime_notify"
    assert case["incident_decision"] in {"escalate_to_incident", "needs_human_confirmation"}
    after = (await client.get("/api/security/incidents")).json()
    assert len(after) == len(before)


@pytest.mark.asyncio
async def test_analysis_case_from_alert_weak_generic_initial_analysis(client: AsyncClient):
    alert_response = await client.post("/api/security/alerts", json={"source": "siem", "title": "Generic alert", "severity": "low"})
    assert alert_response.status_code == 201, alert_response.text
    alert = alert_response.json()
    response = await client.post(f"/api/security/analysis-cases/from-alert/{alert['id']}")
    assert response.status_code == 201, response.text
    case = response.json()
    assert case["verdict"] == "insufficient_evidence"
    assert len(case["evidence_gaps"]) >= 1
    assert case["incident_decision"] == "continue_monitoring"


@pytest.mark.asyncio
async def test_run_initial_analysis_endpoint_enriches_and_deduplicates(client: AsyncClient):
    alert_response = await client.post("/api/security/alerts", json={
        "asset_id": "ast_run_initial",
        "source": "waf",
        "title": "SQLi allowed",
        "severity": "medium",
        "description": "SQL injection action allow",
        "raw_event": {"action": "allow", "attack": "sql injection"},
    })
    assert alert_response.status_code == 201, alert_response.text
    alert = alert_response.json()
    case_response = await client.post("/api/security/analysis-cases", json={"title": "Manual case", "related_alert_ids": [alert["id"]]})
    assert case_response.status_code == 201, case_response.text
    case = case_response.json()
    first = await client.post(f"/api/security/analysis-cases/{case['id']}/run-initial-analysis")
    assert first.status_code == 200, first.text
    enriched = first.json()
    assert enriched["facts"]
    assert enriched["evidence_gaps"]
    assert enriched["hypotheses"]
    fact_count = len(enriched["facts"])
    gap_count = len(enriched["evidence_gaps"])
    second = await client.post(f"/api/security/analysis-cases/{case['id']}/run-initial-analysis")
    assert second.status_code == 200, second.text
    rerun = second.json()
    assert len(rerun["facts"]) == fact_count
    assert len(rerun["evidence_gaps"]) == gap_count


@pytest.mark.asyncio
async def test_analysis_case_filter_matches_related_asset_id(client: AsyncClient):
    related_asset_id = "ast_related_only"
    created = await client.post(
        "/api/security/analysis-cases",
        json={"title": "Related asset case", "related_asset_ids": [related_asset_id]},
    )
    assert created.status_code == 201, created.text
    case = created.json()

    filtered = await client.get("/api/security/analysis-cases", params={"asset_id": related_asset_id})
    assert filtered.status_code == 200
    assert any(item["id"] == case["id"] for item in filtered.json())


@pytest.mark.asyncio
async def test_analysis_case_escalate_to_incident_creates_and_reuses_incident(client: AsyncClient):
    created = await client.post(
        "/api/security/analysis-cases",
        json={
            "title": "Confirmed lateral movement",
            "severity": "high",
            "confidence": "high",
            "evidence_coverage": "ec3_cross_source",
            "analysis_mode": "cross_source",
            "verdict": "confirmed_incident",
            "primary_asset_id": "ast_primary",
            "related_asset_ids": ["ast_primary", "ast_peer"],
            "related_alert_ids": ["alert-1"],
            "summary": "Multiple correlated detections indicate lateral movement.",
            "recommendations": ["Notify the incident commander", "Collect endpoint process evidence"],
            "facts": [
                {
                    "fact_type": "edr_detection",
                    "statement": "Suspicious remote execution was observed",
                    "source_ref": "edr:event-1",
                    "related_asset_id": "ast_primary",
                    "related_alert_id": "alert-1",
                    "confidence": "high",
                    "strength": "strong",
                    "observed_at": "2026-07-06T10:00:00+00:00",
                }
            ],
            "evidence_items": [
                {
                    "title": "EDR event",
                    "description": "Remote execution telemetry",
                    "source_ref": "edr:event-1",
                }
            ],
            "evidence_gaps": [
                {
                    "gap_type": "missing_network_flow",
                    "description": "East-west network flow details are missing",
                    "missing_source_type": "ndr",
                    "impact": "Limits lateral movement path reconstruction",
                }
            ],
        },
    )
    assert created.status_code == 201, created.text
    case = created.json()

    response = await client.post(f"/api/security/analysis-cases/{case['id']}/escalate-to-incident")
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["created"] is True
    incident = payload["incident"]
    updated_case = payload["case"]
    assert incident["id"].startswith("inc_")
    assert incident["title"] == case["title"]
    assert incident["severity"] == "high"
    assert incident["asset_ids"] == ["ast_primary", "ast_peer"]
    assert incident["alert_ids"] == ["alert-1"]
    assert incident["evidence"]
    assert incident["timeline"]
    assert updated_case["related_incident_id"] == incident["id"]
    assert updated_case["incident_decision"] == "escalate_to_incident"
    assert updated_case["disposition"] == "escalated_to_incident"
    assert updated_case["case_status"] == "escalated"

    fetched_incident = await client.get(f"/api/security/incidents/{incident['id']}")
    assert fetched_incident.status_code == 200

    second = await client.post(f"/api/security/analysis-cases/{case['id']}/escalate-to-incident")
    assert second.status_code == 200, second.text
    second_payload = second.json()
    assert second_payload["created"] is False
    assert second_payload["incident"]["id"] == incident["id"]

    incidents = await client.get("/api/security/incidents", params={"keyword": "Confirmed lateral movement"})
    assert incidents.status_code == 200
    assert [item["id"] for item in incidents.json()].count(incident["id"]) == 1


async def _create_basic_analysis_case(client: AsyncClient) -> dict:
    response = await client.post(
        "/api/security/analysis-cases",
        json={
            "title": "Manual confirmation case",
            "severity": "medium",
            "facts": [{"fact_type": "alert_signal", "statement": "Signal observed", "source_ref": "alert:test"}],
            "evidence_gaps": [{"gap_type": "missing_edr", "description": "Endpoint context is missing"}],
            "recommendations": ["Review manually"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_analysis_case_create_notification_record(client: AsyncClient):
    case = await _create_basic_analysis_case(client)
    before_incidents = (await client.get("/api/security/incidents")).json()
    response = await client.post(
        f"/api/security/analysis-cases/{case['id']}/notifications",
        json={"notification_type": "confirmation_request", "channel": "in_app", "recipients": ["security_team"], "created_by": "user"},
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert len(updated["notification_records"]) == 1
    record = updated["notification_records"][0]
    assert record["id"].startswith("anot_")
    assert record["status"] == "sent"
    assert record["channel"] == "in_app"
    assert record["sent_at"]
    assert updated["last_notified_at"]
    assert (await client.get("/api/security/incidents")).json() == before_incidents


@pytest.mark.asyncio
async def test_analysis_case_confirm_false_positive_updates_case_without_incident(client: AsyncClient):
    case = await _create_basic_analysis_case(client)
    before_incidents = (await client.get("/api/security/incidents")).json()
    response = await client.post(
        f"/api/security/analysis-cases/{case['id']}/confirmations",
        json={"confirmation_type": "confirm_false_positive", "decision": "confirmed", "comment": "Authorized scanner", "reviewer": "analyst-name", "reviewer_role": "security_analyst"},
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["verdict"] == "false_positive_rule_noise"
    assert updated["incident_decision"] == "do_not_escalate"
    assert updated["notification_decision"] == "no_notify_store_only"
    assert updated["disposition"] == "closed_false_positive"
    assert updated["case_status"] == "resolved"
    assert len(updated["confirmation_records"]) == 1
    assert updated["confirmation_records"][0]["id"].startswith("acon_")
    assert updated["confirmation_records"][0]["comment"] == "Authorized scanner"
    assert updated["last_confirmed_at"]
    assert (await client.get("/api/security/incidents")).json() == before_incidents


@pytest.mark.asyncio
async def test_analysis_case_confirmation_decision_variants_do_not_create_incidents(client: AsyncClient):
    cases = [await _create_basic_analysis_case(client) for _ in range(3)]
    before_incidents = (await client.get("/api/security/incidents")).json()

    blocked = await client.post(f"/api/security/analysis-cases/{cases[0]['id']}/confirmations", json={"confirmation_type": "confirm_blocked_attempt", "decision": "confirmed"})
    assert blocked.status_code == 200, blocked.text
    blocked_case = blocked.json()
    assert blocked_case["verdict"] == "confirmed_attack_attempt_blocked"
    assert blocked_case["incident_decision"] == "do_not_escalate"
    assert blocked_case["disposition"] == "closed_blocked_attempt"
    assert blocked_case["case_status"] == "resolved"

    monitoring = await client.post(f"/api/security/analysis-cases/{cases[1]['id']}/confirmations", json={"confirmation_type": "continue_monitoring", "decision": "monitoring"})
    assert monitoring.status_code == 200, monitoring.text
    monitoring_case = monitoring.json()
    assert monitoring_case["incident_decision"] == "continue_monitoring"
    assert monitoring_case["disposition"] == "monitoring"
    assert monitoring_case["case_status"] == "monitoring"

    escalate = await client.post(f"/api/security/analysis-cases/{cases[2]['id']}/confirmations", json={"confirmation_type": "escalate_to_incident", "decision": "escalated"})
    assert escalate.status_code == 200, escalate.text
    escalation_case = escalate.json()
    assert escalation_case["incident_decision"] == "escalate_to_incident"
    assert escalation_case["notification_decision"] == "realtime_notify"
    assert not escalation_case["related_incident_id"]
    assert (await client.get("/api/security/incidents")).json() == before_incidents

    created = await client.post(f"/api/security/analysis-cases/{cases[2]['id']}/escalate-to-incident")
    assert created.status_code == 201, created.text
    assert created.json()["created"] is True


@pytest.mark.asyncio
async def test_analysis_case_ack_notification(client: AsyncClient):
    case = await _create_basic_analysis_case(client)
    created = await client.post(f"/api/security/analysis-cases/{case['id']}/notifications", json={"notification_type": "confirmation_request", "channel": "in_app"})
    assert created.status_code == 200, created.text
    notification_id = created.json()["notification_records"][0]["id"]
    response = await client.post(f"/api/security/analysis-cases/{case['id']}/notifications/{notification_id}/ack", json={"reviewer": "operator", "comment": "ack"})
    assert response.status_code == 200, response.text
    record = response.json()["notification_records"][0]
    assert record["status"] == "acknowledged"
    assert record["acknowledged_at"]


@pytest.mark.asyncio
async def test_analysis_case_confirmation_records_append_without_overwrite(client: AsyncClient):
    case = await _create_basic_analysis_case(client)
    first = await client.post(f"/api/security/analysis-cases/{case['id']}/confirmations", json={"confirmation_type": "continue_monitoring", "decision": "monitoring", "comment": "first"})
    assert first.status_code == 200, first.text
    second = await client.post(f"/api/security/analysis-cases/{case['id']}/confirmations", json={"confirmation_type": "request_more_evidence", "decision": "needs_more_evidence", "comment": "second"})
    assert second.status_code == 200, second.text
    records = second.json()["confirmation_records"]
    assert len(records) == 2
    assert [record["comment"] for record in records] == ["first", "second"]


async def test_analysis_case_brief_and_demo_sample_data_are_idempotent(client: AsyncClient):
    first = await client.post("/api/security/analysis-cases/sample-data/load")
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["total_demo_cases"] >= 8
    assert body["loaded"] >= 8

    second = await client.post("/api/security/analysis-cases/sample-data/load")
    assert second.status_code == 200, second.text
    assert second.json()["loaded"] == 0
    assert second.json()["total_demo_cases"] == body["total_demo_cases"]

    cases_response = await client.get("/api/security/analysis-cases", params={"limit": 500})
    cases = cases_response.json()
    demo_cases = [case for case in cases if case["title"].startswith("[Demo Closure]")]
    assert len(demo_cases) == body["total_demo_cases"]
    assert any(case["notification_records"] for case in demo_cases)
    assert any(case["confirmation_records"] for case in demo_cases)

    waf_blocked = next(case for case in demo_cases if "WAF SQL Injection blocked" in case["title"])
    brief = await client.get(f"/api/security/analysis-cases/{waf_blocked['id']}/brief")
    assert brief.status_code == 200, brief.text
    markdown = brief.json()["markdown"]
    assert "Analysis Case Brief" in markdown
    assert "WAF SQL Injection blocked" in markdown
    assert "confirmed_attack_attempt_blocked" in markdown
    assert "## Key Facts" in markdown
    assert "## Evidence Gaps" in markdown


async def test_analysis_case_closure_smoke_flow(client: AsyncClient):
    loaded = await client.post("/api/security/analysis-cases/sample-data/load")
    assert loaded.status_code == 200, loaded.text
    cases = (await client.get("/api/security/analysis-cases", params={"limit": 500})).json()
    demo_cases = [case for case in cases if case["title"].startswith("[Demo Closure]")]

    suspicious = next(case for case in demo_cases if "WAF RCE monitor allow" in case["title"])
    notification = await client.post(
        f"/api/security/analysis-cases/{suspicious['id']}/notifications",
        json={"notification_type": "confirmation_request", "channel": "in_app", "recipients": ["secops-demo"]},
    )
    assert notification.status_code == 200, notification.text

    confirmation = await client.post(
        f"/api/security/analysis-cases/{suspicious['id']}/confirmations",
        json={"confirmation_type": "request_more_evidence", "decision": "needs_more_evidence", "reviewer": "operator", "comment": "Need backend logs."},
    )
    assert confirmation.status_code == 200, confirmation.text

    candidate = next(case for case in demo_cases if "EDR suspicious PowerShell" in case["title"])
    escalated = await client.post(f"/api/security/analysis-cases/{candidate['id']}/escalate-to-incident")
    assert escalated.status_code in {200, 201}, escalated.text
    incident = escalated.json()["incident"]
    fetched_incident = await client.get(f"/api/security/incidents/{incident['id']}")
    assert fetched_incident.status_code == 200, fetched_incident.text

    refreshed = (await client.get(f"/api/security/analysis-cases/{suspicious['id']}/brief")).json()["markdown"]
    assert "WAF monitored an RCE-like request" in refreshed
    assert "backend_access_log" in refreshed
    assert "request_more_evidence" in refreshed

    report = await client.post(f"/api/security/reports/incident/{incident['id']}")
    assert report.status_code == 200, report.text
    assert "Analysis Case Evidence" in report.json()["content"]
