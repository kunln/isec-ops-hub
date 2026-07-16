"""Runtime v2 PreviewBatch confirmation and safety tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flocks.security.integrations.adapter_registry import AdapterRegistry
from flocks.security.integrations.device_runtime_adapter import DeviceIntegrationRuntimeAdapter
from flocks.security.integrations.instances import IntegrationInstance
from flocks.security.integrations.preview_batch_store import PreviewBatchStore
from flocks.security.integrations.sync_profiles import SyncProfile
from flocks.storage.storage import Storage
from flocks.tool import ToolResult


@pytest.fixture
async def isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.security import secrets as secrets_module

    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None


async def seed_profile(
    *,
    instance_id: str = "intinst_tda",
    sync_profile_id: str = "syncprof_tda",
    device_id: str = "device_tda",
) -> tuple[IntegrationInstance, SyncProfile]:
    instance = IntegrationInstance(
        instance_id=instance_id,
        package_id="asiainfo.tda",
        vendor="AsiaInfo",
        product="TDA",
        display_name="TDA Test",
        credential_profile_id="cred_device_reference",
        enabled=True,
        metadata={
            "source": "device_integration_bridge",
            "device_id": device_id,
            "api_key": "REAL_API_KEY_SHOULD_NOT_LEAK",
            "password": "REAL_PASSWORD_SHOULD_NOT_LEAK",
        },
    )
    # Direct Storage writes emulate already-confirmed bridge/profile records;
    # production creation paths reject secret-like metadata before this point.
    profile = SyncProfile(
        sync_profile_id=sync_profile_id,
        display_name="TDA Alert Sync",
        instance_id=instance_id,
        package_id="asiainfo.tda",
        capability="alert.search",
        cursor={"page": 1, "limit": 2},
        params={"time_type": 2, "limit": 2},
        last_run_id=None,
        last_status="never_run",
        metadata={"device_id": device_id, "bridge_source": "device_integration_bridge"},
    )
    await Storage.set(f"security/integration_instances/{instance_id}", instance, "security.integration_instances")
    await Storage.set(f"security/sync_profiles/{sync_profile_id}", profile, "security.sync_profiles")
    return instance, profile


def device_registry(call_counter: dict[str, int]) -> AdapterRegistry:
    async def get_device(device_id: str):
        return {
            "id": device_id,
            "enabled": True,
            "status": "ok",
            "storage_key": "asiainfo_xinwei_tda_v7_0",
            "service_id": "asiainfo_tda_api",
            "api_key": "REAL_API_KEY_SHOULD_NOT_LEAK",
            "password": "REAL_PASSWORD_SHOULD_NOT_LEAK",
        }

    async def execute_tool(*, device_id: str, params: dict[str, object]):
        del device_id, params
        call_counter["count"] += 1
        return ToolResult(
            success=True,
            output={
                "alarm_list": [
                    {
                        "merge_key": "preview-1",
                        "threat_desc": "TDA C2 alert",
                        "description": "Beacon detected",
                        "severity": "高危",
                        "victim_addr": "10.0.0.11",
                        "attacker_addr": "203.0.113.11",
                        "event_time": "2026-07-14T02:00:00Z",
                        "threat_class": "command_and_control",
                        "token": "REAL_TOKEN_SHOULD_NOT_LEAK",
                        "authorization": "Bearer REAL_AUTH_SHOULD_NOT_LEAK",
                    },
                    {
                        "merge_key": "preview-2",
                        "rule_name": "Exploit attempt",
                        "severity": "中危",
                        "dst": ["10.0.0.12"],
                        "src": ["198.51.100.12"],
                        "raw_data": {"password": "REAL_PASSWORD_SHOULD_NOT_LEAK"},
                    },
                ],
                "total": 2,
                "secret": "REAL_API_KEY_SHOULD_NOT_LEAK",
            },
            metadata={"authorization": "Bearer REAL_AUTH_SHOULD_NOT_LEAK"},
        )

    registry = AdapterRegistry()
    registry.register_adapter_factory(
        "asiainfo.tda",
        "alert.search",
        lambda: DeviceIntegrationRuntimeAdapter(
            device_identity_getter=get_device,
            tool_executor=execute_tool,
        ),
    )
    return registry


@pytest.mark.asyncio
async def test_preview_then_confirm_uses_same_batch_without_second_device_call(isolated_store) -> None:
    from flocks.security.integrations.preview_batch_store import default_preview_batch_store
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run
    from flocks.security.integrations.sync_preview import ManualSyncPreviewRequest, preview_sync_profile_run
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store
    from flocks.security.store import default_store

    _, profile = await seed_profile()
    calls = {"count": 0}
    preview = await preview_sync_profile_run(
        ManualSyncPreviewRequest(sync_profile_id=profile.sync_profile_id),
        adapter_registry=device_registry(calls),
    )

    assert preview.status == "previewed"
    assert preview.item_count == preview.event_count == preview.preview_count == 2
    assert preview.preview_batch_id
    assert calls["count"] == 1
    assert await default_store.list_alerts() == []
    assert await default_store.list_incidents() == []
    assert await default_store.list_analysis_cases() == []

    class ExplodingRegistry:
        def require_adapter(self, *_args, **_kwargs):
            raise AssertionError("Confirm Ingest must not resolve an adapter")

    confirmed = await ingest_sync_profile_run(
        ManualSyncIngestRequest(
            sync_profile_id=profile.sync_profile_id,
            preview_batch_id=preview.preview_batch_id,
            preview_run_id=preview.preview_run_id,
            confirmed=True,
        ),
        adapter_registry=ExplodingRegistry(),
    )

    assert confirmed.status == "ingested"
    assert confirmed.created_alerts == 2
    assert confirmed.created_analysis_cases == 0
    assert calls["count"] == 1
    alerts = await default_store.list_alerts()
    assert {alert.title for alert in alerts} == {"TDA C2 alert", "Exploit attempt"}
    first_alert = next(alert for alert in alerts if alert.title == "TDA C2 alert")
    assert first_alert.asset_id == preview.event_summaries[0]["asset_id"]
    assert first_alert.normalized_data["external_event_id"] == preview.event_summaries[0]["external_event_id"]
    assert await default_store.list_incidents() == []
    assert await default_store.list_analysis_cases() == []

    batch = await default_preview_batch_store.get(preview.preview_batch_id)
    assert batch is not None
    assert batch.consumed_by_run_id == confirmed.run_id
    duplicate = await ingest_sync_profile_run(
        ManualSyncIngestRequest(
            sync_profile_id=profile.sync_profile_id,
            preview_batch_id=preview.preview_batch_id,
            confirmed=True,
        )
    )
    assert duplicate.status == "preview_batch_consumed"
    assert len(await default_store.list_alerts()) == 2

    updated = await default_sync_profile_store.get_profile(profile.sync_profile_id)
    assert updated is not None
    assert updated.cursor == {"page": 2, "limit": 2}
    assert updated.last_run_id == confirmed.run_id
    assert updated.last_status == "ingested"
    assert updated.last_synced_at


@pytest.mark.asyncio
async def test_confirm_without_batch_rejected_and_never_calls_adapter(isolated_store) -> None:
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run
    from flocks.security.store import default_store

    _, profile = await seed_profile(sync_profile_id="syncprof_required")

    class ExplodingRegistry:
        def require_adapter(self, *_args, **_kwargs):
            raise AssertionError("adapter must not be called")

    result = await ingest_sync_profile_run(
        ManualSyncIngestRequest(sync_profile_id=profile.sync_profile_id, confirmed=True),
        adapter_registry=ExplodingRegistry(),
    )
    assert result.status == "preview_batch_required"
    assert await default_store.list_alerts() == []


@pytest.mark.asyncio
async def test_expired_and_mismatched_batches_do_not_update_sync_state(isolated_store) -> None:
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run
    from flocks.security.integrations.sync_preview import ManualSyncPreviewRequest, preview_sync_profile_run
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store
    from flocks.security.store import default_store

    _, profile = await seed_profile(sync_profile_id="syncprof_expiring")
    now = [datetime(2026, 7, 14, 0, 0, tzinfo=UTC)]
    batch_store = PreviewBatchStore(clock=lambda: now[0])
    calls = {"count": 0}
    preview = await preview_sync_profile_run(
        ManualSyncPreviewRequest(sync_profile_id=profile.sync_profile_id),
        adapter_registry=device_registry(calls),
        preview_batch_store=batch_store,
    )
    assert preview.preview_batch_id
    now[0] += timedelta(minutes=31)

    expired = await ingest_sync_profile_run(
        ManualSyncIngestRequest(
            sync_profile_id=profile.sync_profile_id,
            preview_batch_id=preview.preview_batch_id,
            confirmed=True,
        ),
        preview_batch_store=batch_store,
    )
    assert expired.status == "preview_batch_expired"
    unchanged = await default_sync_profile_store.get_profile(profile.sync_profile_id)
    assert unchanged is not None
    assert unchanged.cursor == {"page": 1, "limit": 2}
    assert unchanged.last_run_id is None
    assert unchanged.last_synced_at is None
    assert await default_store.list_alerts() == []

    # A fresh batch cannot be confirmed against another Sync Profile.
    now[0] = datetime(2026, 7, 14, 1, 0, tzinfo=UTC)
    fresh = await preview_sync_profile_run(
        ManualSyncPreviewRequest(sync_profile_id=profile.sync_profile_id),
        adapter_registry=device_registry(calls),
        preview_batch_store=batch_store,
    )
    _, other = await seed_profile(
        instance_id="intinst_other",
        sync_profile_id="syncprof_other",
        device_id="device_other",
    )
    mismatch = await ingest_sync_profile_run(
        ManualSyncIngestRequest(
            sync_profile_id=other.sync_profile_id,
            preview_batch_id=fresh.preview_batch_id,
            confirmed=True,
        ),
        preview_batch_store=batch_store,
    )
    assert mismatch.status == "preview_batch_mismatch"
    other_unchanged = await default_sync_profile_store.get_profile(other.sync_profile_id)
    assert other_unchanged is not None
    assert other_unchanged.last_run_id is None


@pytest.mark.asyncio
async def test_end_to_end_plan_preview_ingest_runs_and_safety(isolated_store) -> None:
    from flocks.security.integrations.device_bridge import DeviceBridgeRequest, default_device_integration_bridge
    from flocks.security.integrations.device_sync_profile import (
        DeviceSyncProfileConfirmRequest,
        default_device_sync_profile_service,
    )
    from flocks.security.integrations.run_store import default_integration_run_store
    from flocks.security.integrations.sync_engine import SyncEnginePlanRequest, plan_sync_profile_run
    from flocks.security.integrations.sync_ingest import ManualSyncIngestRequest, ingest_sync_profile_run
    from flocks.security.integrations.sync_preview import ManualSyncPreviewRequest, preview_sync_profile_run
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store
    from flocks.security.store import default_store
    from flocks.tool.device.models import DEFAULT_GROUP_ID
    from flocks.tool.device.store import insert_device

    await insert_device(
        device_id="device_e2e",
        group_id=DEFAULT_GROUP_ID,
        name="TDA End-to-End",
        storage_key="asiainfo_tda_api_v7_0",
        service_id="asiainfo_tda_api",
        enabled=True,
        verify_ssl=False,
        db_fields={
            "base_url": "https://tda.example.test",
            "api_key": "REAL_API_KEY_SHOULD_NOT_LEAK",
            "password": "REAL_PASSWORD_SHOULD_NOT_LEAK",
        },
        status="ok",
    )
    bridge = await default_device_integration_bridge.bridge_device_integration(
        DeviceBridgeRequest(device_id="device_e2e", dry_run=False)
    )
    assert bridge.status == "bridged"
    profile_result = await default_device_sync_profile_service.confirm(
        DeviceSyncProfileConfirmRequest(
            device_id="device_e2e",
            capability="alert.search",
            confirmed=True,
            params={"time_type": 2, "limit": 2},
        )
    )
    assert profile_result.status == "created"
    profile = await default_sync_profile_store.get_profile(str(profile_result.sync_profile_id))
    assert profile is not None
    plan = await plan_sync_profile_run(SyncEnginePlanRequest(sync_profile_id=profile.sync_profile_id))
    assert plan.status == "planned"
    calls = {"count": 0}
    preview = await preview_sync_profile_run(
        ManualSyncPreviewRequest(sync_profile_id=profile.sync_profile_id),
        adapter_registry=device_registry(calls),
    )
    confirm = await ingest_sync_profile_run(
        ManualSyncIngestRequest(
            sync_profile_id=profile.sync_profile_id,
            preview_batch_id=preview.preview_batch_id,
            confirmed=True,
        )
    )
    assert confirm.status == "ingested"

    runs = await default_integration_run_store.list_runs(sync_profile_id=profile.sync_profile_id)
    assert {run.run_type for run in runs} >= {
        "sync_profile_plan",
        "sync_profile_preview",
        "sync_profile_ingest",
    }
    assert await default_store.list_incidents() == []
    assert await default_store.list_analysis_cases() == []

    exported = json.dumps(
        {
            "preview": preview.model_dump(mode="json"),
            "confirm": confirm.model_dump(mode="json"),
            "runs": [run.model_dump(mode="json") for run in runs],
            "alerts": [alert.model_dump(mode="json") for alert in await default_store.list_alerts()],
        },
        ensure_ascii=False,
    )
    for secret in (
        "REAL_TOKEN_SHOULD_NOT_LEAK",
        "REAL_API_KEY_SHOULD_NOT_LEAK",
        "REAL_PASSWORD_SHOULD_NOT_LEAK",
        "Bearer REAL_AUTH_SHOULD_NOT_LEAK",
    ):
        assert secret not in exported
