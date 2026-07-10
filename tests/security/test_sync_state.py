"""Tests for controlled Sync Profile run-state updates."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from flocks.storage.storage import Storage


@pytest.fixture(autouse=True)
async def storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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


async def seed_profile(sync_profile_id: str = "syncprof_state"):
    from flocks.security.integrations.instances import IntegrationInstance
    from flocks.security.integrations.sync_profiles import SyncProfile

    await Storage.set(
        "security/integration_instances/intinst_state",
        IntegrationInstance(instance_id="intinst_state", package_id="fake.integration", display_name="Fake"),
        "security.integration_instances",
    )
    profile = SyncProfile(
        sync_profile_id=sync_profile_id,
        display_name="State",
        instance_id="intinst_state",
        package_id="fake.integration",
        capability="alert.search",
        cursor={"page": "old"},
    )
    await Storage.set(f"security/sync_profiles/{sync_profile_id}", profile, "security.sync_profiles")
    return profile


@pytest.mark.asyncio
async def test_update_sync_profile_run_state_updates_run_status_and_synced_at() -> None:
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store
    from flocks.security.integrations.sync_state import SyncStateUpdateRequest, update_sync_profile_run_state

    profile = await seed_profile()
    result = await update_sync_profile_run_state(
        SyncStateUpdateRequest(sync_profile_id=profile.sync_profile_id, run_id="run_1", status="ingested", synced_at="2026-07-10T00:00:00Z")
    )
    updated = await default_sync_profile_store.get_profile(profile.sync_profile_id)

    assert result.last_run_updated is True
    assert result.last_status_updated is True
    assert result.last_synced_at_updated is True
    assert updated.last_run_id == "run_1"
    assert updated.last_status == "ingested"
    assert updated.last_synced_at == "2026-07-10T00:00:00Z"


@pytest.mark.asyncio
async def test_update_cursor_false_keeps_existing_cursor() -> None:
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store
    from flocks.security.integrations.sync_state import SyncStateUpdateRequest, update_sync_profile_run_state

    profile = await seed_profile("syncprof_no_cursor")
    result = await update_sync_profile_run_state(
        SyncStateUpdateRequest(sync_profile_id=profile.sync_profile_id, run_id="run_2", status="ingested", cursor={"page": "new"}, update_cursor=False)
    )
    updated = await default_sync_profile_store.get_profile(profile.sync_profile_id)
    assert result.cursor_updated is False
    assert updated.cursor == {"page": "old"}


@pytest.mark.asyncio
async def test_update_cursor_true_saves_safe_cursor_without_raw_or_secret_data() -> None:
    from flocks.security.integrations.sync_profile_store import default_sync_profile_store
    from flocks.security.integrations.sync_state import SyncStateUpdateRequest, update_sync_profile_run_state

    profile = await seed_profile("syncprof_cursor")
    result = await update_sync_profile_run_state(
        SyncStateUpdateRequest(
            sync_profile_id=profile.sync_profile_id,
            run_id="run_3",
            status="ingested",
            cursor={"page": "new", "raw_response": {"x": 1}, "token": "secret", "note": "Bearer abc", "nested": {"payload": "raw", "offset": 2}},
            update_cursor=True,
        )
    )
    updated = await default_sync_profile_store.get_profile(profile.sync_profile_id)
    assert result.cursor_updated is True
    assert updated.cursor == {"page": "new", "note": "[REDACTED]", "nested": {"offset": 2}}


@pytest.mark.asyncio
async def test_unknown_sync_profile_returns_error() -> None:
    from flocks.security.integrations.sync_state import SyncStateUpdateRequest, update_sync_profile_run_state

    result = await update_sync_profile_run_state(SyncStateUpdateRequest(sync_profile_id="missing", run_id="run_missing", status="ingested"))
    assert result.errors == ["Sync profile not found"]


@pytest.mark.asyncio
async def test_sync_state_has_no_connector_http_or_credential_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    from flocks.security.integrations.sync_state import SyncStateUpdateRequest, update_sync_profile_run_state

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr("flocks.security.integrations.credential_store.resolve_credential_profile_ref", forbidden)
    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", forbidden)

    profile = await seed_profile("syncprof_safe_side_effects")
    result = await update_sync_profile_run_state(SyncStateUpdateRequest(sync_profile_id=profile.sync_profile_id, run_id="run_4", status="ingested"))
    assert result.errors == []


def test_init_exports_preserved_with_sync_state() -> None:
    import flocks.security.integrations as integrations

    for name in [
        "IntegrationAdapterRequest", "AdapterRegistry", "SyncEnginePlanRequest", "IntegrationRun",
        "SyncProfile", "IntegrationInstance", "CredentialProfile", "MappingRule", "EvidenceDispatchRequest",
        "IntegrationCapabilityRuntime", "ManualSyncPreviewRequest", "ManualSyncPreviewResult", "preview_sync_profile_run",
        "ManualSyncIngestRequest", "ManualSyncIngestResult", "ingest_sync_profile_run",
        "SyncStateUpdateRequest", "SyncStateUpdateResult", "update_sync_profile_run_state",
    ]:
        assert hasattr(integrations, name)
