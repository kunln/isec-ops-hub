from pathlib import Path

import pytest

from flocks.security.asset_identity import build_asset_identity, compare_asset_identity
from flocks.security.connectors.models import ConnectorCapability, ConnectorPreviewResult
from flocks.security.connectors.sync_runtime import sync_connector_preview_result
from flocks.security.evidence_graph import rebuild_evidence_graph
from flocks.security.schemas import SecurityListFilters
from flocks.security.store import SecurityStore
from flocks.storage.storage import Storage


@pytest.fixture
async def security_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config

    Config._global_config = None
    Config._cached_config = None
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield SecurityStore()
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None


def test_asset_identity_prefers_strong_identity_over_ip_changes():
    left = build_asset_identity(
        {
            "name": "PC-A",
            "ip": "192.168.1.10",
            "endpoint_uuid": "endpoint-abc",
            "first_seen": "2026-06-08T09:00:00+08:00",
            "last_seen": "2026-06-08T10:00:00+08:00",
            "allocation_mode": "dhcp",
        }
    )
    right = build_asset_identity(
        {
            "name": "PC-A",
            "ip": "192.168.1.55",
            "endpoint_uuid": "endpoint-abc",
            "first_seen": "2026-06-08T15:00:00+08:00",
            "last_seen": "2026-06-08T16:00:00+08:00",
            "allocation_mode": "dhcp",
        }
    )

    comparison = compare_asset_identity(left, right)

    assert comparison["auto_merge"] is True
    assert "strong_identity_match" in comparison["reasons"]


def test_dhcp_single_ip_without_overlap_is_not_a_merge_candidate():
    left = build_asset_identity(
        {
            "name": "PC-A",
            "ip": "192.168.1.10",
            "network_scope": "office_lan",
            "allocation_mode": "dhcp",
            "first_seen": "2026-06-08T09:00:00+08:00",
            "last_seen": "2026-06-08T10:00:00+08:00",
        }
    )
    right = build_asset_identity(
        {
            "name": "PC-B",
            "ip": "192.168.1.10",
            "network_scope": "office_lan",
            "allocation_mode": "dhcp",
            "first_seen": "2026-06-08T15:00:00+08:00",
            "last_seen": "2026-06-08T16:00:00+08:00",
        }
    )

    comparison = compare_asset_identity(left, right)

    assert comparison["auto_merge"] is False
    assert comparison["candidate"] is False
    assert "time_window_not_overlapping" in comparison["reasons"]


def test_ip_auxiliary_identity_and_time_overlap_auto_merges():
    left = build_asset_identity(
        {
            "hostname": "PC-A",
            "ip": "192.168.1.10",
            "network_scope": "office_lan",
            "allocation_mode": "dhcp",
            "first_seen": "2026-06-08T09:00:00+08:00",
            "last_seen": "2026-06-08T10:00:00+08:00",
        }
    )
    right = build_asset_identity(
        {
            "hostname": "PC-A",
            "ip": "192.168.1.10",
            "network_scope": "office_lan",
            "allocation_mode": "dhcp",
            "first_seen": "2026-06-08T09:30:00+08:00",
            "last_seen": "2026-06-08T11:00:00+08:00",
        }
    )

    comparison = compare_asset_identity(left, right)

    assert comparison["auto_merge"] is True
    assert comparison["score"] >= 80
    assert "auxiliary_identity_match" in comparison["reasons"]


@pytest.mark.asyncio
async def test_evidence_graph_keeps_reused_dhcp_ip_as_separate_assets(security_store: SecurityStore, tmp_path: Path):
    await security_store.upsert_asset(
        {
            "id": "asset-office-a",
            "name": "PC-A",
            "ip": "192.168.1.10",
            "asset_type": "endpoint",
            "normalized_data": {
                "asset_identity": build_asset_identity(
                    {
                        "name": "PC-A",
                        "ip": "192.168.1.10",
                        "network_scope": "office_lan",
                        "allocation_mode": "dhcp",
                        "first_seen": "2026-06-08T09:00:00+08:00",
                        "last_seen": "2026-06-08T10:00:00+08:00",
                    }
                )
            },
        }
    )
    await security_store.upsert_asset(
        {
            "id": "asset-office-b",
            "name": "PC-B",
            "ip": "192.168.1.10",
            "asset_type": "endpoint",
            "normalized_data": {
                "asset_identity": build_asset_identity(
                    {
                        "name": "PC-B",
                        "ip": "192.168.1.10",
                        "network_scope": "office_lan",
                        "allocation_mode": "dhcp",
                        "first_seen": "2026-06-08T15:00:00+08:00",
                        "last_seen": "2026-06-08T16:00:00+08:00",
                    }
                )
            },
        }
    )

    graph = await rebuild_evidence_graph(store=security_store, path=tmp_path / "graph.json", annotate_store=False)

    entity_by_asset = graph["indexes"]["asset_entity_by_asset_id"]
    assert entity_by_asset["asset-office-a"] != entity_by_asset["asset-office-b"]
    assert not any(
        {"asset-office-a", "asset-office-b"}.issubset(set(candidate["asset_ids"]))
        for candidate in graph["merge_candidates"]
    )


@pytest.mark.asyncio
async def test_connector_asset_sync_scopes_source_identity_by_profile(security_store: SecurityStore, tmp_path: Path):
    preview = ConnectorPreviewResult(
        connector_id="demo-connector",
        capability=ConnectorCapability.ASSET_SEARCH,
        success=True,
        source="fixture:assets",
        mapping_result={
            "assets": [
                {
                    "id": "vendor-local-asset-1",
                    "name": "Shared Vendor Local ID",
                    "ip": "10.0.0.5",
                    "hostname": "host-a",
                    "asset_type": "endpoint",
                    "raw_data": {"connector_id": "demo-connector", "response": {"id": "vendor-local-asset-1"}},
                    "normalized_data": {"id": "vendor-local-asset-1", "name": "Shared Vendor Local ID"},
                }
            ]
        },
    )

    await sync_connector_preview_result(
        preview,
        credential_profile_id="device-a",
        store=security_store,
        path=tmp_path / "runs.json",
        evidence_graph_path=tmp_path / "graph.json",
    )
    await sync_connector_preview_result(
        preview,
        credential_profile_id="device-b",
        store=security_store,
        path=tmp_path / "runs.json",
        evidence_graph_path=tmp_path / "graph.json",
    )

    assets = await security_store.list_assets(SecurityListFilters(limit=10))

    assert len(assets) == 2
    assert {asset.normalized_data["connector_evidence"]["credential_profile_id"] for asset in assets} == {
        "device-a",
        "device-b",
    }
    assert {asset.normalized_data["connector_evidence"]["source_object_id"] for asset in assets} == {
        "vendor-local-asset-1"
    }
