from pathlib import Path

import pytest

from flocks.security.schemas import AlertCreate, AnalysisCaseCreate, AssetCreate, SecurityListFilters
from flocks.security.store import SecurityStore
from flocks.storage.storage import Storage


@pytest.fixture
async def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield SecurityStore()
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


@pytest.mark.asyncio
async def test_security_store_asset_crud_and_filters(store: SecurityStore):
    asset = await store.create_asset(
        AssetCreate(
            name="Internet Portal",
            asset_type="web_app",
            ip="203.0.113.10",
            domain="portal.example.com",
            importance="critical",
            exposure_level="external",
            open_ports=[443],
            services=["https"],
            raw_data={"vendor": "demo", "assetId": "portal-1"},
        )
    )

    assert asset.id.startswith("ast_")
    assert asset.created_at
    assert asset.updated_at
    assert asset.raw_data["vendor"] == "demo"
    assert asset.normalized_data["ip"] == "203.0.113.10"
    assert asset.normalized_data["open_ports"] == [443]

    fetched = await store.get_asset(asset.id)
    assert fetched is not None
    assert fetched.name == "Internet Portal"

    updated = await store.update_asset(asset.id, {"business_owner": "Security"})
    assert updated is not None
    assert updated.business_owner == "Security"
    assert updated.updated_at >= updated.created_at

    by_ip = await store.list_assets(SecurityListFilters(ip="203.0.113.10"))
    by_keyword = await store.list_assets(SecurityListFilters(keyword="portal"))
    by_importance = await store.list_assets(SecurityListFilters(importance="critical"))
    assert [item.id for item in by_ip] == [asset.id]
    assert [item.id for item in by_keyword] == [asset.id]
    assert [item.id for item in by_importance] == [asset.id]

    assert await store.delete_asset(asset.id) is True
    assert await store.delete_asset(asset.id) is False


@pytest.mark.asyncio
async def test_security_store_analysis_case_crud_defaults_and_from_alert(store: SecurityStore):
    case = await store.create_analysis_case(
        AnalysisCaseCreate(
            title="Investigate suspicious login",
            facts=[{"title": "login spike", "description": "Multiple failures"}],
        )
    )

    assert case.id.startswith("ana_")
    assert case.case_status == "new"
    assert case.disposition == "open"
    assert case.facts[0].strength == "medium"

    updated = await store.update_analysis_case(case.id, {"case_status": "analyzing", "disposition": "monitoring"})
    assert updated is not None
    assert updated.case_status == "analyzing"
    assert updated.disposition == "monitoring"

    alert = await store.create_alert(
        AlertCreate(
            asset_id="asset-1",
            title="Suspicious process",
            severity="high",
            description="Endpoint alert",
        )
    )
    from_alert = await store.create_analysis_case_from_alert(alert.id)
    assert from_alert is not None
    assert from_alert.related_alert_ids == [alert.id]
    assert from_alert.primary_asset_id == "asset-1"
    assert from_alert.facts[0].title == "alert_signal"
    assert from_alert.facts[0].strength == "medium"
