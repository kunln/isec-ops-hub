from pathlib import Path

import pytest

from flocks.security.schemas import AssetCreate, SecurityListFilters
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

from flocks.security.models import AnalysisCase
from flocks.security.schemas import AnalysisCaseCreate


@pytest.mark.asyncio
async def test_security_store_analysis_case_crud_and_filters(store: SecurityStore):
    case = await store.create_analysis_case(
        AnalysisCaseCreate(
            title="Investigate suspicious login",
            description="Initial signal from SIEM",
            severity="high",
            primary_asset_id="asset-1",
            related_asset_ids=["asset-1"],
            related_alert_ids=["alert-1"],
            facts=[
                {
                    "fact_type": "alert_signal",
                    "statement": "SIEM reported suspicious login for host asset-1.",
                    "source_ref": "alert:alert-1",
                    "related_asset_id": "asset-1",
                    "related_alert_id": "alert-1",
                }
            ],
            evidence_gaps=[{"gap_type": "missing_edr", "description": "No EDR telemetry queried yet."}],
        )
    )

    assert isinstance(case, AnalysisCase)
    assert case.id.startswith("case_")
    assert case.facts[0].id.startswith("fact_")
    assert case.facts[0].created_at
    assert case.evidence_gaps[0].id.startswith("gap_")

    fetched = await store.get_analysis_case(case.id)
    assert fetched is not None
    assert fetched.title == "Investigate suspicious login"

    updated = await store.update_analysis_case(case.id, {"case_status": "investigating", "verdict": "suspicious_true_positive"})
    assert updated is not None
    assert updated.case_status == "investigating"
    assert updated.verdict == "suspicious_true_positive"

    by_asset = await store.list_analysis_cases(SecurityListFilters(asset_id="asset-1"))
    by_status = await store.list_analysis_cases(SecurityListFilters(status="investigating"))
    by_keyword = await store.list_analysis_cases(SecurityListFilters(keyword="EDR"))
    assert [item.id for item in by_asset] == [case.id]
    assert [item.id for item in by_status] == [case.id]
    assert [item.id for item in by_keyword] == [case.id]

    assert await store.delete_analysis_case(case.id) is True
    assert await store.get_analysis_case(case.id) is None
