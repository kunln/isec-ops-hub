from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.evidence_ingestion import summarize_external_event
from flocks.storage.storage import Storage


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config

    Config._global_config = None
    Config._cached_config = None
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


def _request(event_id: str = "evt-001") -> dict:
    return {
        "connector_context": {"connector_id": "demo-waf", "connector_name": "Demo WAF", "vendor": "Generic", "product": "WAF", "source_type": "waf", "external_base_url": "https://waf.example.local/events"},
        "events": [{"id": event_id, "title": "SQL injection blocked", "severity": "high", "action": "block", "src_ip": "1.1.1.1", "dst_ip": "10.0.0.10", "url": "/login?id=1 union select", "timestamp": "2026-07-07T10:00:00+00:00", "payload": "secret raw payload" * 1000}],
        "create_analysis_cases": True,
        "run_initial_analysis": True,
        "deduplicate": True,
    }


def test_summarize_external_event_does_not_return_full_raw_payload():
    event = {f"key_{i}": f"value_{i}" for i in range(40)}
    event.update({"id": "evt-big", "title": "Blocked SQLi", "payload": "X" * 5000, "description": "D" * 1500})
    summary = summarize_external_event(event, connector_context={"connector_id": "demo-waf", "source_type": "waf"})
    assert "payload" not in summary
    assert summary["payload_hash"]
    assert len(summary["key_fields"]) <= 30
    assert "payload" not in summary["key_fields"]
    assert len(summary["description"]) < 1020


@pytest.mark.asyncio
async def test_ingest_api_creates_alert_and_lightweight_raw_event(client: AsyncClient):
    response = await client.post("/api/security/evidence-ingestion/ingest", json=_request())
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["created_alerts"] == 1
    alert_id = data["items"][0]["alert_id"]
    alert = (await client.get(f"/api/security/alerts/{alert_id}")).json()
    assert alert["raw_event"]["evidence_summary"] is True
    assert "secret raw payload" not in str(alert["raw_event"])
    assert alert["normalized_data"]["payload_hash"]
    assert alert["normalized_data"]["external_event_id"] == "evt-001"


@pytest.mark.asyncio
async def test_ingest_api_creates_analysis_case_with_external_evidence_and_facts(client: AsyncClient):
    response = await client.post("/api/security/evidence-ingestion/ingest", json=_request("evt-case"))
    data = response.json()
    case_id = data["items"][0]["analysis_case_id"]
    case = (await client.get(f"/api/security/analysis-cases/{case_id}")).json()
    assert case["evidence_items"]
    external_items = [item for item in case["evidence_items"] if item.get("external_event_id") == "evt-case"]
    assert external_items
    assert external_items[0]["connector_id"] == "demo-waf"
    assert external_items[0]["payload_hash"]
    assert external_items[0]["key_fields"]
    assert case["facts"]
    assert case["verdict"] in ["confirmed_attack_attempt_blocked", "suspicious_true_positive"]


@pytest.mark.asyncio
async def test_ingest_deduplicate_and_does_not_create_incident(client: AsyncClient):
    before = (await client.get("/api/security/incidents")).json()
    first = (await client.post("/api/security/evidence-ingestion/ingest", json=_request("evt-dup"))).json()
    second = (await client.post("/api/security/evidence-ingestion/ingest", json=_request("evt-dup"))).json()
    after = (await client.get("/api/security/incidents")).json()
    assert first["created_alerts"] == 1
    assert second["skipped_duplicates"] == 1
    assert second["created_alerts"] == 0
    assert after == before


@pytest.mark.asyncio
async def test_waf_blocked_event_initial_analysis_and_brief_external_refs(client: AsyncClient):
    data = (await client.post("/api/security/evidence-ingestion/ingest", json=_request("evt-brief"))).json()
    case_id = data["items"][0]["analysis_case_id"]
    case = (await client.get(f"/api/security/analysis-cases/{case_id}")).json()
    fact_types = {fact["fact_type"] for fact in case["facts"]}
    assert case["verdict"] in ["confirmed_attack_attempt_blocked", "suspicious_true_positive"]
    assert "attack_pattern_matched" in fact_types
    assert "protection_action_observed" in fact_types
    brief = (await client.get(f"/api/security/analysis-cases/{case_id}/brief")).json()["markdown"]
    assert "evt-brief" in brief or "demo-waf" in brief or data["items"][0]["payload_hash"] in brief
