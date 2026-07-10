import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations import TDA_ALERT_MAPPING, apply_mapping
from flocks.security.integrations.evidence_dispatcher import (
    EvidenceDispatchRequest,
    dispatch_evidence_events,
    preview_evidence_events,
)
from flocks.security.store import default_store


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.storage.storage import Storage

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


def _event(**overrides):
    event = {
        "external_event_id": "evt-1",
        "title": "Mapped SQL injection blocked",
        "severity": "high",
        "description": "A mapped lightweight event",
        "src_ip": "1.1.1.1",
        "asset_refs": ["10.0.0.10"],
        "ioc_refs": ["evil.example"],
        "raw_payload": {"full": "raw"},
        "api_key": "ak-secret",
        "nested": {"token": "tok-secret", "safe": "kept"},
        "password": "pw-secret",
        "secret": "secret-value",
    }
    event.update(overrides)
    return event


def _context():
    return {
        "connector_id": "demo.integration",
        "connector_name": "Demo Integration",
        "vendor": "DemoVendor",
        "product": "DemoProduct",
        "package_id": "demo.package",
        "source_type": "waf",
    }


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def test_preview_single_mapping_engine_event_success():
    result = preview_evidence_events([_event()], connector_context=_context())
    assert result.item_count == 1
    assert result.preview_only is True
    assert result.event_summaries[0]["title"] == "Mapped SQL injection blocked"
    assert result.event_summaries[0]["severity"] == "high"


def test_preview_multiple_events_success():
    result = preview_evidence_events([_event(external_event_id="evt-1"), _event(external_event_id="evt-2")])
    assert result.item_count == 2
    assert len(result.event_summaries) == 2


@pytest.mark.asyncio
async def test_preview_only_creates_no_alert_or_analysis_case(client: AsyncClient):
    before_alerts = await default_store.list_alerts()
    before_cases = await default_store.list_analysis_cases()
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[_event()], connector_context=_context()))
    after_alerts = await default_store.list_alerts()
    after_cases = await default_store.list_analysis_cases()
    assert result.created_alerts == 0
    assert result.created_analysis_cases == 0
    assert after_alerts == before_alerts
    assert after_cases == before_cases


def test_event_summaries_do_not_contain_raw_payload_or_credentials():
    result = preview_evidence_events([_event()])
    dumped = _dump(result.event_summaries)
    for forbidden in ["raw_payload", "api_key", "ak-secret", "secret", "secret-value", "token", "tok-secret", "password", "pw-secret"]:
        assert forbidden not in dumped
    assert result.warnings


@pytest.mark.parametrize("field_name", ["title", "severity", "external_event_id"])
def test_missing_required_field_warns(field_name):
    event = _event()
    event.pop(field_name)
    result = preview_evidence_events([event])
    assert any(f"missing {field_name}" in warning for warning in result.warnings)


def test_connector_context_can_pass_vendor_product_package_id():
    result = preview_evidence_events([_event()], connector_context=_context())
    summary = result.event_summaries[0]
    assert summary["vendor"] == "DemoVendor"
    assert summary["product"] == "DemoProduct"
    assert summary["connector_id"] == "demo.integration"


@pytest.mark.asyncio
async def test_dispatch_preview_only_true_does_not_write(client: AsyncClient):
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[_event()], preview_only=True))
    assert result.preview_only is True
    assert result.created_alerts == 0
    assert await default_store.list_alerts() == []


@pytest.mark.asyncio
async def test_dispatch_preview_only_false_reuses_ingest_with_cases_default_false(client: AsyncClient):
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[_event()], connector_context=_context(), preview_only=False))
    assert result.preview_only is False
    assert result.created_alerts == 1
    assert result.created_analysis_cases == 0
    assert len(await default_store.list_alerts()) == 1
    assert await default_store.list_analysis_cases() == []


def test_dispatcher_does_not_call_connector(monkeypatch):
    def fail(*args, **kwargs):  # pragma: no cover - regression guard
        raise AssertionError("connector called")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail, raising=False)
    result = preview_evidence_events([_event()])
    assert result.item_count == 1


@pytest.mark.asyncio
async def test_dispatcher_does_not_create_incident_or_notification(client: AsyncClient):
    await dispatch_evidence_events(EvidenceDispatchRequest(events=[_event()], preview_only=False))
    assert (await client.get("/api/security/incidents")).json() == []
    assert "notification" not in _dump((await default_store.list_analysis_cases()))


@pytest.mark.asyncio
async def test_api_preview_200_and_does_not_write(client: AsyncClient):
    response = await client.post(
        "/api/security/integrations/evidence-dispatch/preview",
        json={"events": [_event()], "connector_context": _context(), "preview_only": False, "create_analysis_cases": True},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["preview_only"] is True
    assert data["created_alerts"] == 0
    assert data["created_analysis_cases"] == 0
    assert await default_store.list_alerts() == []
    assert await default_store.list_analysis_cases() == []


def test_apply_mapping_output_is_compatible():
    source = {
        "merge_key": "tda-evt-1",
        "threat_desc": "恶意外联告警",
        "severity": "高危",
        "event_time": "2026-07-09T00:00:00Z",
        "victim_addr": "10.0.0.10",
        "dst": "8.8.8.8",
        "domain": "evil.example",
        "raw_payload": {"full": "raw"},
        "api_key": "secret-api-key",
    }
    mapped = apply_mapping(source, TDA_ALERT_MAPPING).event
    result = preview_evidence_events([mapped])
    assert result.event_summaries[0]["external_event_id"] == "tda-evt-1"
    assert result.event_summaries[0]["title"] == "恶意外联告警"
    assert "raw_payload" not in _dump(result.event_summaries)
