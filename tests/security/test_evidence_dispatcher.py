from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations import (
    CredentialProfile,
    CredentialProfileStore,
    EvidenceDispatchRequest,
    EvidenceDispatchResult,
    MappingRule,
    TDA_ALERT_MAPPING,
    apply_mapping,
    dispatch_evidence_events,
    preview_evidence_events,
)
from flocks.security.store import SecurityStore, utc_now


class MemorySecurityStore(SecurityStore):
    def __init__(self):
        self.alerts = []
        self.analysis_cases = []

    async def create_alert(self, payload):
        from flocks.security.models import Alert
        data = payload.model_dump(mode="json", exclude_unset=True)
        data.setdefault("id", f"alert-{len(self.alerts) + 1}")
        data.setdefault("created_at", utc_now())
        data.setdefault("updated_at", data["created_at"])
        if data.get("raw_event") and not data.get("raw_data"):
            data["raw_data"] = data["raw_event"]
        alert = Alert.model_validate(data)
        self.alerts.append(alert)
        return alert

    async def list_alerts(self, filters=None):
        return list(self.alerts)

    async def create_analysis_case(self, payload):
        from flocks.security.models import AnalysisCase
        data = payload.model_dump(mode="json", exclude_unset=True)
        data.setdefault("id", f"case-{len(self.analysis_cases) + 1}")
        data.setdefault("created_at", utc_now())
        data.setdefault("updated_at", data["created_at"])
        case = AnalysisCase.model_validate(data)
        self.analysis_cases.append(case)
        return case

    async def update_analysis_case(self, case_id, payload):
        return self.analysis_cases[0] if self.analysis_cases else None

    async def list_analysis_cases(self, filters=None):
        return list(self.analysis_cases)


def sample_event(**extra):
    event = {
        "external_event_id": "evt-1",
        "title": "Suspicious login",
        "severity": "high",
        "description": "Login from unusual host",
        "asset_id": "host-1",
        "src_ip": "10.0.0.1",
        "key_fields": {"src_ip": "10.0.0.1"},
    }
    event.update(extra)
    return event


def dumped(value) -> str:
    return json.dumps(value, ensure_ascii=False).lower()


def test_preview_single_mapping_engine_event_success():
    result = preview_evidence_events([sample_event()])
    assert isinstance(result, EvidenceDispatchResult)
    assert result.item_count == 1
    assert result.preview_only is True
    assert result.event_summaries[0]["title"] == "Suspicious login"


def test_preview_multiple_events_success():
    result = preview_evidence_events([sample_event(), sample_event(external_event_id="evt-2")])
    assert result.item_count == 2
    assert len(result.event_summaries) == 2


@pytest.mark.asyncio
async def test_preview_only_does_not_create_alert():
    store = MemorySecurityStore()
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[sample_event()], preview_only=True), store=store)
    assert result.created_alerts == 0
    assert await store.list_alerts() == []


@pytest.mark.asyncio
async def test_preview_only_does_not_create_analysis_case():
    store = MemorySecurityStore()
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[sample_event()], preview_only=True), store=store)
    assert result.created_analysis_cases == 0
    assert await store.list_analysis_cases() == []


def test_event_summaries_drop_raw_and_verbose_fields():
    result = preview_evidence_events([
        sample_event(raw_payload="raw", raw_data="raw", source="raw", request="raw", response="raw", body="raw", packet="raw", pcap="raw")
    ])
    text = dumped(result.event_summaries)
    for forbidden in ["raw_payload", "raw_data", "source\": \"raw", "request", "response", "body", "packet", "pcap"]:
        assert forbidden not in text


def test_event_summaries_drop_credential_fields():
    result = preview_evidence_events([
        sample_event(api_key="a", secret="s", token="t", password="p", authorization="bearer", cookie="c")
    ])
    text = dumped(result.event_summaries)
    for forbidden in ["api_key", "secret", "token", "password", "authorization", "cookie", "bearer"]:
        assert forbidden not in text


def test_missing_title_warning():
    result = preview_evidence_events([sample_event(title="")])
    assert any("missing title" in warning for warning in result.warnings)


def test_missing_severity_warning():
    result = preview_evidence_events([sample_event(severity=None)])
    assert any("missing severity" in warning for warning in result.warnings)


def test_missing_external_event_id_warning():
    result = preview_evidence_events([sample_event(external_event_id="")])
    assert any("missing external_event_id" in warning for warning in result.warnings)


def test_connector_context_accepts_vendor_product_package_id():
    result = preview_evidence_events([sample_event()], {"vendor": "Vendor", "product": "Product", "package_id": "pkg.one"})
    summary = result.event_summaries[0]
    assert summary["vendor"] == "Vendor"
    assert summary["product"] == "Product"


@pytest.mark.asyncio
async def test_dispatch_preview_only_true_does_not_write():
    store = MemorySecurityStore()
    await dispatch_evidence_events(EvidenceDispatchRequest(events=[sample_event()]), store=store)
    assert await store.list_alerts() == []


@pytest.mark.asyncio
async def test_dispatch_preview_only_false_reuses_ingest_external_events():
    store = MemorySecurityStore()
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[sample_event()], preview_only=False), store=store)
    assert result.created_alerts == 1
    alerts = await store.list_alerts()
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_preview_only_false_create_analysis_cases_defaults_false():
    store = MemorySecurityStore()
    result = await dispatch_evidence_events(EvidenceDispatchRequest(events=[sample_event()], preview_only=False), store=store)
    assert result.created_analysis_cases == 0
    assert await store.list_analysis_cases() == []


def test_does_not_call_connector(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("connector called")

    monkeypatch.setattr("flocks.security.connectors.tda.TDAConnector", fail, raising=False)
    result = preview_evidence_events([sample_event()])
    assert result.item_count == 1


def test_does_not_create_incident():
    result = preview_evidence_events([sample_event(incident_id="bad")])
    assert "incident_id" not in dumped(result.event_summaries)


def test_does_not_send_notification(monkeypatch):
    monkeypatch.setattr("flocks.security.analysis.build_notification_for_case", lambda *a, **k: (_ for _ in ()).throw(AssertionError("notification")))
    assert preview_evidence_events([sample_event()]).item_count == 1


def test_does_not_remediate():
    result = preview_evidence_events([sample_event(remediation="block host", action="quarantine")])
    text = dumped(result.event_summaries)
    assert "remediation" not in text


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from fastapi import FastAPI, Request
    from flocks.auth.context import AuthUser
    from flocks.server.routes.security import router as security_router
    from flocks.storage.storage import Storage

    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
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


@pytest.mark.asyncio
async def test_api_preview_200(client: AsyncClient):
    response = await client.post("/api/security/integrations/evidence-dispatch/preview", json={"events": [sample_event()]})
    assert response.status_code == 200, response.text
    assert response.json()["item_count"] == 1


@pytest.mark.asyncio
async def test_api_preview_does_not_write_store(client: AsyncClient):
    response = await client.post("/api/security/integrations/evidence-dispatch/preview", json={"events": [sample_event()]})
    assert response.status_code == 200
    alerts = await client.get("/api/security/alerts")
    assert alerts.status_code == 200
    assert alerts.json() == []


def test_compatible_with_apply_mapping_output():
    mapped = apply_mapping({"merge_key": "m1", "threat_desc": "TDA alert", "severity": "高危", "victim_addr": "10.0.0.2"}, TDA_ALERT_MAPPING)
    result = preview_evidence_events([mapped.event])
    assert result.event_summaries[0]["external_event_id"] == mapped.event["external_event_id"]


def test_integrations_init_keeps_credential_and_dispatcher_exports():
    assert CredentialProfile is not None
    assert CredentialProfileStore is not None
    assert EvidenceDispatchRequest is not None
    assert EvidenceDispatchResult is not None
    assert MappingRule is not None
