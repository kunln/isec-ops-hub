import base64
import hashlib
import hmac
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.connectors import tda
from flocks.security.connectors.tda import (
    TdaClient,
    build_tda_time_query,
    extract_tda_items,
    ingest_tda_events,
    map_tda_item_to_evidence_event,
)
from flocks.security.store import default_store
from flocks.storage.storage import Storage


@pytest.fixture
async def isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config

    Config._global_config = None
    Config._cached_config = None
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield default_store
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


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


def test_tda_signature_generation():
    headers = TdaClient("https://tda.local", "ak", "sk").build_auth_headers(timestamp=1751532923)
    expected = base64.urlsafe_b64encode(hmac.new(b"sk", b"1751532923ak", hashlib.sha256).digest()).decode("ascii")
    assert headers == {"api_key": "ak", "auth_timestamp": "1751532923", "sign": expected}
    assert "secret" not in headers


def test_build_tda_time_query():
    query = build_tda_time_query("2026-07-01 00:00:00", "2026-07-07T23:59:59", time_type=2)
    assert query["time_type"] == 5
    assert query["time_limit"] == "1782864000,1783468799"
    assert build_tda_time_query(None, None, time_type=3) == {"time_type": 3}


def test_alert_mapping_lightweight_fields():
    item = {"merge_key": "2024-03-13:106050025:1.150.2.200:1.200.29.40:1", "first_time": 1710309566000, "latest_time": 1710309566000, "threat_desc": "可疑威胁：检测到内网穿透工具", "src": "1.150.2.200", "dst": "1.200.29.40", "severity": "高危", "attack_res": 2, "rule_id": 103016461, "http_req_body": "drop"}
    event = map_tda_item_to_evidence_event(item, "alert", {"connector_id": "tda", "source_type": "tda"})
    assert event["external_event_id"] == item["merge_key"]
    assert "内网穿透" in event["title"]
    assert event["severity"] == "high"
    assert event["asset_id"] == "1.200.29.40"
    assert "1.150.2.200" in event["ioc"] and "1.200.29.40" in event["ioc"]
    assert event["occurred_at"]
    assert "http_req_body" not in event["key_fields"]


def test_event_mapping_drops_body_headers():
    item = {"flow_id": "146366989535228235", "event_time": 1645687115, "attacker_addr": "1.150.12.119", "victim_addr": "1.200.15.237", "rule_id": 103020715, "severity": "中危", "threat_class": "Web攻击", "rule_name": "Web弱密码尝试访问", "http_req_body": "very large body", "http_resp_body": "very large response"}
    event = map_tda_item_to_evidence_event(item, "event", {"connector_id": "tda"})
    assert event["severity"] == "medium"
    assert "Web弱密码" in event["title"] or "Web攻击" in event["title"]
    assert "http_req_body" not in event["key_fields"]
    assert "http_resp_body" not in event["key_fields"]
    assert event["payload_hash"]


def test_asset_risk_mapping():
    item = {"asset_addr": "10.21.144.215", "asset_name": "test_asset_name", "level": "失陷", "latest_time": 1746707625, "count": 3, "disposal_name": "未处置"}
    event = map_tda_item_to_evidence_event(item, "asset_risk", {"connector_id": "tda"})
    assert event["severity"] in {"critical", "high"}
    assert event["asset_id"] == "10.21.144.215"
    assert "10.21.144.215" in event["title"] and "失陷" in event["title"]
    assert event["key_fields"]["count"] == 3
    assert event["key_fields"]["disposal_name"] == "未处置"


def test_password_mapping_does_not_store_passwords():
    item = {"latest_time": 1751595363, "app_proto": "imap", "rule_id": 105010004, "dst": "192.168.71.130", "dst_port": 143, "login_user": "zhuzhu", "login_password": "***456", "login_password_encrypted": "qh8IER42VPUMU2DstxaPC29S/8QsCQ==", "login_path": "zhuzhu@192.168.71.130", "login_result": "成功", "threat_desc": "口令安全：检测到 IMAP 弱密码登录，命中弱口令字典", "num": 60}
    event = map_tda_item_to_evidence_event(item, "weak_pwd", {"connector_id": "tda"})
    assert "弱密码" in event["title"] or "口令安全" in event["description"]
    assert event["asset_id"] == "192.168.71.130"
    assert "***456" not in event["ioc"]
    assert "login_password" not in event["key_fields"]
    assert "login_password_encrypted" not in event["key_fields"]
    assert event["payload_hash"]
    assert "***456" not in str(event)
    assert "qh8IER42VPUMU2DstxaPC29S/8QsCQ==" not in str(event)


def test_extract_tda_items_paths():
    assert extract_tda_items({"data": {"alarm_list": [{"id": 1}]}}, "alert") == [{"id": 1}]
    assert extract_tda_items({"data": {"alarm_list": [{"id": 2}]}}, "event") == [{"id": 2}]
    assert extract_tda_items({"data": {"ar_list": [{"id": 3}]}}, "asset_risk") == [{"id": 3}]
    assert extract_tda_items({"data": {"asset_list": [{"id": 4}]}}, "weak_pwd") == [{"id": 4}]
    assert extract_tda_items({"data": {"asset_list": [{"id": 5}]}}, "plaintext") == [{"id": 5}]


@pytest.mark.asyncio
async def test_ingest_tda_events_with_fake_client(monkeypatch: pytest.MonkeyPatch, isolated_store):
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        def fetch_alert_list(self, *args, **kwargs):
            return {"data": {"alarm_list": [{"merge_key": "a", "threat_desc": "A", "dst": "10.0.0.1"}, {"merge_key": "b", "threat_desc": "B", "dst": "10.0.0.2"}], "total": 2}}
    monkeypatch.setattr(tda, "TdaClient", FakeClient)
    result = await ingest_tda_events("https://tda.local", "ak", "sk", limit=2, max_pages=1, store=isolated_store)
    assert result["created_alerts"] == 2
    assert result["created_analysis_cases"] == 2
    assert await isolated_store.list_incidents() == []
    item = (await isolated_store.list_analysis_cases())[0].evidence_items[-1]
    assert item.connector_id == "tda"
    assert item.product == "TDA"
    assert item.external_event_id
    assert item.payload_hash


@pytest.mark.asyncio
async def test_tda_deduplicate(monkeypatch: pytest.MonkeyPatch, isolated_store):
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        def fetch_alert_list(self, *args, **kwargs): return {"data": {"alarm_list": [{"merge_key": "dup", "threat_desc": "A"}]}}
    monkeypatch.setattr(tda, "TdaClient", FakeClient)
    first = await ingest_tda_events("https://tda.local", "ak", "sk", store=isolated_store)
    second = await ingest_tda_events("https://tda.local", "ak", "sk", store=isolated_store)
    assert first["created_alerts"] == 1
    assert second["skipped_duplicates"] == 1


@pytest.mark.asyncio
async def test_tda_test_endpoint(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        def test_connection(self): return {"ok": True}
    monkeypatch.setattr("flocks.server.routes.security.TdaClient", FakeClient)
    response = await client.post("/api/security/connectors/tda/test", json={"base_url": "https://tda.local", "api_key": "ak", "secret": "sk", "verify_ssl": False})
    assert response.status_code == 200, response.text
    assert response.json()["result"] == {"ok": True}
    assert "sk" not in response.text


@pytest.mark.asyncio
async def test_tda_ingest_endpoint_success_records_run(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    async def fake_ingest(**kwargs):
        return {"created_alerts": 1, "skipped_duplicates": 0, "created_analysis_cases": 1, "items": [{"status": "created", "alert_id": "a", "analysis_case_id": "c", "external_event_id": "evt", "payload_hash": "hash", "title": "TDA", "severity": "high"}]}
    monkeypatch.setattr("flocks.server.routes.security.ingest_tda_events", fake_ingest)
    payload = {"base_url": "https://tda.local/path?q=secret", "api_key": "ak", "secret": "sk", "begin": "2026-07-01 00:00:00", "end": "2026-07-07 23:59:59", "mode": "alert", "limit": 20, "max_pages": 1, "create_analysis_cases": True, "run_initial_analysis": True, "deduplicate": True, "verify_ssl": False}
    res = await client.post("/api/security/connectors/tda/ingest", json=payload)
    assert res.status_code == 200, res.text
    run_id = res.json()["run_id"]
    run = (await client.get(f"/api/security/connector-runs/{run_id}")).json()
    assert run["status"] == "success"
    assert "ak" not in str(run["request_summary"])
    assert "sk" not in str(run["request_summary"])
    assert "sign" not in str(run["request_summary"]).lower()
    assert "auth_timestamp" not in str(run["request_summary"])
    assert run["result_summary"]["created_alerts"] == 1


@pytest.mark.asyncio
async def test_tda_ingest_endpoint_failed_sanitizes_error(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    async def fake_ingest(**kwargs):
        raise RuntimeError('api_key=ak secret=sk sign=sig auth_timestamp=123 "secret":"sk" Authorization: Bearer tok')
    monkeypatch.setattr("flocks.server.routes.security.ingest_tda_events", fake_ingest)
    payload = {"base_url": "https://tda.local", "api_key": "ak", "secret": "sk", "mode": "alert"}
    res = await client.post("/api/security/connectors/tda/ingest", json=payload)
    assert res.status_code == 400
    runs = (await client.get("/api/security/connector-runs", params={"connector_id": "tda"})).json()
    assert runs[0]["status"] == "failed"
    assert "ak" not in runs[0]["error_message"]
    assert "sk" not in runs[0]["error_message"]
    assert "tok" not in runs[0]["error_message"]
