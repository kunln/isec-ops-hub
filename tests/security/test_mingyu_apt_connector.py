from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.connectors import mingyu_apt
from flocks.security.connectors.mingyu_apt import map_mingyu_risk_to_evidence_event, parse_accessid_time, ingest_mingyu_apt_risks
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


def test_map_mingyu_risk_to_evidence_event_lightweight_fields():
    item = {"accessid": "2209211622370001684", "name": "远程代码执行【WEB攻击】XXE漏洞利用", "attackgradeid": 3, "attackStatusName": "尝试", "sip": "10.50.24.4", "dip": "61.160.213.115", "payload": "POST / huge payload", "rawdata": "huge raw header"}
    event = map_mingyu_risk_to_evidence_event(item, {"connector_id": "mingyu-apt", "source_type": "apt"})
    assert event["title"] == "远程代码执行【WEB攻击】XXE漏洞利用"
    assert event["severity"] == "high"
    assert event["external_event_id"] == "2209211622370001684"
    assert "payload" not in event["key_fields"]
    assert "rawdata" not in event["key_fields"]
    assert event["payload_hash"]
    assert event["source_type"] == "apt"


def test_accessid_time_parsing():
    assert parse_accessid_time("2209211622370001684") == "2022-09-21 16:22:37"


def test_important_event_mapping():
    event = map_mingyu_risk_to_evidence_event({"accessid": "2210230526280000090", "attackerip": "192.142.40.193", "victimip": "10.20.171.177", "description": "检测到受感染主机请求解析C&C域名 [h868vip2.com]", "processed": 0}, {"connector_id": "mingyu-apt"})
    assert "C&C" in event["title"] or "C&C" in event["description"]
    assert event["asset_id"] == "10.20.171.177"
    assert "192.142.40.193" in event["ioc"] or "10.20.171.177" in event["ioc"]
    assert event["severity"] in {"medium", "high"}


def test_safe_event_mapping():
    event = map_mingyu_risk_to_evidence_event({"id": "1683512349227", "sip": "192.168.30.10", "dip": "192.168.30.100", "success": 150, "total": 499, "event": [{"incidentName": "Webshell后门访问事件", "high": 366, "success": 129}]}, {"connector_id": "mingyu-apt"})
    assert "Webshell" in event["title"]
    assert event["severity"] == "high"
    assert event["asset_id"] == "192.168.30.100"
    assert event["key_fields"]["success"] == 150
    assert event["key_fields"]["total"] == 499
    assert event["key_fields"]["eventSize"] == 1


@pytest.mark.asyncio
async def test_ingest_mingyu_apt_risks_with_fake_client(monkeypatch: pytest.MonkeyPatch, isolated_store):
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        def fetch_risk_list(self, *args, **kwargs):
            return {"data": {"data": [{"accessid": "2209211622370001684", "name": "RCE", "attackgradeid": 3, "dip": "10.0.0.1"}, {"accessid": "2209211622380001685", "name": "SQLi", "attackgradeid": 2, "dip": "10.0.0.2"}]}}
    monkeypatch.setattr(mingyu_apt, "MingyuAptClient", FakeClient)
    result = await ingest_mingyu_apt_risks("https://apt.local", "secret", "b", "e", limit=2, max_pages=1, store=isolated_store)
    assert result["created_alerts"] == 2
    assert result["created_analysis_cases"] == 2
    assert await isolated_store.list_incidents() == []
    cases = await isolated_store.list_analysis_cases()
    item = cases[0].evidence_items[-1]
    assert item.connector_id == "mingyu-apt"
    assert item.product == "Mingyu APT"
    assert item.external_event_id
    assert item.payload_hash


@pytest.mark.asyncio
async def test_mingyu_deduplicate(monkeypatch: pytest.MonkeyPatch, isolated_store):
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        def fetch_risk_list(self, *args, **kwargs): return {"data": {"data": [{"accessid": "2209211622370001684", "name": "RCE"}]}}
    monkeypatch.setattr(mingyu_apt, "MingyuAptClient", FakeClient)
    first = await ingest_mingyu_apt_risks("https://apt.local", "secret", "b", "e", store=isolated_store)
    second = await ingest_mingyu_apt_risks("https://apt.local", "secret", "b", "e", store=isolated_store)
    assert first["created_alerts"] == 1
    assert second["skipped_duplicates"] == 1


@pytest.mark.asyncio
async def test_api_test_endpoint(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        def get_version(self): return {"version": "V2.0R77"}
    monkeypatch.setattr("flocks.server.routes.security.MingyuAptClient", FakeClient)
    response = await client.post("/api/security/connectors/mingyu-apt/test", json={"base_url": "https://apt.local", "apikey": "secret", "verify_ssl": False})
    assert response.status_code == 200, response.text
    assert response.json()["version"]["version"] == "V2.0R77"


@pytest.mark.asyncio
async def test_api_ingest_endpoint(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    captured = {}
    async def fake_ingest(**kwargs):
        captured.update(kwargs)
        return {"created_alerts": 1, "skipped_duplicates": 0, "created_analysis_cases": 1, "items": []}
    monkeypatch.setattr("flocks.server.routes.security.ingest_mingyu_apt_risks", fake_ingest)
    payload = {"base_url": "https://apt.local", "apikey": "secret", "begin": "2026-07-01 00:00:00", "end": "2026-07-07 23:59:59", "mode": "important", "limit": 20, "max_pages": 1, "create_analysis_cases": True, "run_initial_analysis": True, "deduplicate": True, "verify_ssl": False}
    response = await client.post("/api/security/connectors/mingyu-apt/ingest", json=payload)
    assert response.status_code == 200, response.text
    assert captured["base_url"] == payload["base_url"]
    assert captured["apikey"] == payload["apikey"]
    assert captured["mode"] == "important"
