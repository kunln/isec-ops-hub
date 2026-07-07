from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.connector_runs import sanitize_connector_request_summary
from flocks.security.store import default_store
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


def _payload():
    return {"base_url": "https://apt.local/openapi?token=secret", "apikey": "secret", "begin": "b", "end": "e", "mode": "risk", "limit": 20, "max_pages": 1, "create_analysis_cases": True, "run_initial_analysis": True, "deduplicate": True, "verify_ssl": False}


def test_sanitize_connector_request_summary_removes_secrets():
    summary = sanitize_connector_request_summary({**_payload(), "token": "t", "password": "p", "secret": "s", "authorization": "Bearer x"})
    assert "apikey" not in summary
    assert "token" not in summary
    assert "password" not in summary
    assert "secret" not in summary
    assert "authorization" not in summary
    assert summary["base_url_host"] == "https://apt.local"
    assert summary["begin"] == "b"
    assert summary["end"] == "e"
    assert summary["mode"] == "risk"
    assert summary["limit"] == 20
    assert summary["max_pages"] == 1


@pytest.mark.asyncio
async def test_connector_sync_run_store_crud(client: AsyncClient):
    run = await default_store.create_connector_sync_run({"connector_id": "mingyu-apt", "mode": "risk", "status": "running"})
    assert run.id.startswith("csrun_")
    got = await default_store.get_connector_sync_run(run.id)
    assert got and got.connector_id == "mingyu-apt"
    assert await default_store.list_connector_sync_runs(connector_id="mingyu-apt", status="running", mode="risk")
    updated = await default_store.update_connector_sync_run(run.id, {"status": "success", "finished_at": "done"})
    assert updated and updated.status == "success"
    failed = await default_store.create_connector_sync_run({"connector_id": "other", "mode": "test", "status": "failed"})
    assert (await default_store.get_connector_sync_run(failed.id)).status == "failed"


@pytest.mark.asyncio
async def test_mingyu_ingest_api_success_records_run(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    async def fake_ingest(**kwargs):
        return {"created_alerts": 1, "skipped_duplicates": 0, "created_analysis_cases": 1, "items": [{"status": "created", "alert_id": "alr_1", "analysis_case_id": "acase_1", "external_event_id": "evt", "payload_hash": "hash", "title": "APT", "severity": "high", "raw": "drop"}]}
    monkeypatch.setattr("flocks.server.routes.security.ingest_mingyu_apt_risks", fake_ingest)
    res = await client.post("/api/security/connectors/mingyu-apt/ingest", json=_payload())
    assert res.status_code == 200, res.text
    run_id = res.json()["run_id"]
    run = (await client.get(f"/api/security/connector-runs/{run_id}")).json()
    assert run["status"] == "success"
    assert "apikey" not in run["request_summary"]
    assert run["request_summary"]["base_url_host"] == "https://apt.local"
    assert run["result_summary"]["created_alerts"] == 1
    assert "raw" not in run["item_refs"][0]


@pytest.mark.asyncio
async def test_mingyu_ingest_api_partial_success(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    async def fake_ingest(**kwargs):
        return {"created_alerts": 1, "skipped_duplicates": 0, "created_analysis_cases": 1, "items": [{"status": "created", "alert_id": "alr_1"}, {"status": "error", "error": "bad"}]}
    monkeypatch.setattr("flocks.server.routes.security.ingest_mingyu_apt_risks", fake_ingest)
    res = await client.post("/api/security/connectors/mingyu-apt/ingest", json=_payload())
    run = (await client.get(f"/api/security/connector-runs/{res.json()['run_id']}")).json()
    assert run["status"] == "partial_success"
    assert run["result_summary"]["error_count"] == 1


@pytest.mark.asyncio
async def test_mingyu_ingest_api_failed_sanitizes_error(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    async def fake_ingest(**kwargs):
        raise RuntimeError("boom apikey=secret secret=hunter2 token=abc")
    monkeypatch.setattr("flocks.server.routes.security.ingest_mingyu_apt_risks", fake_ingest)
    res = await client.post("/api/security/connectors/mingyu-apt/ingest", json=_payload())
    assert res.status_code == 400
    runs = (await client.get("/api/security/connector-runs", params={"status": "failed"})).json()
    assert runs[0]["status"] == "failed"
    assert "secret" not in runs[0]["error_message"]
    assert "hunter2" not in runs[0]["error_message"]


@pytest.mark.asyncio
async def test_connector_runs_list_api_filters(client: AsyncClient):
    await default_store.create_connector_sync_run({"connector_id": "mingyu-apt", "mode": "risk", "status": "success"})
    await default_store.create_connector_sync_run({"connector_id": "other", "mode": "test", "status": "failed"})
    res = await client.get("/api/security/connector-runs", params={"connector_id": "mingyu-apt", "status": "success", "mode": "risk"})
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["connector_id"] == "mingyu-apt"


@pytest.mark.asyncio
async def test_success_run_does_not_auto_create_incident(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    before = len(await default_store.list_incidents())
    async def fake_ingest(**kwargs):
        return {"created_alerts": 1, "skipped_duplicates": 0, "created_analysis_cases": 1, "items": [{"status": "created"}]}
    monkeypatch.setattr("flocks.server.routes.security.ingest_mingyu_apt_risks", fake_ingest)
    res = await client.post("/api/security/connectors/mingyu-apt/ingest", json=_payload())
    assert res.status_code == 200
    assert len(await default_store.list_incidents()) == before
