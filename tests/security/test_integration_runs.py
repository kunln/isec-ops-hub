"""Tests for Integration Run v2 alignment with ConnectorSyncRun."""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.integrations.run_store import IntegrationRunStore, finish_integration_run, record_integration_run
from flocks.security.integrations.runs import IntegrationRunCreate, IntegrationRunUpdate, build_integration_run_from_connector_sync_run
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


@pytest.mark.asyncio
async def test_integration_run_store_crud_filters_and_safe_export(client: AsyncClient):
    store = IntegrationRunStore()
    payload = IntegrationRunCreate(
        package_id="asiainfo.tda",
        instance_id="intinst_1",
        sync_profile_id="sync_1",
        capability="alert.search",
        status="running",
        request_summary={"api_key": "secret", "raw_payload": {"full": True}, "query": "alerts"},
        plan_summary={"request": {"secret": "hidden"}, "step": "dry-run"},
        metadata={"token": "secret", "owner": "secops"},
        item_refs=[{"type": "event", "id": "evt_1", "title": "T", "raw_data": "drop", "password": "drop"}],
        error_message="boom token=abcdef " + "x" * 1000,
    )
    run = await store.create_run(payload)
    assert run.run_id.startswith("intrun_")
    assert run.request_summary["api_key"] == "[REDACTED]"
    assert "raw_payload" not in run.request_summary
    assert "request" not in run.plan_summary
    assert run.metadata["token"] == "[REDACTED]"
    assert run.item_refs == [{"type": "event", "id": "evt_1", "title": "T"}]
    dumped = run.model_dump_json()
    for forbidden in ("raw_payload", "raw_data", "response", "body", "packet", "pcap", "abcdef"):
        assert forbidden not in dumped
    assert "request" not in run.plan_summary
    assert len(run.error_message or "") <= 500

    got = await store.get_run(run.run_id)
    assert got and got.run_id == run.run_id
    assert [r.run_id for r in await store.list_runs()] == [run.run_id]
    assert await store.list_runs(package_id="asiainfo.tda")
    assert await store.list_runs(instance_id="intinst_1")
    assert await store.list_runs(sync_profile_id="sync_1")
    assert await store.list_runs(capability="alert.search")
    assert await store.list_runs(status="running")
    assert not await store.list_runs(package_id="other")

    updated = await store.update_run(run.run_id, IntegrationRunUpdate(status="success", result_summary={"created": 1, "response": "drop"}))
    assert updated and updated.status == "success"
    assert updated.result_summary == {"created": 1}


@pytest.mark.asyncio
async def test_record_and_finish_helpers_do_not_execute_external_actions(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("connector/http/security object creation must not be called")

    monkeypatch.setattr("flocks.server.routes.security.ingest_tda_events", forbidden)
    monkeypatch.setattr("flocks.server.routes.security.ingest_mingyu_apt_risks", forbidden)
    run = await record_integration_run(IntegrationRunCreate(package_id="asiainfo.tda", capability="alert.search"))
    finished = await finish_integration_run(run.run_id, "success", result_summary={"count": 1}, item_refs=[{"id": "evt_1", "hash": "h"}])
    assert finished and finished.status == "success"
    assert finished.result_summary == {"count": 1}
    assert finished.item_refs == [{"id": "evt_1", "hash": "h"}]
    assert not await default_store.list_alerts()
    assert not await default_store.list_analysis_cases()
    assert not await default_store.list_incidents()


@pytest.mark.asyncio
async def test_build_integration_run_from_connector_sync_run_is_non_mutating(client: AsyncClient):
    connector_run = await default_store.create_connector_sync_run({
        "connector_id": "tda",
        "connector_name": "TDA",
        "vendor": "AsiaInfo",
        "product": "TDA",
        "mode": "alert",
        "status": "success",
        "request_summary": {"begin": "b", "api_key": "secret"},
        "result_summary": {"created_alerts": 1, "raw_data": {"drop": True}},
        "item_refs": [{"status": "created", "external_event_id": "evt", "raw_payload": "drop"}],
        "metadata": {"note": "v1"},
    })
    before = connector_run.model_dump(mode="json")
    run = build_integration_run_from_connector_sync_run(connector_run)
    assert run.run_id == f"intrun_{connector_run.id}"
    assert run.connector_id == "tda"
    assert run.connector_name == "TDA"
    assert run.vendor == "AsiaInfo"
    assert run.product == "TDA"
    assert run.mode == "alert"
    assert run.status == "success"
    assert run.request_summary["api_key"] == "[REDACTED]"
    assert "raw_data" not in run.result_summary
    assert run.item_refs == [{"status": "created", "external_event_id": "evt"}]
    assert connector_run.model_dump(mode="json") == before


@pytest.mark.asyncio
async def test_integration_runs_api_and_old_connector_runs_api_remain(client: AsyncClient):
    store = IntegrationRunStore()
    run = await store.create_run(IntegrationRunCreate(package_id="asiainfo.tda", instance_id="intinst_1", capability="alert.search", status="running"))
    connector_run = await default_store.create_connector_sync_run({"connector_id": "mingyu-apt", "mode": "risk", "status": "success"})

    res = await client.get("/api/security/integrations/runs", params={"status": "running"})
    assert res.status_code == 200, res.text
    assert any(item["run_id"] == run.run_id for item in res.json())

    detail = await client.get(f"/api/security/integrations/runs/{run.run_id}")
    assert detail.status_code == 200
    assert detail.json()["package_id"] == "asiainfo.tda"

    compat_detail = await client.get(f"/api/security/integrations/runs/intrun_{connector_run.id}")
    assert compat_detail.status_code == 200
    assert compat_detail.json()["metadata"]["source_run_id"] == connector_run.id

    old_list = await client.get("/api/security/connector-runs")
    assert old_list.status_code == 200
    assert any(item["id"] == connector_run.id for item in old_list.json())
    old_detail = await client.get(f"/api/security/connector-runs/{connector_run.id}")
    assert old_detail.status_code == 200


def test_flocks_package_name_not_changed():
    import flocks

    assert flocks.__name__ == "flocks"
