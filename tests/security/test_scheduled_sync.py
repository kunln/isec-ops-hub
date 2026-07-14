"""Tests for the Integration Runtime v2 Scheduled Sync plan-only skeleton."""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.storage.storage import Storage


NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.security import secrets as secrets_module
    from flocks.security.connectors.registry import connector_registry

    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")

    from fastapi import FastAPI, Request
    from flocks.auth.context import AuthUser
    from flocks.server.routes.security import router as security_router

    app = FastAPI()

    @app.middleware("http")
    async def inject_admin(request: Request, call_next):
        request.state.auth_user = AuthUser(
            id="admin",
            username="admin",
            role="admin",
            status="active",
            must_reset_password=False,
        )
        return await call_next(request)

    app.include_router(security_router, prefix="/api/security")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests()


def make_profile(**updates: Any):
    from flocks.security.integrations.sync_profiles import SyncProfile

    values: dict[str, Any] = {
        "sync_profile_id": "syncprof_scheduled",
        "display_name": "Scheduled TDA alerts",
        "instance_id": "intinst_scheduled",
        "package_id": "asiainfo.tda",
        "capability": "alert.search",
        "mode": "manual",
        "enabled": True,
        "schedule": None,
        "cursor": {"page": "unchanged"},
        "last_status": "never_run",
        "last_synced_at": None,
        "last_run_id": None,
    }
    values.update(updates)
    return SyncProfile(**values)


async def seed_profile(**updates: Any):
    profile = make_profile(**updates)
    await Storage.set(
        f"security/sync_profiles/{profile.sync_profile_id}",
        profile,
        "security.sync_profiles",
    )
    return profile


def evaluate(profile, *, now: datetime = NOW):
    from flocks.security.integrations.scheduled_sync import (
        evaluate_scheduled_sync_status,
    )

    return evaluate_scheduled_sync_status(profile, now=now)


def iso_before(seconds: int) -> str:
    return (NOW - timedelta(seconds=seconds)).isoformat()


def test_manual_and_disabled_profiles_are_never_due() -> None:
    manual = evaluate(make_profile(mode="manual"))
    disabled = evaluate(make_profile(mode="hourly", enabled=False))

    assert (manual.schedule_kind, manual.reason, manual.due) == (
        "manual",
        "manual_only",
        False,
    )
    assert (disabled.schedule_kind, disabled.reason, disabled.due) == (
        "hourly",
        "disabled",
        False,
    )


def test_hourly_never_synced_recent_and_due_thresholds() -> None:
    never = evaluate(make_profile(mode="hourly"))
    recent = evaluate(
        make_profile(mode="hourly", last_synced_at=iso_before(3_599))
    )
    due = evaluate(make_profile(mode="hourly", last_synced_at=iso_before(3_600)))

    assert (never.reason, never.due) == ("never_synced", True)
    assert (recent.reason, recent.due) == ("not_due", False)
    assert (due.reason, due.due) == ("due", True)


@pytest.mark.parametrize(
    ("mode", "threshold"),
    [("daily", 86_400), ("weekly", 604_800)],
)
def test_daily_and_weekly_thresholds(mode: str, threshold: int) -> None:
    before = evaluate(
        make_profile(mode=mode, last_synced_at=iso_before(threshold - 1))
    )
    at_threshold = evaluate(
        make_profile(mode=mode, last_synced_at=iso_before(threshold))
    )

    assert (before.reason, before.due) == ("not_due", False)
    assert (at_threshold.reason, at_threshold.due) == ("due", True)


@pytest.mark.parametrize(
    "schedule",
    ["interval:3600", {"kind": "interval", "seconds": 3_600}, {"interval_seconds": 3_600}],
)
def test_interval_schedule_forms(schedule: Any) -> None:
    status = evaluate(
        make_profile(
            mode="manual",
            schedule=schedule,
            last_synced_at=iso_before(3_600),
        )
    )

    assert (status.schedule_kind, status.reason, status.due) == (
        "interval",
        "due",
        True,
    )


@pytest.mark.parametrize(
    ("schedule", "reason"),
    [
        ("interval:0", "invalid_interval"),
        ({"type": "interval", "seconds": "invalid"}, "invalid_interval"),
        ("cron:0 * * * *", "unsupported_schedule"),
        ({"kind": "cron"}, "unsupported_schedule"),
    ],
)
def test_invalid_and_unsupported_schedules_are_not_due(
    schedule: Any, reason: str
) -> None:
    status = evaluate(make_profile(schedule=schedule))

    assert status.reason == reason
    assert status.due is False


@pytest.mark.parametrize("last_synced_at", ["invalid", "2026-07-14T11:00:00"])
def test_invalid_or_naive_last_sync_time_fails_closed(last_synced_at: str) -> None:
    status = evaluate(make_profile(mode="hourly", last_synced_at=last_synced_at))

    assert (status.reason, status.due) == ("validation_failed", False)


@pytest.mark.asyncio
async def test_status_missing_profile_and_due_query(client: AsyncClient) -> None:
    await seed_profile(sync_profile_id="syncprof_manual", mode="manual")
    await seed_profile(sync_profile_id="syncprof_due", mode="hourly")
    await seed_profile(
        sync_profile_id="syncprof_recent",
        mode="hourly",
        last_synced_at=datetime.now(UTC).isoformat(),
    )

    missing = await client.get(
        "/api/security/integrations/scheduled-sync/status",
        params={"sync_profile_id": "syncprof_missing"},
    )
    due = await client.get("/api/security/integrations/scheduled-sync/due")
    all_status = await client.get(
        "/api/security/integrations/scheduled-sync/due",
        params={"due_only": False},
    )

    assert missing.status_code == 200
    assert missing.json()[0]["reason"] == "missing_profile"
    assert [item["sync_profile_id"] for item in due.json()] == ["syncprof_due"]
    assert {item["sync_profile_id"] for item in all_status.json()} == {
        "syncprof_manual",
        "syncprof_due",
        "syncprof_recent",
    }


@pytest.mark.asyncio
async def test_plan_manual_and_not_due_do_not_create_runs(client: AsyncClient) -> None:
    manual = await seed_profile(sync_profile_id="syncprof_manual", mode="manual")
    recent = await seed_profile(
        sync_profile_id="syncprof_recent",
        mode="hourly",
        last_synced_at=datetime.now(UTC).isoformat(),
    )

    manual_response = await client.post(
        "/api/security/integrations/scheduled-sync/plan",
        json={"sync_profile_id": manual.sync_profile_id, "dry_run": False},
    )
    recent_response = await client.post(
        "/api/security/integrations/scheduled-sync/plan",
        json={"sync_profile_id": recent.sync_profile_id},
    )
    runs = await client.get("/api/security/integrations/runs")

    assert manual_response.json()["status"] == "manual_only"
    assert recent_response.json()["status"] == "not_due"
    assert runs.json() == []


@pytest.mark.asyncio
async def test_due_and_forced_not_due_create_plan_only_runs(client: AsyncClient) -> None:
    due = await seed_profile(sync_profile_id="syncprof_due", mode="hourly")
    recent = await seed_profile(
        sync_profile_id="syncprof_force",
        mode="hourly",
        last_synced_at=datetime.now(UTC).isoformat(),
    )

    due_response = await client.post(
        "/api/security/integrations/scheduled-sync/plan",
        json={"sync_profile_id": due.sync_profile_id, "dry_run": False},
    )
    forced_response = await client.post(
        "/api/security/integrations/scheduled-sync/plan",
        json={"sync_profile_id": recent.sync_profile_id, "force": True},
    )

    for body in (due_response.json(), forced_response.json()):
        assert body["status"] == "planned"
        assert body["planned_action"] == "scheduled_sync_plan_only"
        assert body["run_id"].startswith("intrun_")
        run = (
            await client.get(f"/api/security/integrations/runs/{body['run_id']}")
        ).json()
        assert run["run_type"] == "scheduled_sync_plan"
        assert run["status"] == "planned"
        assert run["request_summary"]["dry_run"] is True
        assert run["metadata"]["source"] == "scheduled_sync"
        assert run["metadata"]["plan_only"] is True

    assert due_response.json()["due"] is True
    assert forced_response.json()["due"] is False
    assert forced_response.json()["reason"] == "not_due"


@pytest.mark.asyncio
async def test_plan_missing_disabled_and_invalid_statuses(client: AsyncClient) -> None:
    disabled = await seed_profile(
        sync_profile_id="syncprof_disabled", mode="hourly", enabled=False
    )
    invalid = await seed_profile(
        sync_profile_id="syncprof_invalid", schedule="interval:0"
    )
    unsupported = await seed_profile(
        sync_profile_id="syncprof_unsupported", schedule="cron"
    )

    expected = {
        "missing": "not_found",
        disabled.sync_profile_id: "disabled",
        invalid.sync_profile_id: "validation_failed",
        unsupported.sync_profile_id: "unsupported_schedule",
    }
    for sync_profile_id, status in expected.items():
        response = await client.post(
            "/api/security/integrations/scheduled-sync/plan",
            json={"sync_profile_id": sync_profile_id},
        )
        assert response.status_code == 200
        assert response.json()["status"] == status


@pytest.mark.asyncio
async def test_scheduled_plan_preserves_profile_and_all_dangerous_boundaries(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flocks.security.connectors.registry import ConnectorRegistry
    from flocks.security.integrations.adapter_registry import AdapterRegistry
    from flocks.security.integrations.sync_profile_store import (
        default_sync_profile_store,
    )

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("scheduled plan crossed a forbidden execution boundary")

    monkeypatch.setattr(AdapterRegistry, "get_adapter", forbidden)
    monkeypatch.setattr(ConnectorRegistry, "sync", forbidden)
    monkeypatch.setattr(
        "flocks.security.integrations.evidence_dispatcher.dispatch_evidence_events",
        forbidden,
    )
    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr(
        "flocks.security.integrations.credential_store.resolve_credential_profile_ref",
        forbidden,
    )
    monkeypatch.setattr(socket, "create_connection", forbidden)

    profile = await seed_profile(
        sync_profile_id="syncprof_boundary",
        mode="hourly",
        cursor={"page": "keep"},
        last_synced_at=(datetime.now(UTC) - timedelta(seconds=7_200)).isoformat(),
        last_run_id="intrun_existing",
        last_status="ingested",
    )
    before = profile.model_dump(mode="json")
    response = await client.post(
        "/api/security/integrations/scheduled-sync/plan",
        json={"sync_profile_id": profile.sync_profile_id},
    )
    after = await default_sync_profile_store.get_profile(profile.sync_profile_id)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "planned"
    assert after is not None
    assert after.model_dump(mode="json") == before
    assert after.cursor == {"page": "keep"}
    assert after.last_synced_at == before["last_synced_at"]
    assert after.last_run_id == "intrun_existing"
    assert after.last_status == "ingested"
    assert (await client.get("/api/security/alerts")).json() == []
    assert (await client.get("/api/security/analysis-cases")).json() == []
    assert (await client.get("/api/security/incidents")).json() == []


def test_integrations_init_exports_scheduled_sync_symbols() -> None:
    import flocks.security.integrations as integrations

    for name in (
        "ScheduledSyncStatus",
        "ScheduledSyncPlanRequest",
        "ScheduledSyncPlanResult",
        "evaluate_scheduled_sync_status",
        "list_scheduled_sync_status",
        "list_due_scheduled_sync",
        "plan_scheduled_sync",
    ):
        assert hasattr(integrations, name)
