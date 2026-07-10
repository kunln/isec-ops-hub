"""Tests for Sync Engine manual dry-run planning."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.storage.storage import Storage


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


async def create_instance(client: AsyncClient, **extra: object) -> dict[str, object]:
    payload = {
        "package_id": "asiainfo.tda",
        "display_name": "TDA",
        "base_url": "https://tda.example.test",
        "metadata": {"region": "cn"},
    }
    payload.update(extra)
    response = await client.post("/api/security/integrations/instances", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


async def create_profile(
    client: AsyncClient, instance_id: str, **extra: object
) -> dict[str, object]:
    payload = {
        "display_name": "TDA Sync",
        "instance_id": instance_id,
        "capability": "alert.search",
        "params": {"limit": 10},
    }
    payload.update(extra)
    response = await client.post(
        "/api/security/integrations/sync-profiles", json=payload
    )
    assert response.status_code == 200, response.text
    return response.json()


async def plan_api(client: AsyncClient, payload: dict[str, object]):
    return await client.post(
        "/api/security/integrations/sync-engine/plan", json=payload
    )


@pytest.mark.asyncio
async def test_plan_sync_profile_run_success_and_records_run(
    client: AsyncClient,
) -> None:
    from flocks.security.integrations.sync_engine import (
        SyncEnginePlanRequest,
        plan_sync_profile_run,
    )

    instance = await create_instance(client)
    profile = await create_profile(client, str(instance["instance_id"]))
    result = await plan_sync_profile_run(
        SyncEnginePlanRequest(
            sync_profile_id=str(profile["sync_profile_id"]), requested_by="tester"
        )
    )

    assert result.status == "planned"
    assert result.dry_run is True
    assert result.package_id == "asiainfo.tda"
    assert result.instance_id == instance["instance_id"]
    assert result.capability == "alert.search"
    assert result.run_id and result.run_id.startswith("intrun_")
    assert result.request_summary["dry_run"] is True
    assert result.request_summary["params"] == {"region": "cn", "limit": 10}
    assert "raw" not in json.dumps(result.plan_summary).lower()

    run_response = await client.get(f"/api/security/integrations/runs/{result.run_id}")
    run = run_response.json()
    assert run["status"] == "planned"
    assert run["run_type"] == "sync_profile_plan"
    assert run["sync_profile_id"] == profile["sync_profile_id"]
    assert "secret" not in json.dumps(run["request_summary"]).lower()

    unchanged = (
        await client.get(
            f"/api/security/integrations/sync-profiles/{profile['sync_profile_id']}"
        )
    ).json()
    assert unchanged["last_run_id"] is None


@pytest.mark.asyncio
async def test_api_post_plan_success_and_params_override(client: AsyncClient) -> None:
    instance = await create_instance(client)
    profile = await create_profile(
        client, str(instance["instance_id"]), params={"limit": 10, "severity": "high"}
    )
    response = await plan_api(
        client,
        {
            "sync_profile_id": profile["sync_profile_id"],
            "params_override": {"limit": 5},
            "dry_run": False,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "planned"
    assert body["dry_run"] is True
    assert body["request_summary"]["dry_run"] is True
    assert body["request_summary"]["params"]["limit"] == 5
    assert body["request_summary"]["params"]["severity"] == "high"


@pytest.mark.asyncio
async def test_unknown_sync_profile_returns_404(client: AsyncClient) -> None:
    response = await plan_api(client, {"sync_profile_id": "syncprof_missing"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_missing_instance_returns_400(client: AsyncClient) -> None:
    from flocks.security.integrations.sync_profile_store import (
        default_sync_profile_store,
    )
    from flocks.security.integrations.sync_profiles import SyncProfile
    from flocks.storage.storage import Storage

    profile = SyncProfile(
        sync_profile_id="syncprof_orphan",
        display_name="Orphan",
        instance_id="intinst_missing",
        package_id="asiainfo.tda",
        capability="alert.search",
    )
    await Storage.set(
        "security/sync_profiles/syncprof_orphan", profile, "security.sync_profiles"
    )
    assert await default_sync_profile_store.get_profile("syncprof_orphan")
    response = await plan_api(client, {"sync_profile_id": "syncprof_orphan"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_unknown_and_destructive_capability_return_400(
    client: AsyncClient,
) -> None:
    from flocks.security.integrations.sync_profiles import SyncProfile
    from flocks.storage.storage import Storage

    instance = await create_instance(client)
    for sync_profile_id, capability in (
        ("syncprof_unknowncap", "missing.search"),
        ("syncprof_destructive", "ip.block"),
    ):
        await Storage.set(
            f"security/sync_profiles/{sync_profile_id}",
            SyncProfile(
                sync_profile_id=sync_profile_id,
                display_name="Bad",
                instance_id=str(instance["instance_id"]),
                package_id="asiainfo.tda",
                capability=capability,
            ),
            "security.sync_profiles",
        )
        response = await plan_api(client, {"sync_profile_id": sync_profile_id})
        assert response.status_code == 400, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [{"api_key": "x"}, {"query": "Bearer abcdef"}])
async def test_params_override_secret_like_key_or_value_returns_400(
    client: AsyncClient, override: dict[str, object]
) -> None:
    instance = await create_instance(client)
    profile = await create_profile(client, str(instance["instance_id"]))
    response = await plan_api(
        client,
        {"sync_profile_id": profile["sync_profile_id"], "params_override": override},
    )
    assert response.status_code == 400
    assert "abcdef" not in response.text


@pytest.mark.asyncio
async def test_no_connector_http_credential_evidence_or_security_object_side_effects(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", forbidden)
    monkeypatch.setattr(
        "flocks.security.connectors.mingyu_apt.MingyuAptClient", forbidden
    )
    monkeypatch.setattr(
        "flocks.security.integrations.credential_store.resolve_credential_profile_ref",
        forbidden,
    )
    monkeypatch.setattr(
        "flocks.security.integrations.evidence_dispatcher.dispatch_evidence_events",
        forbidden,
    )
    monkeypatch.setattr(socket.socket, "connect", forbidden)

    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    instance = await create_instance(client, credential_profile_id="credprof_ref")
    profile = await create_profile(client, str(instance["instance_id"]))
    response = await plan_api(client, {"sync_profile_id": profile["sync_profile_id"]})

    assert response.status_code == 200, response.text
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (
        (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    )
    assert (
        (await client.get("/api/security/incidents")).json() == before_incidents == []
    )


def test_init_exports_are_preserved() -> None:
    import flocks.security.integrations as integrations

    for name in (
        "SyncProfile",
        "IntegrationRun",
        "IntegrationCapabilityRuntime",
        "EvidenceDispatchRequest",
        "CredentialProfile",
        "IntegrationInstance",
        "MappingRule",
        "SyncEnginePlanRequest",
        "SyncEnginePlanResult",
        "plan_sync_profile_run",
    ):
        assert hasattr(integrations, name)
