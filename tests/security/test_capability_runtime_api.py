"""API tests for Capability Runtime dry-run planning."""

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
            id="admin-user",
            username="admin-user",
            role="admin",
            status="active",
            must_reset_password=False,
        )
        return await call_next(request)

    app.include_router(security_router, prefix="/api/security")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests()


async def create_instance(client: AsyncClient, **extra: object) -> dict[str, object]:
    payload = {"package_id": "asiainfo.tda", "display_name": "TDA", "base_url": "https://tda.example.test"}
    payload.update(extra)
    response = await client.post("/api/security/integrations/instances", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


async def plan(client: AsyncClient, payload: dict[str, object]):
    return await client.post("/api/security/integrations/capability-runtime/plan", json=payload)


@pytest.mark.asyncio
async def test_package_level_dry_run_plan_success(client: AsyncClient) -> None:
    response = await plan(client, {"package_id": "asiainfo.tda", "capability": "alert.search", "params": {"limit": 5}})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "planned"
    assert body["package_id"] == "asiainfo.tda"
    assert body["capability"] == "alert.search"
    assert body["dry_run"] if "dry_run" in body else body["request_summary"]["dry_run"] is True
    assert body["request_summary"]["params"] == {"limit": 5}
    assert body["capability_summary"]["package_id"] == "asiainfo.tda"
    assert body["safety_summary"]["credential_access"] == "none"


@pytest.mark.asyncio
async def test_instance_level_dry_run_plan_success_without_resolving_credentials(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    instance = await create_instance(client, credential_profile_id="cred-profile-secret-ref", metadata={"region": "cn"})

    def fail_resolve(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Credential Profile secret_ref must not be resolved")

    monkeypatch.setattr("flocks.security.integrations.credential_store.resolve_credential_profile_ref", fail_resolve)
    response = await plan(client, {"instance_id": instance["instance_id"], "capability": "alert.search"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["package_id"] == "asiainfo.tda"
    assert body["request_summary"]["params"] == {"region": "cn"}
    assert "cred-profile-secret-ref" not in json.dumps(body)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "status_code"),
    [
        ({"package_id": "unknown.package", "capability": "alert.search"}, 400),
        ({"package_id": "asiainfo.tda", "capability": "unknown.search"}, 400),
        ({"instance_id": "missing-instance", "capability": "alert.search"}, 404),
    ],
)
async def test_validation_errors(client: AsyncClient, payload: dict[str, object], status_code: int) -> None:
    response = await plan(client, payload)
    assert response.status_code == status_code


@pytest.mark.asyncio
async def test_dry_run_false_is_forced_to_true(client: AsyncClient) -> None:
    response = await plan(client, {"package_id": "asiainfo.tda", "capability": "alert.search", "dry_run": False})
    assert response.status_code == 200, response.text
    assert response.json()["request_summary"]["dry_run"] is True


@pytest.mark.asyncio
async def test_secret_like_params_and_nested_values_are_sanitized(client: AsyncClient) -> None:
    response = await plan(
        client,
        {
            "package_id": "asiainfo.tda",
            "capability": "alert.search",
            "params": {
                "api_key": "plain-api-key",
                "secret": "plain-secret",
                "token": "plain-token",
                "password": "plain-password",
                "safe": {"nested": "Bearer nested-token", "ok": "visible"},
            },
        },
    )

    assert response.status_code == 200, response.text
    serialized = json.dumps(response.json())
    for forbidden in ("plain-api-key", "plain-secret", "plain-token", "plain-password", "Bearer nested-token"):
        assert forbidden not in serialized
    assert "visible" in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.asyncio
async def test_plan_has_no_runtime_side_effects(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connector(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("connector/vendor API must not be called")

    def fail_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("HTTP/network must not be called")

    monkeypatch.setattr("flocks.security.connectors.tda.TdaClient", fail_connector)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAptClient", fail_connector)
    monkeypatch.setattr(socket.socket, "connect", fail_socket)

    before_alerts = (await client.get("/api/security/alerts")).json()
    before_cases = (await client.get("/api/security/analysis-cases")).json()
    before_incidents = (await client.get("/api/security/incidents")).json()

    response = await plan(client, {"package_id": "asiainfo.tda", "capability": "alert.search"})

    assert response.status_code == 200, response.text
    assert (await client.get("/api/security/alerts")).json() == before_alerts == []
    assert (await client.get("/api/security/analysis-cases")).json() == before_cases == []
    assert (await client.get("/api/security/incidents")).json() == before_incidents == []


@pytest.mark.asyncio
async def test_destructive_capability_is_rejected(client: AsyncClient) -> None:
    response = await plan(client, {"package_id": "asiainfo.tda", "capability": "ip.block"})
    assert response.status_code == 400
    assert "Destructive capability" in response.text
