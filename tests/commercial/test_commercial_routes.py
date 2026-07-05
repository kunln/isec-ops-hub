from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.auth.context import AuthUser
from flocks.storage.storage import Storage


def _make_app(role: str | None = None):
    from fastapi import FastAPI, Request
    from flocks.server.routes.commercial import router as commercial_router

    app = FastAPI()

    if role:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.auth_user = AuthUser(
                id=f"{role}-user",
                username=f"{role}-user",
                role=role,
                status="active",
                must_reset_password=False,
            )
            return await call_next(request)

    app.include_router(commercial_router, prefix="/api/commercial")
    return app


async def _init_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")


async def _clear_storage():
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


@pytest.fixture
async def public_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    await _init_storage(tmp_path, monkeypatch)
    transport = ASGITransport(app=_make_app())
    async with AsyncClient(transport=transport, base_url="http://test", headers={"User-Agent": "pytest"}) as ac:
        yield ac
    await _clear_storage()


@pytest.fixture
async def admin_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    await _init_storage(tmp_path, monkeypatch)
    transport = ASGITransport(app=_make_app("admin"))
    async with AsyncClient(transport=transport, base_url="http://test", headers={"User-Agent": "pytest"}) as ac:
        yield ac
    await _clear_storage()


@pytest.fixture
async def member_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    await _init_storage(tmp_path, monkeypatch)
    transport = ASGITransport(app=_make_app("member"))
    async with AsyncClient(transport=transport, base_url="http://test", headers={"User-Agent": "pytest"}) as ac:
        yield ac
    await _clear_storage()


async def _enable_license_features(client: AsyncClient, *features: str):
    response = await client.post(
        "/api/commercial/license/import",
        json={
            "manifest": {
                "status": "active",
                "edition": "community",
                "license_id": "test-license",
                "features": list(features),
            }
        },
    )
    assert response.status_code == 200
    return response


@pytest.mark.asyncio
async def test_public_branding_and_admin_boundary(public_client: AsyncClient):
    branding = await public_client.get("/api/commercial/branding")
    assert branding.status_code == 200
    assert branding.json()["product_name"]

    license_info = await public_client.get("/api/commercial/license")
    assert license_info.status_code == 401


@pytest.mark.asyncio
async def test_admin_routes_branding_policy_and_audit(admin_client: AsyncClient):
    await _enable_license_features(admin_client, "branding")

    patched = await admin_client.patch("/api/commercial/branding", json={"product_name": "Acme Console"})
    assert patched.status_code == 200
    assert patched.json()["product_name"] == "Acme Console"

    telemetry = await admin_client.get("/api/commercial/telemetry")
    assert telemetry.status_code == 200
    assert telemetry.json()["enabled"] is False
    assert telemetry.json()["include_security_data"] is False

    audit = await admin_client.get("/api/commercial/audit")
    assert audit.status_code == 200
    events = audit.json()
    assert events[0]["action"] == "commercial.branding.update"
    assert events[0]["actor_role"] == "admin"
    assert events[0]["status"] == "success"


@pytest.mark.asyncio
async def test_member_write_denied_and_audited(member_client: AsyncClient):
    rejected = await member_client.patch("/api/commercial/branding", json={"product_name": "Blocked"})
    assert rejected.status_code == 403

    from flocks.commercial.store import default_store

    events = await default_store.list_audit_events()
    assert events[0].action == "commercial.branding.update"
    assert events[0].status == "denied"
    assert events[0].actor_role == "member"


@pytest.mark.asyncio
async def test_tool_package_requires_permission_ack(admin_client: AsyncClient):
    await _enable_license_features(admin_client, "packages")

    manifest = {
        "id": "tool-one",
        "type": "tool",
        "name": "Tool One",
        "version": "1.0.0",
        "permissions": ["bash", "network"],
        "hash": "sha256:abc123",
        "signature": "sig-local",
    }

    rejected = await admin_client.post(
        "/api/commercial/packages/install",
        json={"manifest": manifest, "permissions_acknowledged": False, "risk_acknowledged": True},
    )
    assert rejected.status_code == 400

    accepted = await admin_client.post(
        "/api/commercial/packages/install",
        json={"manifest": manifest, "permissions_acknowledged": True, "risk_acknowledged": True},
    )
    assert accepted.status_code == 200
    assert accepted.json()["id"] == "tool-one"
    assert accepted.json()["risk_level"] == "high"
    assert accepted.json()["permissions"][0]["id"] == "bash"

    audit = await admin_client.get("/api/commercial/audit")
    statuses = [event["status"] for event in audit.json() if event["action"] == "commercial.package.install"]
    assert statuses == ["success", "denied"]


@pytest.mark.asyncio
async def test_high_risk_package_requires_hash_signature_and_risk_ack(admin_client: AsyncClient):
    await _enable_license_features(admin_client, "packages")

    manifest = {
        "id": "runtime-one",
        "type": "runtime",
        "name": "Runtime One",
        "version": "1.0.0",
    }

    missing_integrity = await admin_client.post(
        "/api/commercial/packages/install",
        json={"manifest": manifest, "risk_acknowledged": True, "permissions_acknowledged": True},
    )
    assert missing_integrity.status_code == 400
    assert "hash" in missing_integrity.json()["detail"]
    assert "signature" in missing_integrity.json()["detail"]

    missing_ack = await admin_client.post(
        "/api/commercial/packages/install",
        json={
            "manifest": {**manifest, "hash": "sha256:runtime", "signature": "sig-runtime"},
            "permissions_acknowledged": True,
        },
    )
    assert missing_ack.status_code == 400
    assert "assessment" in missing_ack.json()["detail"]


@pytest.mark.asyncio
async def test_unsigned_high_risk_package_requires_non_signature_policy_ack(admin_client: AsyncClient):
    await _enable_license_features(admin_client, "packages")

    policy = await admin_client.patch("/api/commercial/update-policy", json={"signature_required": False})
    assert policy.status_code == 200

    manifest = {
        "id": "tool-unsigned",
        "type": "tool",
        "name": "Unsigned Tool",
        "version": "1.0.0",
        "permissions": [{"id": "bash", "risk": "high", "scope": "local execution"}],
        "hash": "sha256:unsigned",
    }

    rejected = await admin_client.post(
        "/api/commercial/packages/install",
        json={"manifest": manifest, "permissions_acknowledged": True, "risk_acknowledged": True},
    )
    assert rejected.status_code == 400
    assert "non-signature policy" in rejected.json()["detail"]

    accepted = await admin_client.post(
        "/api/commercial/packages/install",
        json={
            "manifest": manifest,
            "permissions_acknowledged": True,
            "risk_acknowledged": True,
            "signature_policy_acknowledged": True,
        },
    )
    assert accepted.status_code == 200
    assert accepted.json()["risk_level"] == "high"


@pytest.mark.asyncio
async def test_offline_import_policy_blocks_local_package_install(admin_client: AsyncClient):
    await _enable_license_features(admin_client, "packages")

    policy = await admin_client.patch("/api/commercial/update-policy", json={"offline_package_import": False})
    assert policy.status_code == 200

    rejected = await admin_client.post(
        "/api/commercial/packages/install",
        json={
            "manifest": {
                "id": "skill-local",
                "type": "skill",
                "name": "Local Skill",
                "version": "1.0.0",
            },
        },
    )
    assert rejected.status_code == 400
    assert "offline package import is disabled" in rejected.json()["detail"]


@pytest.mark.asyncio
async def test_license_features_drive_feature_flags(admin_client: AsyncClient):
    feature_state = await admin_client.get("/api/commercial/feature-flags")
    assert feature_state.status_code == 200
    flags = feature_state.json()["flags"]
    assert flags["packages"]["enabled"] is False
    assert flags["telemetry"]["enabled"] is False
    assert flags["audit"]["enabled"] is True

    imported = await _enable_license_features(
        admin_client,
        "commercial-packages",
        "commercial.telemetry",
        "telemetry-security-data",
    )
    assert imported.json()["features"] == ["packages", "telemetry", "telemetry.security_data"]

    feature_state = await admin_client.get("/api/commercial/feature-flags")
    flags = feature_state.json()["flags"]
    assert flags["packages"]["enabled"] is True
    assert flags["telemetry"]["enabled"] is True
    assert flags["telemetry.security_data"]["enabled"] is True
    assert flags["connectivity"]["enabled"] is False


@pytest.mark.asyncio
async def test_package_install_requires_license_feature(admin_client: AsyncClient):
    manifest = {
        "id": "skill-locked",
        "type": "skill",
        "name": "Locked Skill",
        "version": "1.0.0",
    }
    rejected = await admin_client.post("/api/commercial/packages/install", json={"manifest": manifest})
    assert rejected.status_code == 403
    assert "packages" in rejected.json()["detail"]

    await _enable_license_features(admin_client, "packages")
    accepted = await admin_client.post("/api/commercial/packages/install", json={"manifest": manifest})
    assert accepted.status_code == 200
    assert accepted.json()["id"] == "skill-locked"


@pytest.mark.asyncio
async def test_license_reconcile_disables_dependent_toggles(admin_client: AsyncClient):
    await _enable_license_features(
        admin_client,
        "telemetry",
        "telemetry.security_data",
        "connectivity",
        "updates",
    )

    telemetry = await admin_client.patch(
        "/api/commercial/telemetry",
        json={
            "enabled": True,
            "mode": "support",
            "include_logs": True,
            "include_metrics": True,
            "include_security_data": True,
        },
    )
    assert telemetry.status_code == 200

    connectivity = await admin_client.patch("/api/commercial/connectivity", json={"outbound_enabled": True})
    assert connectivity.status_code == 200

    update_policy = await admin_client.patch("/api/commercial/update-policy", json={"auto_check": True, "auto_install": True})
    assert update_policy.status_code == 200

    response = await admin_client.post(
        "/api/commercial/license/import",
        json={"manifest": {"status": "active", "edition": "community", "features": []}},
    )
    assert response.status_code == 200

    telemetry = await admin_client.get("/api/commercial/telemetry")
    assert telemetry.json()["enabled"] is False
    assert telemetry.json()["mode"] == "off"
    assert telemetry.json()["include_security_data"] is False

    connectivity = await admin_client.get("/api/commercial/connectivity")
    assert connectivity.json()["outbound_enabled"] is False

    update_policy = await admin_client.get("/api/commercial/update-policy")
    assert update_policy.json()["auto_check"] is False
    assert update_policy.json()["auto_install"] is False
