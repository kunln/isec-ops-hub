from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from flocks.commercial import policy as commercial_policy
from flocks.commercial.models import ConnectivityUpdate
from flocks.commercial.store import default_store
from flocks.storage.storage import Storage


@pytest.fixture
async def commercial_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


async def _enable_connectivity_license() -> None:
    await default_store.set_license({
        "status": "active",
        "edition": "enterprise",
        "license_id": "test-connectivity-license",
        "features": ["connectivity"],
    })


async def _enable_license_without_connectivity() -> None:
    await default_store.set_license({
        "status": "active",
        "edition": "community",
        "license_id": "test-non-connectivity-license",
        "features": ["branding"],
    })


@pytest.mark.asyncio
async def test_local_urls_are_not_treated_as_external_outbound(commercial_storage):
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    await commercial_policy.ensure_outbound_allowed(
        url="http://127.0.0.1:19000/health",
        purpose="local health probe",
    )


@pytest.mark.asyncio
async def test_private_network_urls_require_explicit_device_allowance(commercial_storage):
    await _enable_connectivity_license()
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    with pytest.raises(commercial_policy.CommercialPolicyError, match="private test"):
        await commercial_policy.ensure_outbound_allowed(
            url="https://192.168.31.182:443",
            purpose="private test",
        )

    await commercial_policy.ensure_outbound_allowed(
        url="https://192.168.31.182:443",
        purpose="device connectivity probe",
        allow_private_network=True,
    )


@pytest.mark.asyncio
async def test_allowed_hosts_requires_known_target_for_unknown_outbound(commercial_storage):
    await _enable_connectivity_license()
    await default_store.update_connectivity(
        ConnectivityUpdate(outbound_enabled=True, allowed_hosts=["api.example.com"])
    )

    with pytest.raises(commercial_policy.CommercialPolicyError, match="allowed_hosts"):
        await commercial_policy.ensure_outbound_allowed(
            purpose="package manager install",
            require_url_for_allowed_hosts=True,
        )


@pytest.mark.asyncio
async def test_allowed_hosts_rejects_unlisted_remote_host_and_records_audit(commercial_storage):
    await _enable_connectivity_license()
    await default_store.update_connectivity(
        ConnectivityUpdate(outbound_enabled=True, allowed_hosts=["api.example.com"])
    )

    with pytest.raises(commercial_policy.CommercialPolicyError, match="allowed_hosts"):
        await commercial_policy.ensure_outbound_allowed(
            url="https://updates.example.net/releases/latest",
            purpose="update check",
        )

    events = await default_store.list_audit_events()
    assert events[0].action == "commercial.outbound.denied"
    assert events[0].target == "https://updates.example.net/releases/latest"
    assert events[0].status == "denied"
    assert events[0].metadata["purpose"] == "update check"


@pytest.mark.asyncio
async def test_remote_mcp_connection_blocked_before_transport(commercial_storage, monkeypatch):
    from flocks.mcp.client import McpClient

    await _enable_connectivity_license()
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))
    client = McpClient(
        name="remote-demo",
        server_type="remote",
        url="https://mcp.example.com/mcp",
    )
    monkeypatch.setattr(
        client,
        "_connect_auto",
        AsyncMock(side_effect=AssertionError("remote transport should not start")),
    )

    with pytest.raises(commercial_policy.CommercialPolicyError, match="remote MCP connection"):
        await client._connect_remote(asyncio.get_running_loop().create_future())

    events = await default_store.list_audit_events()
    assert events[0].action == "commercial.outbound.denied"
    assert events[0].target == "https://mcp.example.com/mcp"


@pytest.mark.asyncio
async def test_mcp_package_install_blocked_before_subprocess(commercial_storage, monkeypatch):
    from flocks.mcp import installer

    await _enable_connectivity_license()
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))
    monkeypatch.setattr(
        installer,
        "_run_subprocess",
        AsyncMock(side_effect=AssertionError("package install subprocess should not run")),
    )
    entry = SimpleNamespace(
        id="demo",
        transport="local",
        install=SimpleNamespace(
            local_command=["npx", "-y", "@vendor/demo-mcp"],
            npx="@vendor/demo-mcp",
            pip=None,
        ),
    )

    with pytest.raises(commercial_policy.CommercialPolicyError, match="MCP npm package install"):
        await installer.preflight_install(entry)


@pytest.mark.asyncio
async def test_skill_url_download_blocked_before_http_client(commercial_storage):
    from flocks.skill.installer import SkillInstaller

    await _enable_connectivity_license()
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    result = await SkillInstaller.install_from_source("https://example.com/SKILL.md")

    assert result.success is False
    assert result.error is not None
    assert "skill URL download" in result.error


@pytest.mark.asyncio
async def test_skill_registry_search_records_policy_denial(commercial_storage):
    from flocks.cli.commands import skill as skill_command

    await _enable_connectivity_license()
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    results = await skill_command._search_clawhub("demo")

    assert results == []
    events = await default_store.list_audit_events()
    assert events[0].action == "commercial.outbound.denied"
    assert events[0].target == "https://clawhub.com/api/search"
    assert events[0].metadata["purpose"] == "skill registry search"


@pytest.mark.asyncio
async def test_webfetch_blocked_before_permission_prompt(commercial_storage):
    from flocks.tool.web.webfetch import webfetch_tool

    await _enable_connectivity_license()
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    class DummyContext:
        asked = False

        async def ask(self, *args, **kwargs):
            self.asked = True

    ctx = DummyContext()
    result = await webfetch_tool(ctx, "https://example.com")

    assert result.success is False
    assert "webfetch tool request" in (result.error or "")
    assert ctx.asked is False


@pytest.mark.asyncio
async def test_community_unlicensed_provider_credential_policy_allows_when_connectivity_disabled(commercial_storage):
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    decision = await commercial_policy.decide_outbound_allowed(
        url="https://api.minimax.io/v1/models",
        purpose="provider credential test: minimax",
    )

    assert decision.allowed is True
    assert decision.reason is None


@pytest.mark.asyncio
async def test_licensed_connectivity_enabled_rejects_unlisted_provider_host(commercial_storage):
    await _enable_connectivity_license()
    await default_store.update_connectivity(
        ConnectivityUpdate(outbound_enabled=True, allowed_hosts=["api.example.com"])
    )

    with pytest.raises(commercial_policy.CommercialPolicyError, match="allowed_hosts"):
        await commercial_policy.ensure_outbound_allowed(
            url="https://api.minimax.io/v1/models",
            purpose="provider credential test: minimax",
        )


@pytest.mark.asyncio
async def test_licensed_connectivity_disabled_feature_allows_outbound_policy(commercial_storage):
    await _enable_license_without_connectivity()
    await default_store.update_connectivity(
        ConnectivityUpdate(outbound_enabled=False, allowed_hosts=["api.example.com"])
    )

    await commercial_policy.ensure_outbound_allowed(
        url="https://api.minimax.io/v1/models",
        purpose="provider credential test: minimax",
    )


@pytest.mark.asyncio
async def test_community_security_connector_and_device_policy_purposes_allow(commercial_storage):
    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    for purpose, url in (
        ("security connector test: tda", "https://tda.example.com/ngtda/dashboard/system_resource_overview"),
        ("security connector ingest: mingyu-apt", "https://apt.example.com/openapi/risk"),
        ("device connectivity probe", "https://device.example.com/api/status"),
    ):
        decision = await commercial_policy.decide_outbound_allowed(url=url, purpose=purpose)
        assert decision.allowed is True
        assert decision.reason is None
