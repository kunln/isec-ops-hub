from __future__ import annotations

import os

import pytest

os.environ["HOME"] = "/tmp/flocks-cli-commercial-home"

from flocks.cli.commands.commercial import allow_host_local, issue_temp_license_local
from flocks.commercial.features import get_feature_state
from flocks.commercial.store import default_store
from flocks.config.config import Config
from flocks.storage.storage import Storage


@pytest.fixture(autouse=True)
async def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Config.clear_cache()
    Storage._db_path = None
    Storage._initialized = False
    Storage._init_pid = None
    yield
    await Storage.shutdown()
    Storage._db_path = None
    Storage._initialized = False
    Storage._init_pid = None
    Config.clear_cache()


@pytest.mark.asyncio
async def test_issue_temp_license_local_writes_active_commercial_license():
    license_info = await issue_temp_license_local(
        days=7,
        licensed_to="Acme Security",
        license_id="TEMP-COMMERCIAL-ACME",
    )

    assert license_info.status == "active"
    assert license_info.edition == "commercial"
    assert license_info.licensed_to == "Acme Security"
    assert license_info.license_id == "TEMP-COMMERCIAL-ACME"
    assert license_info.features == ["*"]

    await Storage.init()
    stored_license = await default_store.get_license()
    feature_state = await get_feature_state()
    events = await default_store.list_audit_events()

    assert stored_license.license_id == "TEMP-COMMERCIAL-ACME"
    assert feature_state.flags["connectivity"].enabled is True
    assert events[0].action == "commercial.license.issue_temp"


@pytest.mark.asyncio
async def test_allow_host_local_enables_outbound_and_normalizes_url_host():
    connectivity = await allow_host_local("https://api.minimax.chat/v1")

    assert connectivity.outbound_enabled is True
    assert connectivity.allowed_hosts == ["api.minimax.chat"]

    await allow_host_local("API.MINIMAX.CHAT")
    await allow_host_local("*.example.com", enable_outbound=False)

    await Storage.init()
    stored_connectivity = await default_store.get_connectivity()
    events = await default_store.list_audit_events()

    assert stored_connectivity.outbound_enabled is True
    assert stored_connectivity.allowed_hosts == ["*.example.com", "api.minimax.chat"]
    assert events[0].action == "commercial.connectivity.allow_host"
