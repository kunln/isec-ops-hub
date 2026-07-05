from __future__ import annotations

import pytest
from httpx import AsyncClient


SERVICE_ID = "dbappsecurity_mingjian_vuln_scanner_api"
STORAGE_KEY = "dbappsecurity_mingjian_vuln_scanner_api_v5_0"


@pytest.mark.asyncio
async def test_mingjian_template_can_be_saved_and_listed_from_device_integration(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    """Covers the 8080 Device Integration data path:

    /api/provider/api-services template -> POST /api/devices -> GET /api/devices.
    """
    from flocks.config.config import Config
    from flocks.config import api_versioning
    from flocks.security import secrets as secrets_mod
    from flocks.storage.storage import Storage
    from flocks.tool.device.store import ensure_default_group
    from flocks.tool.registry import ToolRegistry

    home = tmp_path / "home"
    config_dir = tmp_path / "flocks_config"
    home.mkdir(exist_ok=True)
    config_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(config_dir))
    Config._global_config = None
    Config._cached_config = None
    secrets_mod._secret_manager = None
    api_versioning._reset_descriptor_cache()
    ToolRegistry._initialized = False

    # The shared server fixture initialises Storage before this route test
    # imports the device package in some orders. Re-run DDL registration against
    # the same temporary DB so device_groups/device_integrations exist.
    Storage._initialized = False
    await Storage.init(Storage.get_db_path())
    await ensure_default_group()
    assert Storage.get_db_path().is_relative_to(tmp_path)

    services_resp = await client.get("/api/provider/api-services")
    assert services_resp.status_code == 200, services_resp.text
    services = services_resp.json()
    template = next((item for item in services if item["id"] == STORAGE_KEY), None)
    assert template is not None
    assert template["integration_type"] == "device"
    assert template["vendor"] == "安恒信息"
    assert template["name"] == "明鉴漏洞扫描系统"

    create_resp = await client.post(
        "/api/devices",
        json={
            "name": "明鉴漏洞扫描系统",
            "storage_key": STORAGE_KEY,
            "enabled": True,
            "verify_ssl": False,
            "fields": {
                "base_url": "https://ras.example.com",
                "username": "api-user",
                "user_code": "1234567890abcdef1234567890abcdef",
            },
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    created = create_resp.json()
    assert created["storage_key"] == STORAGE_KEY
    assert created["service_id"] == SERVICE_ID
    assert created["fields"]["base_url"] == "https://ras.example.com"
    assert created["fields"]["username"] == "api-user"
    assert created["fields"]["user_code"] != "1234567890abcdef1234567890abcdef"
    assert created["fields_set"]["user_code"] is True

    list_resp = await client.get("/api/devices")
    assert list_resp.status_code == 200, list_resp.text
    listed = next((item for item in list_resp.json() if item["id"] == created["id"]), None)
    assert listed is not None
    assert listed["name"] == "明鉴漏洞扫描系统"
    assert listed["storage_key"] == STORAGE_KEY
    assert listed["service_id"] == SERVICE_ID
    assert listed["fields_set"]["user_code"] is True

    from flocks.config.config_writer import ConfigWriter

    raw_service = ConfigWriter.get_api_service_raw(STORAGE_KEY)
    assert raw_service is not None
    assert raw_service["enabled"] is True
