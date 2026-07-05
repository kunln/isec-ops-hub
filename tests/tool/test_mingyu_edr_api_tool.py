import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from flocks.tool.registry import ToolContext
from flocks.tool.tool_loader import yaml_to_tool


PLUGIN_DIR = Path.cwd() / ".flocks/plugins/tools/device/dbappsecurity_mingyu_edr_v2_0_17"
HANDLER_PATH = PLUGIN_DIR / "mingyu_edr.handler.py"


def _load_handler(module_name: str = "mingyu_edr_handler_test"):
    spec = importlib.util.spec_from_file_location(module_name, HANDLER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ctx() -> ToolContext:
    return ToolContext(session_id="test", message_id="test")


class _FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._payload = payload

    async def text(self):
        return json.dumps(self._payload, ensure_ascii=False)


class _FakeContextManager:
    def __init__(self, response: _FakeResponse):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return None


class _FakeSession:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return _FakeContextManager(self.response)


def test_mingyu_edr_provider_yaml_loads_as_device_tool():
    yaml_path = PLUGIN_DIR / "mingyu_edr_health.yaml"
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    tool = yaml_to_tool(raw, yaml_path)

    assert tool.info.source == "device"
    assert tool.info.vendor == "安恒信息"
    assert tool.info.provider == "dbappsecurity_edr_api_v2_0_17"
    assert getattr(tool, "_service_id") == "dbappsecurity_edr_api"


def test_mingyu_edr_customer_side_tools_exclude_write_export_and_disposal_paths():
    module = _load_handler("mingyu_edr_safety_handler_test")
    exposed_paths = set()
    for mapping_name in (
        "ASSET_ACTIONS",
        "SECURITY_ACTIONS",
        "POLICY_ACTIONS",
        "LOG_ACTIONS",
        "REPORT_ACTIONS",
        "INFO_SEARCH_ACTIONS",
        "RISK_BASELINE_ACTIONS",
    ):
        exposed_paths.update(getattr(module, mapping_name).values())

    forbidden_paths = {
        "/node/unbind",
        "/node/uninstall",
        "/node/setUninstallPsd",
        "/node/set_protect_status",
        "/node/batch_sys_shutdown",
        "/node/batch_sys_reboot",
        "/node/batch_client_reboots",
        "/node/batch_move_property",
        "/horse/scan/custom",
        "/horse/scan/stop",
        "/horse/scan/isolate",
        "/horse/scan/ignore",
        "/horse/scan/restore",
        "/horse/scan/ignoreCancel",
        "/horse/scan/delete",
        "/horse/scan/fix_items",
        "/horse/scan/set_scan_directorys",
        "/antivirus/scan/fast",
        "/antivirus/scan/full",
        "/antivirus/scan/custom",
        "/antivirus/scan/stop",
        "/antivirus/scan/virus_scan_setting_set",
        "/antivirus/virus/check",
        "/antivirus/virus/isolate",
        "/antivirus/isolation/restore_all",
        "/antivirus/isolation/del_backup_all",
        "/antivirus/trust/ignore",
        "/antivirus/trust/cancel_ignore",
        "/antivirus/fix_items",
        "/antivirus/isolation/restore",
        "/antivirus/isolation/del_backup",
        "/vulnerability/win/scanWindows",
        "/vulnerability/win/repairWindows",
        "/vulnerability/linux/scan",
        "/rule/template/remove",
        "/rule/template/download_url",
        "/rule/template/bind",
        "/rule/template/save",
        "/rule/template/default",
        "/rule/template/import",
        "/rule/microisolation/add",
        "/rule/microisolation/update",
        "/rule/microisolation/delete",
        "/log/exportCSV",
        "/operationlog/export_csv",
        "/info_search/process_stop",
        "/info_search/refresh",
        "/info_search/export",
        "/file_push/delete_item",
        "/file_push/push",
        "/task/delete_task",
        "/task/add_task",
        "/task/modify_task",
        "/traffic/portray/delete_template",
        "/traffic/portray/save_template",
        "/traffic/portray/delete_data",
        "/traffic/del_port",
        "/risk/node_assess",
        "/risk/ransom_assess",
        "/risk/mine_assess",
        "/risk/weak_assess",
        "/base_line/start_scan",
        "/base_line/del",
        "/base_line/save",
        "/admin/system/upgrade/server",
        "/admin/system/upgrade/offline_upgrade",
        "/admin/user/add",
        "/admin/user/update",
        "/admin/user/delete",
    }

    assert exposed_paths.isdisjoint(forbidden_paths)


@pytest.mark.asyncio
async def test_health_uses_cookie_and_minimal_asset_list_probe(monkeypatch):
    module = _load_handler("mingyu_edr_health_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(200, {"code": 0, "data": {"total": 1, "list": [{"name": "host-1"}]}})
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://edr.example.com",
            "session_cookie": "sid=abc",
            "verify_ssl": False,
        }
        if service_id == "dbappsecurity_edr_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.health(_ctx())

    assert result.success is True
    call = fake_session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://edr.example.com/node/list"
    assert call["kwargs"]["headers"]["Cookie"] == "sid=abc"
    assert call["kwargs"]["json"] == {"page": 1, "limit": 1}


@pytest.mark.asyncio
async def test_assets_respects_get_method_api_prefix_and_token_header(monkeypatch):
    module = _load_handler("mingyu_edr_assets_handler_test")
    fake_session = _FakeSession(_FakeResponse(200, {"code": 0, "data": {"rows": []}}))

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://edr.example.com",
            "auth_token": "token-1",
            "token_header": "X-Auth-Token",
            "api_prefix": "api",
            "read_method": "GET",
            "verify_ssl": True,
        }
        if service_id == "dbappsecurity_edr_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.assets(_ctx(), action="details", node_id="node-1", body={"id": "node-1"})

    assert result.success is True
    call = fake_session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://edr.example.com/api/node/details"
    assert call["kwargs"]["headers"]["X-Auth-Token"] == "token-1"
    assert call["kwargs"]["params"] == {"id": "node-1", "page": 1, "limit": 50, "node_id": "node-1"}


@pytest.mark.asyncio
async def test_missing_cookie_or_token_returns_actionable_error(monkeypatch):
    module = _load_handler("mingyu_edr_auth_validation_handler_test")

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {"base_url": "https://edr.example.com"} if service_id == "dbappsecurity_edr_api" else {},
    )

    result = await module.logs(_ctx(), action="protection_list")

    assert result.success is False
    assert "Cookie 或 Token 未配置" in result.error
