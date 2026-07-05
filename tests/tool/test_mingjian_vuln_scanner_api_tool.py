import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from flocks.tool.registry import ToolContext
from flocks.tool.tool_loader import yaml_to_tool


PLUGIN_DIR = Path.cwd() / ".flocks/plugins/tools/device/dbappsecurity_mingjian_vuln_scanner_v5_0"
HANDLER_PATH = PLUGIN_DIR / "mingjian_vuln_scanner.handler.py"


def _load_handler(module_name: str = "mingjian_vuln_scanner_handler_test"):
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
    def __init__(self, responses: list[_FakeResponse] | _FakeResponse):
        self.responses = responses if isinstance(responses, list) else [responses]
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        return _FakeContextManager(response)


def test_mingjian_vuln_scanner_provider_yaml_loads_as_device_tool():
    yaml_path = PLUGIN_DIR / "mingjian_vuln_scanner_health.yaml"
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    tool = yaml_to_tool(raw, yaml_path)

    assert tool.info.source == "device"
    assert tool.info.vendor == "安恒信息"
    assert tool.info.provider == "dbappsecurity_mingjian_vuln_scanner_api_v5_0"
    assert getattr(tool, "_service_id") == "dbappsecurity_mingjian_vuln_scanner_api"


def test_mingjian_vuln_scanner_yaml_tools_use_script_handlers():
    expected_functions = {
        "mingjian_vuln_scanner_assets.yaml": "assets",
        "mingjian_vuln_scanner_engines.yaml": "engines",
        "mingjian_vuln_scanner_health.yaml": "health",
        "mingjian_vuln_scanner_policies.yaml": "policies",
        "mingjian_vuln_scanner_results.yaml": "results",
        "mingjian_vuln_scanner_system.yaml": "system",
        "mingjian_vuln_scanner_tasks.yaml": "tasks",
    }
    for filename, function_name in expected_functions.items():
        yaml_path = PLUGIN_DIR / filename
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert raw["handler"]["type"] == "script"
        assert raw["handler"]["script_file"] == "mingjian_vuln_scanner.handler.py"
        assert raw["handler"]["function"] == function_name

        tool = yaml_to_tool(raw, yaml_path)
        assert getattr(tool, "_handler_type") == "script"


def test_mingjian_customer_side_tools_exclude_write_export_and_disposal_paths():
    module = _load_handler("mingjian_vuln_scanner_safety_handler_test")
    exposed_paths = {
        spec["path"]
        for mapping_name in (
            "ENGINE_ACTIONS",
            "TASK_ACTIONS",
            "RESULT_ACTIONS",
            "ASSET_ACTIONS",
            "POLICY_ACTIONS",
            "SYSTEM_ACTIONS",
        )
        for spec in getattr(module, mapping_name).values()
    }

    forbidden_paths = {
        "/api/normal/task/create",
        "/api/normal/task/createFromExistAsset",
        "/api/normal/task/start",
        "/api/normal/task/suspend",
        "/api/normal/task/resume",
        "/api/normal/task/delete",
        "/api/normal/task/stop",
        "/api/normal/asset/createAssets",
        "/api/normal/asset/updateAsset",
        "/api/normal/asset/delete",
        "/api/v2/normal/asset/delete",
        "/api/normal/asset/checkConnection",
        "/api/normal/task/doReport",
        "/api/normal/lic/export",
        "/api/normal/lic/import",
        "/api/normal/system/update-syslog",
        "/api/normal/system/dictionary",
        "/api/normal/dict/list",
        "/api/normal/dict/add",
        "/api/normal/dict/view",
        "/api/normal/dict/save",
        "/api/normal/dict/delete",
    }

    assert exposed_paths.isdisjoint(forbidden_paths)


@pytest.mark.asyncio
async def test_health_gets_token_then_calls_v5_engines_with_raw_authorization_header(monkeypatch):
    module = _load_handler("mingjian_vuln_scanner_health_handler_test")
    fake_session = _FakeSession(
        [
            _FakeResponse(200, {"code": 200, "data": {"Authorization": "tok-1"}}),
            _FakeResponse(200, {"code": 200, "data": {"engines": [{"name": "engine-1"}]}}),
        ]
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://ras.example.com",
            "username": "api-user",
            "user_code": "md5-32",
            "verify_ssl": False,
        }
        if service_id == "dbappsecurity_mingjian_vuln_scanner_api"
        else {"enabled": True},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.health(_ctx())

    assert result.success is True
    assert result.output["engines"][0]["name"] == "engine-1"

    token_call = fake_session.calls[0]
    assert token_call["method"] == "GET"
    assert token_call["url"] == "https://ras.example.com/api/normal/token"
    assert token_call["kwargs"]["params"] == {"userName": "api-user", "userCode": "md5-32"}

    engine_call = fake_session.calls[1]
    assert engine_call["method"] == "GET"
    assert engine_call["url"] == "https://ras.example.com/api/normal/getEngines/v5"
    assert engine_call["kwargs"]["headers"]["Authorization"] == "tok-1"
    assert not engine_call["kwargs"]["headers"]["Authorization"].startswith("Bearer ")


@pytest.mark.asyncio
async def test_tasks_list_v2_uses_query_params_after_token(monkeypatch):
    module = _load_handler("mingjian_vuln_scanner_tasks_handler_test")
    fake_session = _FakeSession(
        [
            _FakeResponse(200, {"code": 200, "data": {"Authorization": "tok-2"}}),
            _FakeResponse(200, {"code": 200, "data": {"rows": []}}),
        ]
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://ras.example.com",
            "username": "api-user",
            "user_code": "md5-32",
            "api_prefix": "proxy",
            "verify_ssl": True,
        }
        if service_id == "dbappsecurity_mingjian_vuln_scanner_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.tasks(
        _ctx(),
        action="list_v2",
        module=0,
        offset=10,
        limit=500,
        state=2,
        start_time="2026-06-01 00:00:00",
        end_time="2026-06-08 23:59:59",
    )

    assert result.success is True
    task_call = fake_session.calls[1]
    assert task_call["method"] == "GET"
    assert task_call["url"] == "https://ras.example.com/proxy/api/normal/task/list/V2"
    assert task_call["kwargs"]["params"] == {
        "module": 0,
        "offset": 10,
        "limit": 100,
        "state": 2,
        "startTime": "2026-06-01 00:00:00",
        "endTime": "2026-06-08 23:59:59",
    }


@pytest.mark.asyncio
async def test_asset_sync_aggregates_supported_modules(monkeypatch):
    module = _load_handler("mingjian_vuln_scanner_asset_sync_handler_test")
    fake_session = _FakeSession(
        [
            _FakeResponse(200, {"code": 200, "data": {"Authorization": "tok-asset-0"}}),
            _FakeResponse(200, {"code": 200, "data": {"list": [{"id": "asset-0", "ip": "10.0.0.1"}]}}),
            _FakeResponse(200, {"code": 200, "data": {"Authorization": "tok-asset-8"}}),
            _FakeResponse(200, {"code": 200, "data": {"rows": [{"id": "asset-8", "ip": "10.0.0.8"}]}}),
        ]
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://ras.example.com",
            "username": "api-user",
            "user_code": "md5-32",
            "verify_ssl": False,
        }
        if service_id == "dbappsecurity_mingjian_vuln_scanner_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.assets(_ctx(), action="sync", modules=[0, 8], limit=10)

    assert result.success is True
    assert [item["id"] for item in result.output["items"]] == ["asset-0", "asset-8"]
    assert [item["mingjian_module"] for item in result.output["items"]] == [0, 8]
    assert result.output["modules"] == [
        {"module": 0, "name": "website", "status": "ok", "count": 1},
        {"module": 8, "name": "host", "status": "ok", "count": 1},
    ]
    assert fake_session.calls[1]["kwargs"]["params"] == {"module": 0, "offset": 0, "limit": 10}
    assert fake_session.calls[3]["kwargs"]["params"] == {"module": 8, "offset": 0, "limit": 10}


@pytest.mark.asyncio
async def test_vulnerability_sync_lists_tasks_then_fetches_task_results(monkeypatch):
    module = _load_handler("mingjian_vuln_scanner_vulnerability_sync_handler_test")
    fake_session = _FakeSession(
        [
            _FakeResponse(200, {"code": 200, "data": {"Authorization": "tok-task"}}),
            _FakeResponse(
                200,
                {"code": 200, "data": {"rows": [{"taskId": "task-1", "taskName": "weekly scan"}]}},
            ),
            _FakeResponse(200, {"code": 200, "data": {"Authorization": "tok-result"}}),
            _FakeResponse(
                200,
                {"code": 200, "data": {"vulList": [{"id": "vul-1", "riskName": "OpenSSL vuln"}]}},
            ),
        ]
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://ras.example.com",
            "username": "api-user",
            "user_code": "md5-32",
            "verify_ssl": False,
        }
        if service_id == "dbappsecurity_mingjian_vuln_scanner_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.results(_ctx(), action="sync", modules=[0], task_limit=1, limit=10)

    assert result.success is True
    assert result.output["items"] == [
        {
            "id": "vul-1",
            "riskName": "OpenSSL vuln",
            "taskId": "task-1",
            "taskName": "weekly scan",
            "mingjian_module": 0,
            "mingjian_module_name": "website",
        }
    ]
    assert fake_session.calls[1]["kwargs"]["params"] == {"module": 0, "offset": 0, "limit": 1}
    assert fake_session.calls[3]["kwargs"]["params"] == {"module": 0, "offset": 0, "limit": 10, "taskId": "task-1"}


@pytest.mark.asyncio
async def test_missing_username_or_user_code_returns_actionable_error(monkeypatch):
    module = _load_handler("mingjian_vuln_scanner_auth_validation_handler_test")

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {"base_url": "https://ras.example.com"} if service_id == "dbappsecurity_mingjian_vuln_scanner_api" else {},
    )

    result = await module.engines(_ctx())

    assert result.success is False
    assert "userName 或 userCode 未配置" in result.error
