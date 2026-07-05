import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from flocks.tool.registry import ToolContext
from flocks.tool.tool_loader import yaml_to_tool


PLUGIN_DIR = Path.cwd() / ".flocks/plugins/tools/device/dbappsecurity_mingyu_apt_v2_0_r77"
HANDLER_PATH = PLUGIN_DIR / "mingyu_apt.handler.py"


def _load_handler(module_name: str = "mingyu_apt_handler_test"):
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


def test_mingyu_apt_provider_yaml_loads_as_device_tool():
    yaml_path = PLUGIN_DIR / "mingyu_apt_health.yaml"
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    tool = yaml_to_tool(raw, yaml_path)

    assert tool.info.source == "device"
    assert tool.info.vendor == "安恒信息"
    assert tool.info.provider == "dbappsecurity_mingyu_apt_api_v2_0R77"
    assert getattr(tool, "_service_id") == "dbappsecurity_mingyu_apt_api"


@pytest.mark.asyncio
async def test_health_uses_apikey_header_and_openapi_about_path(monkeypatch):
    module = _load_handler("mingyu_apt_health_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(
            200,
            {
                "error_code": 200,
                "message": "success",
                "data": {"version": "2.0.77", "ServerBuildID": "server-1"},
            },
        )
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://apt.example.com",
            "apiKey": "token-1",
            "verify_ssl": False,
        },
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.health(_ctx())

    assert result.success is True
    assert result.output["version"] == "2.0.77"
    call = fake_session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://apt.example.com/openapi/about"
    assert call["kwargs"]["headers"]["apikey"] == "token-1"


@pytest.mark.asyncio
async def test_risk_list_defaults_to_all_flags_and_json_body(monkeypatch):
    module = _load_handler("mingyu_apt_risk_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(
            200,
            {
                "error_code": 200,
                "message": "成功",
                "data": {"total": 0, "data": []},
            },
        )
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://apt.example.com",
            "apiKey": "token-1",
            "verify_ssl": True,
        },
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.risk(
        _ctx(),
        action="list",
        begin="2026-06-01 00:00:00",
        end="2026-06-04 23:59:59",
    )

    assert result.success is True
    call = fake_session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://apt.example.com/openapi/risk/getList"
    body = call["kwargs"]["json"]
    assert body["begin"] == "2026-06-01 00:00:00"
    assert body["end"] == "2026-06-04 23:59:59"
    assert body["flags"] == [-1]
    assert body["offset"] == 0
    assert body["limit"] == 20


@pytest.mark.asyncio
async def test_risk_detail_validates_required_fields():
    module = _load_handler("mingyu_apt_validation_handler_test")

    result = await module.risk(_ctx(), action="detail", accessid="risk-1")

    assert result.success is False
    assert "poid" in result.error
