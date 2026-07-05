import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from flocks.tool.registry import ToolContext
from flocks.tool.tool_loader import yaml_to_tool


PLUGIN_DIR = Path.cwd() / ".flocks/plugins/tools/device/asiainfo_xinwei_tda_v7_0"
HANDLER_PATH = PLUGIN_DIR / "asiainfo_tda.handler.py"


def _load_handler(module_name: str = "asiainfo_tda_handler_test"):
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


def test_asiainfo_tda_provider_yaml_loads_as_device_tool():
    yaml_path = PLUGIN_DIR / "asiainfo_tda_health.yaml"
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    tool = yaml_to_tool(raw, yaml_path)

    assert tool.info.source == "device"
    assert tool.info.vendor == "亚信安全"
    assert tool.info.provider == "asiainfo_tda_api_v7_0"
    assert getattr(tool, "_service_id") == "asiainfo_tda_api"


def test_tda_customer_side_tools_exclude_write_download_and_delete_endpoints():
    yaml_names = {
        yaml.safe_load(path.read_text(encoding="utf-8"))["name"]
        for path in PLUGIN_DIR.glob("*.yaml")
        if not path.name.startswith("_")
    }

    assert yaml_names == {
        "asiainfo_tda_health",
        "asiainfo_tda_assets",
        "asiainfo_tda_alerts",
        "asiainfo_tda_raw_events",
        "asiainfo_tda_asset_risks",
        "asiainfo_tda_attackers",
        "asiainfo_tda_sandbox_results",
        "asiainfo_tda_system_resource",
        "asiainfo_tda_alarm_pcap_detail",
        "asiainfo_tda_ioc",
    }
    joined = " ".join(sorted(yaml_names))
    for unsafe_token in ("download", "export", "virus", "add", "delete"):
        assert unsafe_token not in joined


@pytest.mark.asyncio
async def test_health_uses_signed_system_resource_probe(monkeypatch):
    module = _load_handler("asiainfo_tda_health_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(
            200,
            {
                "message": "",
                "res": True,
                "data": {"cpu": {"average": 7}, "memory": {"percent": 42}},
            },
        )
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://tda.example.com",
            "apiKey": "key-1",
            "secret": "secret-1",
            "verify_ssl": False,
        },
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())
    monkeypatch.setattr(module.time, "time", lambda: 1751532923)

    result = await module.health(_ctx())

    assert result.success is True
    assert result.output["connected"] is True
    assert result.output["cpu_average"] == 7
    assert result.output["memory_percent"] == 42
    call = fake_session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://tda.example.com/ngtda/dashboard/system_resource_overview"
    params = call["kwargs"]["params"]
    assert params["api_key"] == "key-1"
    assert params["auth_timestamp"] == "1751532923"
    assert params["sign"] == module._auth_params("key-1", "secret-1", {"signature_mode": "hex_digest"})["sign"]


@pytest.mark.asyncio
async def test_assets_use_2025_signed_assetlist_body(monkeypatch):
    module = _load_handler("asiainfo_tda_assets_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(
            200,
            {
                "message": "",
                "res": True,
                "data": {"result": [{"asset_ip": "10.0.0.1", "asset_name": "host-a"}], "total": 1},
            },
        )
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://tda.example.com",
            "apiKey": "key-1",
            "secret": "secret-1",
            "verify_ssl": False,
        },
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())
    monkeypatch.setattr(module.time, "time", lambda: 1751532923)

    result = await module.assets(_ctx(), time_type=5, time_limit="1735747200,1735833599", asset_ip="10.0.0.1")

    assert result.success is True
    call = fake_session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://tda.example.com/ngtda/asset/assetlist"
    assert call["kwargs"]["json"] == {
        "time_type": 5,
        "time_limit": "1735747200,1735833599",
        "asset_ip": {"value": "10.0.0.1", "op": "default"},
        "order_key": "active_time",
        "order_direction": 0,
        "page": 1,
        "limit": 100,
    }
    assert call["kwargs"]["params"]["api_key"] == "key-1"


@pytest.mark.asyncio
async def test_ioc_query_uses_get_params(monkeypatch):
    module = _load_handler("asiainfo_tda_ioc_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(
            200,
            {
                "message": "ok",
                "res": True,
                "data": [{"sid": "250000001", "content": "68CCC2EFC570A8CE52AD7A6EEE30ADBC"}],
            },
        )
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "tda.example.com",
            "apiKey": "key-1",
            "secret": "secret-1",
            "verify_ssl": True,
        },
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.ioc(_ctx(), sid="250000001", content="68CCC2EFC570A8CE52AD7A6EEE30ADBC")

    assert result.success is True
    call = fake_session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://tda.example.com/ngtda/rule/cus_ioc_md5_list"
    assert call["kwargs"]["params"]["sid"] == "250000001"
    assert call["kwargs"]["params"]["content"] == "68CCC2EFC570A8CE52AD7A6EEE30ADBC"
    assert call["kwargs"]["params"]["api_key"] == "key-1"
    assert call["kwargs"]["params"]["auth_timestamp"]
    assert call["kwargs"]["params"]["sign"]


@pytest.mark.asyncio
async def test_alarm_pcap_detail_validates_required_flow_id():
    module = _load_handler("asiainfo_tda_validation_handler_test")

    result = await module.alarm_pcap_detail(_ctx(), "")

    assert result.success is False
    assert "flow_id" in result.error
