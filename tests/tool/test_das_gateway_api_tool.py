import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from flocks.tool.registry import ToolContext
from flocks.tool.tool_loader import yaml_to_tool


PLUGIN_DIR = Path.cwd() / ".flocks/plugins/tools/device/dbappsecurity_das_gateway_v3_0_6_0r"
HANDLER_PATH = PLUGIN_DIR / "das_gateway.handler.py"


def _load_handler(module_name: str = "das_gateway_handler_test"):
    spec = importlib.util.spec_from_file_location(module_name, HANDLER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ctx() -> ToolContext:
    return ToolContext(session_id="test", message_id="test")


class _FakeResponse:
    def __init__(self, status: int, payload: dict, headers: dict | None = None):
        self.status = status
        self._payload = payload
        self.headers = headers or {}

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


def test_das_gateway_provider_yaml_loads_as_device_tool():
    yaml_path = PLUGIN_DIR / "das_gateway_health.yaml"
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    tool = yaml_to_tool(raw, yaml_path)

    assert tool.info.source == "device"
    assert tool.info.vendor == "安恒信息"
    assert tool.info.provider == "dbappsecurity_das_gateway_api_v3_0_6_0r"
    assert getattr(tool, "_service_id") == "dbappsecurity_das_gateway_api"


@pytest.mark.asyncio
async def test_health_uses_basic_auth_and_read_only_system_paths(monkeypatch):
    module = _load_handler("das_gateway_health_handler_test")
    fake_session = _FakeSession(
        [
            _FakeResponse(200, {"code": 1, "data": {"host_name": "das-gw"}}),
            _FakeResponse(200, {"code": 1, "data": {"cpu": "10"}}),
            _FakeResponse(200, {"code": 1, "data": {"status": "valid"}}),
        ]
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://gateway.example.com/api/v3",
            "username": "admin",
            "password": "secret",
            "verify_ssl": False,
        }
        if service_id == "dbappsecurity_das_gateway_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.health(_ctx())

    assert result.success is True
    assert result.output["host_info"]["host_name"] == "das-gw"
    assert [call["method"] for call in fake_session.calls] == ["GET", "GET", "GET"]
    assert [call["url"] for call in fake_session.calls] == [
        "https://gateway.example.com/api/v3/Objects/HostInfo",
        "https://gateway.example.com/api/v3/Objects/SystemResourceInfo",
        "https://gateway.example.com/api/v3/Objects/License",
    ]
    auth = fake_session.calls[0]["kwargs"]["auth"]
    assert auth.login == "admin"
    assert auth.password == "secret"


@pytest.mark.asyncio
async def test_network_detail_encodes_path_params_and_keeps_pagination_metadata(monkeypatch):
    module = _load_handler("das_gateway_network_handler_test")
    fake_session = _FakeSession(
        _FakeResponse(
            200,
            {"code": 1, "data": [{"name": "eth 0/1"}]},
            headers={"X-Pagination-Total-Count": "1", "X-Pagination-Current-Page": "1"},
        )
    )

    monkeypatch.setattr(
        module.ConfigWriter,
        "get_api_service_raw",
        lambda service_id: {
            "base_url": "https://gateway.example.com",
            "username": "admin",
            "password": "secret",
            "verify_ssl": True,
        }
        if service_id == "dbappsecurity_das_gateway_api"
        else {},
    )
    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda **kwargs: fake_session)
    monkeypatch.setattr(module.aiohttp, "TCPConnector", lambda **kwargs: object())

    result = await module.network(
        _ctx(),
        action="interface_detail",
        path_params={"name": "eth 0/1"},
        page=1,
        count=20,
        language="EN",
    )

    assert result.success is True
    call = fake_session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://gateway.example.com/api/v3/Objects/Interface/name/eth%200%2F1"
    assert call["kwargs"]["params"] == {"page": 1, "count": 20, "language": "EN"}
    assert result.metadata["pagination"]["total_count"] == 1


@pytest.mark.asyncio
async def test_required_path_params_are_validated_before_request(monkeypatch):
    module = _load_handler("das_gateway_validation_handler_test")

    result = await module.policy(_ctx(), action="audit_policy_detail")

    assert result.success is False
    assert "id" in result.error


def test_customer_side_mappings_exclude_write_export_download_and_diagnostic_paths():
    module = _load_handler("das_gateway_safety_handler_test")
    exposed_paths = {
        spec["path"]
        for actions in module.ACTION_GROUPS.values()
        for spec in actions.values()
    }

    forbidden_fragments = {
        "/move",
        "/export",
        "download",
        "Capture",
        "CaptureFile",
        "Corefile",
        "SystemConfig/export",
        "rollback",
        "registry",
        "deadletter",
        "batch",
        "delete",
    }

    for path in exposed_paths:
        lowered = path.lower()
        assert all(fragment.lower() not in lowered for fragment in forbidden_fragments), path
