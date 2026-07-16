"""Device Integration-backed Runtime v2 adapter tests."""

from __future__ import annotations

import json

import pytest

from flocks.security.integrations.adapter import IntegrationAdapterRequest
from flocks.security.integrations.adapter_registry import create_default_adapter_registry
from flocks.security.integrations.device_runtime_adapter import DeviceIntegrationRuntimeAdapter
from flocks.security.integrations.instances import IntegrationInstance
from flocks.tool import ToolResult


class InstanceStore:
    def __init__(self, instance: IntegrationInstance | None) -> None:
        self.instance = instance

    async def get_instance(self, instance_id: str) -> IntegrationInstance | None:
        if self.instance and self.instance.instance_id == instance_id:
            return self.instance
        return None


def bridged_instance(**updates: object) -> IntegrationInstance:
    values = {
        "instance_id": "intinst_tda",
        "package_id": "asiainfo.tda",
        "display_name": "TDA Test",
        "enabled": True,
        "metadata": {
            "source": "device_integration_bridge",
            "device_id": "device_tda",
        },
    }
    values.update(updates)
    return IntegrationInstance(**values)


def adapter_request(**updates: object) -> IntegrationAdapterRequest:
    values = {
        "package_id": "asiainfo.tda",
        "instance_id": "intinst_tda",
        "capability": "alert.search",
        "params": {"time_type": 2, "page": 1, "page_size": 2},
    }
    values.update(updates)
    return IntegrationAdapterRequest(**values)


def test_default_registry_resolves_device_adapter_and_keeps_fake() -> None:
    registry = create_default_adapter_registry(include_fake=True)

    assert isinstance(registry.require_adapter("asiainfo.tda", "alert.search"), DeviceIntegrationRuntimeAdapter)
    assert registry.has_adapter("fake.integration", "alert.search") is True


@pytest.mark.asyncio
async def test_adapter_resolves_instance_device_and_maps_tda_alerts() -> None:
    calls: list[dict[str, object]] = []

    async def get_device(device_id: str):
        assert device_id == "device_tda"
        return {
            "id": device_id,
            "name": "TDA",
            "storage_key": "asiainfo_xinwei_tda_v7_0",
            "service_id": "asiainfo_tda_api",
            "enabled": True,
            "verify_ssl": False,
            "status": "ok",
            "api_key": "REAL_API_KEY_SHOULD_NOT_LEAK",
            "password": "REAL_PASSWORD_SHOULD_NOT_LEAK",
        }

    async def execute_tool(*, device_id: str, params: dict[str, object]):
        calls.append({"device_id": device_id, "params": params})
        return ToolResult(
            success=True,
            output={
                "alarm_list": [
                    {
                        "merge_key": "tda-1",
                        "threat_desc": "C2 beacon",
                        "severity": "高危",
                        "victim_addr": "10.0.0.8",
                        "attacker_addr": "203.0.113.8",
                        "event_time": "2026-07-14T01:02:03Z",
                        "threat_class": "C2",
                        "token": "REAL_TOKEN_SHOULD_NOT_LEAK",
                        "raw_response": {"authorization": "Bearer REAL_AUTH_SHOULD_NOT_LEAK"},
                    },
                    {
                        "merge_key": "tda-2",
                        "rule_name": "Malware download",
                        "severity": "0x4",
                        "dst": ["10.0.0.9"],
                        "src": ["198.51.100.4"],
                        "password": "REAL_PASSWORD_SHOULD_NOT_LEAK",
                    },
                ],
                "total": 2,
            },
            metadata={"api_key": "REAL_API_KEY_SHOULD_NOT_LEAK"},
        )

    adapter = DeviceIntegrationRuntimeAdapter(
        instance_store=InstanceStore(bridged_instance()),
        device_identity_getter=get_device,
        tool_executor=execute_tool,
    )
    result = await adapter.run_capability(adapter_request())

    assert result.status == "success"
    assert result.item_count == 2
    assert calls == [{"device_id": "device_tda", "params": {"time_type": 2, "page": 1, "limit": 2}}]
    first = result.items[0]
    assert first["external_event_id"] == "tda-1"
    assert first["title"] == "C2 beacon"
    assert first["description"] == "C2 beacon"
    assert first["severity"] == "high"
    assert first["source"] == "ndr"
    assert first["source_type"] == "integration_event"
    assert first["asset_id"] == "10.0.0.8"
    assert "203.0.113.8" in first["ioc"]
    assert first["occurred_at"] == "2026-07-14T01:02:03Z"
    assert first["alert_type"] == "C2"
    assert first["payload_hash"]
    assert result.cursor == {"page": 2, "limit": 2}

    exported = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    for secret in (
        "REAL_TOKEN_SHOULD_NOT_LEAK",
        "REAL_API_KEY_SHOULD_NOT_LEAK",
        "REAL_PASSWORD_SHOULD_NOT_LEAK",
        "Bearer REAL_AUTH_SHOULD_NOT_LEAK",
    ):
        assert secret not in exported


@pytest.mark.asyncio
async def test_adapter_calls_tda_tool_registry_with_explicit_device_id(monkeypatch: pytest.MonkeyPatch) -> None:
    from flocks.tool import ToolRegistry

    captured: dict[str, object] = {}

    async def get_device(_device_id: str):
        return {"enabled": True, "status": "ok"}

    async def fake_execute(cls, tool_name: str, ctx=None, **kwargs):
        del cls, ctx
        captured["tool_name"] = tool_name
        captured["kwargs"] = kwargs
        return ToolResult(success=True, output={"alarm_list": [], "total": 0})

    monkeypatch.setattr(ToolRegistry, "init", classmethod(lambda cls: None))
    monkeypatch.setattr(ToolRegistry, "execute", classmethod(fake_execute))
    adapter = DeviceIntegrationRuntimeAdapter(
        instance_store=InstanceStore(bridged_instance()),
        device_identity_getter=get_device,
    )

    result = await adapter.run_capability(adapter_request())

    assert result.status == "success"
    assert captured["tool_name"] == "asiainfo_tda_alerts"
    assert captured["kwargs"] == {
        "device_id": "device_tda",
        "time_type": 2,
        "page": 1,
        "limit": 2,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("instance", "device", "expected"),
    [
        (bridged_instance(metadata={"source": "manual", "device_id": "device_tda"}), None, "bridge_metadata_invalid"),
        (bridged_instance(metadata={"source": "device_integration_bridge"}), None, "bridge_metadata_invalid"),
        (bridged_instance(), None, "device_not_found"),
        (bridged_instance(), {"enabled": False, "status": "ok"}, "device_disabled"),
        (bridged_instance(), {"enabled": True, "status": "error"}, "device_connection_failed"),
    ],
)
async def test_adapter_rejects_invalid_bridge_or_device_state(instance, device, expected: str) -> None:
    async def get_device(_device_id: str):
        return device

    async def forbidden_tool(**_kwargs):
        raise AssertionError("device tool must not be called")

    adapter = DeviceIntegrationRuntimeAdapter(
        instance_store=InstanceStore(instance),
        device_identity_getter=get_device,
        tool_executor=forbidden_tool,
    )
    result = await adapter.run_capability(adapter_request())
    assert result.status == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("TDA API Key 未配置", "missing_credentials"),
        ("HTTP 401 unauthorized", "device_auth_failed"),
        ("request timed out", "device_timeout"),
        ("cannot connect to device", "device_connection_failed"),
    ],
)
async def test_adapter_returns_stable_sanitized_tool_errors(error: str, expected: str) -> None:
    async def get_device(_device_id: str):
        return {"enabled": True, "status": "ok"}

    async def execute_tool(**_kwargs):
        return ToolResult(success=False, error=f"{error} api_key=REAL_API_KEY_SHOULD_NOT_LEAK")

    adapter = DeviceIntegrationRuntimeAdapter(
        instance_store=InstanceStore(bridged_instance()),
        device_identity_getter=get_device,
        tool_executor=execute_tool,
    )
    result = await adapter.run_capability(adapter_request())
    assert result.status == expected
    assert "REAL_API_KEY_SHOULD_NOT_LEAK" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_adapter_rejects_unsupported_capability_without_tool_call() -> None:
    adapter = DeviceIntegrationRuntimeAdapter(instance_store=InstanceStore(bridged_instance()))
    result = await adapter.run_capability(adapter_request(capability="event.search"))
    assert result.status == "unsupported_capability"
