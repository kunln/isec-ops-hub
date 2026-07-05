import pytest

from flocks.security.connectors.adapter import (
    execute_adapter_contract,
    load_adapter_contract,
    preview_adapter_contract,
    validate_adapter_contract,
    _parse_tool_output,
)
from flocks.security.connectors.replay import ADAPTER_ROOT, REPLAY_CONNECTOR_ID
from flocks.tool import ToolRegistry, ToolResult


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeHttpClient:
    def __init__(self):
        self.calls = []

    async def request(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponse(
            {
                "items": [
                    {
                        "id": "ast_http_1",
                        "name": "HTTP Asset",
                        "type": "server",
                        "ip": "203.0.113.99",
                    }
                ]
            }
        )


@pytest.mark.asyncio
async def test_fixture_adapter_executes_raw_response_and_mapping_preview():
    adapter_path = ADAPTER_ROOT / "asset.search.adapter.json"
    contract = load_adapter_contract(adapter_path)

    executed = await execute_adapter_contract(contract, base_dir=adapter_path.parent)
    preview = await preview_adapter_contract(
        REPLAY_CONNECTOR_ID,
        contract,
        base_dir=adapter_path.parent,
        contract_file=adapter_path,
    )

    assert executed.source == "fixture:assets_search.json"
    assert executed.raw_response["items"][0]["name"] == "Replay Internet Portal"
    assert preview.adapter_contract["version"] == "connector.adapter.v1"
    assert preview.adapter_contract["transport"] == "fixture"
    assert preview.mapping_result["assets"][0]["name"] == "Replay Internet Portal"
    assert "items[1].ip" in preview.missing_required_fields


@pytest.mark.asyncio
async def test_http_adapter_builds_request_with_env_auth_and_maps_response():
    client = FakeHttpClient()
    contract = {
        "version": "connector.adapter.v1",
        "capability": "asset.search",
        "transport": "http",
        "mapping": "../mappings/asset.search.mapping.json",
        "request": {
            "method": "GET",
            "base_url": "https://vendor.example",
            "path": "/api/assets",
            "query": {"page": 1, "tenant": "${ENV:TENANT_ID}"},
            "headers": {"Accept": "application/json"},
            "auth": {"type": "bearer", "token_env": "VENDOR_TOKEN"},
        },
    }

    preview = await preview_adapter_contract(
        "http-test",
        contract,
        base_dir=ADAPTER_ROOT,
        http_client=client,
        env={"VENDOR_TOKEN": "secret-token", "TENANT_ID": "tenant-a"},
    )

    call = client.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://vendor.example/api/assets"
    assert call["headers"]["Authorization"] == "Bearer secret-token"
    assert call["params"]["tenant"] == "tenant-a"
    assert preview.source == "http:GET:https://vendor.example/api/assets"
    assert preview.adapter_request["auth_type"] == "bearer"
    assert preview.mapping_result["assets"][0]["name"] == "HTTP Asset"


def test_adapter_contract_validation_rejects_missing_transport():
    with pytest.raises(ValueError, match="unsupported transport"):
        validate_adapter_contract(
            {
                "version": "connector.adapter.v1",
                "capability": "asset.search",
                "mapping": "asset.search.mapping.json",
            }
        )


@pytest.mark.asyncio
async def test_tool_adapter_executes_registry_and_normalizes_items(monkeypatch):
    calls = []

    async def fake_execute(cls, tool_name, ctx=None, **kwargs):
        calls.append({"tool_name": tool_name, "ctx": ctx, "kwargs": kwargs})
        return ToolResult(
            success=True,
            output={
                "data": {
                    "list": [
                        {
                            "id": "ast_tool_1",
                            "name": "Tool Asset",
                            "type": "server",
                            "ip": "203.0.113.101",
                        }
                    ]
                }
            },
            metadata={"device_id": "dev-1"},
        )

    monkeypatch.setattr(ToolRegistry, "init", classmethod(lambda cls: None))
    monkeypatch.setattr(ToolRegistry, "execute", classmethod(fake_execute))
    contract = {
        "version": "connector.adapter.v1",
        "capability": "asset.search",
        "transport": "tool",
        "mapping": "../mappings/asset.search.mapping.json",
        "tool": {
            "name": "vendor_asset_tool",
            "params": {"action": "list", "device_id": "${ENV:DEVICE_ID}"},
            "output": {"items_path": ["data.list"], "wrap_items_as": "items"},
        },
    }

    preview = await preview_adapter_contract(
        "tool-test",
        contract,
        base_dir=ADAPTER_ROOT,
        env={"DEVICE_ID": "dev-1"},
    )

    assert calls[0]["tool_name"] == "vendor_asset_tool"
    assert calls[0]["kwargs"]["device_id"] == "dev-1"
    assert calls[0]["ctx"].message_id == "connector:asset.search"
    assert preview.source == "tool:vendor_asset_tool"
    assert preview.raw_response["items"][0]["name"] == "Tool Asset"
    assert preview.raw_response["response"]["data"]["list"][0]["id"] == "ast_tool_1"
    assert preview.mapping_result["assets"][0]["name"] == "Tool Asset"
    assert preview.adapter_request["metadata"]["device_id"] == "dev-1"


def test_tool_adapter_restores_truncated_tool_output_from_workspace(monkeypatch, tmp_path):
    output_dir = tmp_path / "tool-output"
    output_dir.mkdir()
    output_file = output_dir / "tool_123"
    output_file.write_text('{"result": [{"id": "ast_1", "name": "Restored"}]}', encoding="utf-8")

    class FakeWorkspaceManager:
        def get_workspace_dir(self):
            return tmp_path

    from flocks.workspace.manager import WorkspaceManager

    monkeypatch.setattr(WorkspaceManager, "get_instance", classmethod(lambda cls: FakeWorkspaceManager()))
    truncated = (
        '{"result": [{"id": "ast_1"\n\n'
        "...42 lines truncated...\n\n"
        f"The tool call succeeded but the output was truncated. Full output saved to: {output_file}\n"
        "Use Grep to search the full content or Read with offset/limit to view specific sections."
    )

    parsed = _parse_tool_output(truncated)

    assert parsed == {"result": [{"id": "ast_1", "name": "Restored"}]}
