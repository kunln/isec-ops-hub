from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from flocks.commercial import policy as commercial_policy
from flocks.tool.wecom import wecom_mcp


@pytest.mark.asyncio
async def test_wecom_mcp_initialize_rejects_before_http_client_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    async_client = MagicMock()
    monkeypatch.setattr(commercial_policy, "ensure_outbound_allowed", fake_ensure_outbound_allowed)
    monkeypatch.setattr(wecom_mcp.httpx, "AsyncClient", async_client)

    with pytest.raises(commercial_policy.CommercialPolicyError, match="blocked by commercial policy"):
        await wecom_mcp._initialize_session("https://example.com/mcp", "doc")

    assert calls == [
        {
            "url": "https://example.com/mcp",
            "purpose": "WeCom MCP initialize",
            "require_initialized": False,
        }
    ]
    async_client.assert_not_called()
