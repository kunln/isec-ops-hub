from __future__ import annotations

from unittest.mock import MagicMock

from flocks.commercial import policy as commercial_policy
from flocks.workflow.engine import WorkflowEngine
from flocks.workflow.models import Node, Workflow


def test_http_request_node_rejects_before_http_client_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    monkeypatch.setattr(
        commercial_policy,
        "ensure_outbound_allowed",
        fake_ensure_outbound_allowed,
    )

    import httpx

    client = MagicMock()
    monkeypatch.setattr(httpx, "Client", client)

    workflow = Workflow(
        start="call_api",
        nodes=[
            Node(
                id="call_api",
                type="http_request",
                method="GET",
                url="https://example.com/data",
            ),
        ],
    )

    result = WorkflowEngine(workflow).run_node("call_api", {})

    assert "blocked by commercial policy" in (result.error or "")
    assert calls == [
        {
            "url": "https://example.com/data",
            "purpose": "workflow HTTP request",
            "require_initialized": False,
        }
    ]
    client.assert_not_called()
