"""
Sandbox elevated mode tests for bash tool.
"""

import pytest

from flocks.tool.code.bash import bash_tool
from flocks.tool.registry import ToolContext, ToolResult


def _ctx(elevated_enabled: bool) -> ToolContext:
    return ToolContext(
        session_id="sandbox-elevated-session",
        message_id="sandbox-elevated-message",
        extra={
            "sandbox": {
                "container_name": "flocks-sbx-test",
                "workspace_dir": "/tmp",
                "container_workdir": "/workspace",
            },
            "sandbox_elevated": {
                "enabled": elevated_enabled,
                "tools": ["bash"],
            },
        },
    )


@pytest.mark.asyncio
async def test_bash_elevated_host_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"host": False, "sandbox": False}

    async def fake_host(**_kwargs):
        called["host"] = True
        return ToolResult(success=True, output="host")

    async def fake_sandbox(**_kwargs):
        called["sandbox"] = True
        return ToolResult(success=True, output="sandbox")

    monkeypatch.setattr("flocks.tool.code.bash._execute_host", fake_host)
    monkeypatch.setattr("flocks.tool.code.bash._execute_sandboxed", fake_sandbox)

    result = await bash_tool(
        ctx=_ctx(elevated_enabled=True),
        command="echo hello",
        host="host",
    )

    assert result.success
    assert called["host"] is True
    assert called["sandbox"] is False


@pytest.mark.asyncio
async def test_bash_elevated_host_denied_when_disabled() -> None:
    result = await bash_tool(
        ctx=_ctx(elevated_enabled=False),
        command="echo hello",
        host="host",
    )
    assert not result.success
    assert "Elevated host execution is not allowed" in (result.error or "")
