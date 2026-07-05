"""
Sandbox system prompt generation tests.
"""

import pytest

from flocks.sandbox.system_prompt import build_sandbox_system_prompt
from flocks.sandbox.types import SandboxContext, SandboxDockerConfig, SandboxToolPolicy


@pytest.mark.asyncio
async def test_build_sandbox_system_prompt_includes_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve_sandbox_context(**_kwargs):
        return SandboxContext(
            enabled=True,
            session_key="s1",
            workspace_dir="/tmp/.flocks/sandboxes/s1",
            agent_workspace_dir="/tmp",
            workspace_access="rw",
            container_name="flocks-sbx-s1",
            container_workdir="/workspace",
            docker=SandboxDockerConfig(),
            tools=SandboxToolPolicy(),
        )

    monkeypatch.setattr(
        "flocks.sandbox.system_prompt.resolve_sandbox_context",
        fake_resolve_sandbox_context,
    )

    prompt = await build_sandbox_system_prompt(
        config_data={
            "sandbox": {
                "mode": "on",
                "scope": "session",
                "workspace_access": "rw",
                "elevated": {"enabled": True, "tools": ["bash"]},
            }
        },
        session_key="s1",
        agent_id="rex",
        main_session_key="main",
        workspace_dir="/tmp",
    )

    assert prompt is not None
    assert "## Sandbox Runtime" in prompt
    assert "mode: on" in prompt
    assert "workspace_access: rw" in prompt
    assert "elevated host execution is enabled" in prompt
