"""
Real Docker integration test for sandbox execution.

This test verifies actual container lifecycle and command execution path.
It is opt-in and will be skipped unless:
  FLOCKS_RUN_DOCKER_TEST=1
"""

import os
import tempfile
import uuid

import pytest

from flocks.sandbox.context import resolve_sandbox_context
from flocks.sandbox.docker import docker_container_state, exec_docker, remove_container
from flocks.sandbox.types import BashSandboxConfig
from flocks.tool.code.bash import bash_tool
from flocks.tool.registry import ToolContext


def _docker_test_enabled() -> bool:
    return os.getenv("FLOCKS_RUN_DOCKER_TEST", "").strip() == "1"


@pytest.mark.asyncio
async def test_real_docker_sandbox_bash_execution() -> None:
    """
    Real integration:
    1) create/ensure sandbox container
    2) execute bash via docker exec
    3) verify container state and mounted file side-effect
    """
    if not _docker_test_enabled():
        pytest.skip("Set FLOCKS_RUN_DOCKER_TEST=1 to run real Docker integration test")

    # Probe docker daemon availability early.
    _, _, code = await exec_docker(["version"], allow_failure=True)
    if code != 0:
        pytest.skip("Docker daemon not available")

    session_key = f"docker-it-{uuid.uuid4().hex[:8]}"
    container_name = None
    marker_filename = "sandbox_integration_marker.txt"

    with tempfile.TemporaryDirectory() as workspace_dir:
        config_data = {
            "sandbox": {
                "mode": "on",
                "scope": "session",
                "workspace_access": "rw",
                "docker": {
                    # default image is allowed to auto-bootstrap via ensure_docker_image
                    "image": "python:slim",
                    "workdir": "/workspace",
                    "network": "none",
                    "read_only_root": True,
                    "cap_drop": ["ALL"],
                    "tmpfs": ["/tmp", "/var/tmp", "/run"],
                },
            }
        }

        try:
            sandbox_ctx = await resolve_sandbox_context(
                config_data=config_data,
                session_key=session_key,
                agent_id="rex",
                main_session_key="main",
                workspace_dir=workspace_dir,
            )
            assert sandbox_ctx is not None
            container_name = sandbox_ctx.container_name

            state = await docker_container_state(container_name)
            assert state["exists"] is True
            assert state["running"] is True

            tool_ctx = ToolContext(
                session_id="docker-it",
                message_id="docker-it-msg",
                extra={
                    "sandbox": BashSandboxConfig(
                        container_name=sandbox_ctx.container_name,
                        workspace_dir=sandbox_ctx.workspace_dir,
                        container_workdir=sandbox_ctx.container_workdir,
                        env=sandbox_ctx.docker.env,
                    ).model_dump(exclude_none=True)
                },
            )

            cmd = (
                "echo FLOCKS_DOCKER_SANDBOX_OK && "
                f"echo 'from_sandbox' > {marker_filename} && "
                "pwd"
            )
            result = await bash_tool(
                ctx=tool_ctx,
                command=cmd,
                workdir=workspace_dir,
                description="real docker sandbox integration test",
            )
            assert result.success
            output = str(result.output or "")
            assert "FLOCKS_DOCKER_SANDBOX_OK" in output
            assert "/workspace" in output

            marker_path = os.path.join(workspace_dir, marker_filename)
            assert os.path.exists(marker_path)
            with open(marker_path, "r", encoding="utf-8") as f:
                assert f.read().strip() == "from_sandbox"
        finally:
            if container_name:
                await remove_container(container_name)
