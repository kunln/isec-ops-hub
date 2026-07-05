"""
Real Docker integration test for workflow requirements in sandbox runtime.

This test verifies:
1) workflow requirements are installed inside sandbox container
2) workflow python node can import installed package
3) container marker cache is reused on subsequent runs

Opt-in only:
  FLOCKS_RUN_DOCKER_TEST=1
"""

import asyncio
import os
import tempfile
import uuid
from pathlib import Path

import pytest

from flocks.sandbox.context import resolve_sandbox_context
from flocks.sandbox.docker import exec_docker, remove_container
from flocks.tool.registry import ToolContext
from flocks.workflow.requirements import requirements_cache_key
from flocks.workflow.runner import run_workflow


def _docker_test_enabled() -> bool:
    return os.getenv("FLOCKS_RUN_DOCKER_TEST", "").strip() == "1"


@pytest.mark.asyncio
async def test_real_docker_workflow_requirements_install_and_marker_cache() -> None:
    """Requirements should install in container and reuse marker cache."""
    if not _docker_test_enabled():
        pytest.skip("Set FLOCKS_RUN_DOCKER_TEST=1 to run real Docker integration test")

    # Probe docker daemon early.
    _, _, code = await exec_docker(["version"], allow_failure=True)
    if code != 0:
        pytest.skip("Docker daemon not available")

    session_key = f"wf-req-it-{uuid.uuid4().hex[:8]}"
    container_name = None
    requirements = ["python-dateutil==2.9.0.post0"]
    marker_key = requirements_cache_key(requirements, python_executable="container:python3")
    marker_path = f"/workspace/.flocks/workflow/requirements/{marker_key}.installed"

    with tempfile.TemporaryDirectory() as workspace_dir:
        config_data = {
            "sandbox": {
                "mode": "on",
                "scope": "session",
                "workspace_access": "rw",
                "docker": {
                    "image": "python:slim",
                    "workdir": "/workspace",
                    # Requirements installation needs network access.
                    "network": "bridge",
                    "read_only_root": True,
                    "cap_drop": ["ALL"],
                    "tmpfs": ["/tmp", "/var/tmp", "/run"],
                },
                "tools": {
                    "allow": ["run_workflow"],
                },
            },
            "workflow": {
                "runtime": {
                    "default": "sandbox",
                }
            },
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

            tool_ctx = ToolContext(
                session_id=session_key,
                message_id="wf-req-msg",
                agent="rex",
                extra={
                    "config_data": config_data,
                    "main_session_key": "main",
                    "workspace_dir": workspace_dir,
                    "sandbox": {
                        "container_name": sandbox_ctx.container_name,
                        "workspace_dir": sandbox_ctx.workspace_dir,
                        "container_workdir": sandbox_ctx.container_workdir,
                        "env": sandbox_ctx.docker.env,
                    },
                },
            )

            workflow = {
                "id": "wf-req-it",
                "name": "workflow requirements docker integration",
                "metadata": {
                    "requirements": requirements,
                },
                "start": "n1",
                "nodes": [
                    {
                        "id": "n1",
                        "type": "python",
                        "code": (
                            "import dateutil\n"
                            "from pathlib import Path\n"
                            "outputs['import_ok'] = True\n"
                            "outputs['version'] = getattr(dateutil, '__version__', 'unknown')\n"
                            "outputs['marker_exists'] = Path("
                            f"{marker_path!r}"
                            ").exists()\n"
                        ),
                    }
                ],
                "edges": [],
            }

            # First run: should install requirements in container and create marker.
            result1 = await asyncio.to_thread(
                run_workflow,
                workflow=workflow,
                inputs={},
                ensure_requirements=True,
                use_llm=False,
                tool_context=tool_ctx,
            )
            assert result1.status == "SUCCEEDED"
            assert result1.outputs.get("import_ok") is True
            assert result1.outputs.get("marker_exists") is True
            assert str(result1.outputs.get("version") or "") != ""

            # Capture marker mtime to verify cache reuse on second run.
            stdout1, stderr1, code1 = await exec_docker(
                [
                    "exec",
                    container_name,
                    "python3",
                    "-c",
                    (
                        "from pathlib import Path\n"
                        f"p=Path({marker_path!r})\n"
                        "print(int(p.stat().st_mtime_ns) if p.exists() else -1)\n"
                    ),
                ],
                allow_failure=True,
            )
            assert code1 == 0, f"failed to read marker mtime: {stderr1}"
            mtime1 = int((stdout1 or "").strip())
            assert mtime1 > 0

            # Second run: marker should be reused (mtime unchanged).
            result2 = await asyncio.to_thread(
                run_workflow,
                workflow=workflow,
                inputs={},
                ensure_requirements=True,
                use_llm=False,
                tool_context=tool_ctx,
            )
            assert result2.status == "SUCCEEDED"
            assert result2.outputs.get("import_ok") is True

            stdout2, stderr2, code2 = await exec_docker(
                [
                    "exec",
                    container_name,
                    "python3",
                    "-c",
                    (
                        "from pathlib import Path\n"
                        f"p=Path({marker_path!r})\n"
                        "print(int(p.stat().st_mtime_ns) if p.exists() else -1)\n"
                    ),
                ],
                allow_failure=True,
            )
            assert code2 == 0, f"failed to read marker mtime: {stderr2}"
            mtime2 = int((stdout2 or "").strip())
            assert mtime2 == mtime1

            # Optional host-side evidence: workspace is still mounted/writable.
            assert Path(workspace_dir).exists()
        finally:
            if container_name:
                await remove_container(container_name)
