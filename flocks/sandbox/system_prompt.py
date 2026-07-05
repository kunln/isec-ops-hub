"""
Sandbox system prompt helpers.
"""

from typing import Any, Dict, Optional

from .config import resolve_sandbox_config_for_agent
from .context import resolve_sandbox_context
from .runtime_status import resolve_sandbox_runtime_status


async def build_sandbox_system_prompt(
    config_data: Dict[str, Any],
    session_key: str,
    agent_id: str,
    main_session_key: str,
    workspace_dir: Optional[str] = None,
) -> Optional[str]:
    """
    Build sandbox prompt content for LLM system instructions.
    """
    runtime = resolve_sandbox_runtime_status(
        config_data=config_data,
        session_key=session_key,
        agent_id=agent_id,
        main_session_key=main_session_key,
    )
    if not runtime.sandboxed:
        return None

    sandbox_cfg = resolve_sandbox_config_for_agent(config_data, agent_id)
    sandbox_ctx = await resolve_sandbox_context(
        config_data=config_data,
        session_key=session_key,
        agent_id=agent_id,
        main_session_key=main_session_key,
        workspace_dir=workspace_dir,
    )
    if not sandbox_ctx:
        return None

    elevated_tools = sandbox_cfg.elevated.tools or ["bash"]
    lines = [
        "## Sandbox Runtime",
        "You are running with sandbox constraints.",
        f"- mode: {runtime.mode}",
        f"- scope: {sandbox_cfg.scope}",
        f"- workspace_access: {sandbox_ctx.workspace_access}",
        f"- sandbox_workspace: {sandbox_ctx.workspace_dir}",
        f"- container_workdir: {sandbox_ctx.container_workdir}",
        "- read/write/edit paths are constrained to sandbox workspace.",
        "- bash runs in sandbox container by default.",
    ]
    if sandbox_ctx.workspace_access == "ro":
        lines.append("- write/edit are blocked in read-only sandbox mode.")
    if sandbox_cfg.elevated.enabled:
        lines.append(
            f"- elevated host execution is enabled for tools: {', '.join(elevated_tools)}."
        )
    else:
        lines.append("- elevated host execution is disabled.")
    return "\n".join(lines)
