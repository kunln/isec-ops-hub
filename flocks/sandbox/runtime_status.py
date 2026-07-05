"""
沙箱运行时状态判定

对齐 OpenClaw sandbox/runtime-status.ts：
- 根据 mode + session key 判定是否需要沙箱化
- 生成运行时状态信息
"""

from typing import Any, Dict, Optional

from .config import resolve_sandbox_config_for_agent
from .tool_policy import resolve_tool_policy
from .types import SandboxConfig, SandboxMode, SandboxToolPolicy


def should_sandbox_session(
    cfg: SandboxConfig,
    session_key: str,
    main_session_key: str,
) -> bool:
    """
    判定会话是否应该沙箱化。

    对齐 OpenClaw shouldSandboxSession：
    - off → False
    - on → True
    """
    _ = session_key
    _ = main_session_key
    return cfg.mode == "on"


class SandboxRuntimeStatus:
    """沙箱运行时状态."""

    def __init__(
        self,
        agent_id: str,
        session_key: str,
        main_session_key: str,
        mode: SandboxMode,
        sandboxed: bool,
        tool_policy: SandboxToolPolicy,
    ):
        self.agent_id = agent_id
        self.session_key = session_key
        self.main_session_key = main_session_key
        self.mode = mode
        self.sandboxed = sandboxed
        self.tool_policy = tool_policy


def resolve_sandbox_runtime_status(
    config_data: Optional[Dict[str, Any]] = None,
    session_key: Optional[str] = None,
    agent_id: Optional[str] = None,
    main_session_key: Optional[str] = None,
) -> SandboxRuntimeStatus:
    """
    解析沙箱运行时状态。

    对齐 OpenClaw resolveSandboxRuntimeStatus。

    Args:
        config_data: 完整配置字典
        session_key: 当前会话标识
        agent_id: Agent 标识
        main_session_key: 主会话标识

    Returns:
        SandboxRuntimeStatus
    """
    session_key = (session_key or "").strip()
    agent_id = agent_id or "default"
    main_session_key = main_session_key or "main"

    sandbox_cfg = resolve_sandbox_config_for_agent(config_data, agent_id)

    sandboxed = (
        should_sandbox_session(sandbox_cfg, session_key, main_session_key)
        if session_key
        else False
    )

    # 解析工具策略
    global_sandbox = (config_data or {}).get("sandbox", {}) or {}
    agent_data = (config_data or {}).get("agent", {}) or {}
    agent_sandbox = {}
    if agent_id and agent_id in agent_data:
        ac = agent_data[agent_id]
        if isinstance(ac, dict):
            agent_sandbox = ac.get("sandbox", {}) or {}

    global_tools = global_sandbox.get("tools", {}) or {}
    agent_tools = agent_sandbox.get("tools", {}) or {}

    tool_policy = resolve_tool_policy(
        global_allow=global_tools.get("allow"),
        global_deny=global_tools.get("deny"),
        agent_allow=agent_tools.get("allow"),
        agent_deny=agent_tools.get("deny"),
    )

    return SandboxRuntimeStatus(
        agent_id=agent_id,
        session_key=session_key,
        main_session_key=main_session_key,
        mode=sandbox_cfg.mode,
        sandboxed=sandboxed,
        tool_policy=tool_policy,
    )
