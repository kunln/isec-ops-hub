"""
沙箱上下文解析

对齐 OpenClaw sandbox/context.ts：
- 核心入口: 根据配置 + 会话信息组装完整沙箱上下文
- 协调 workspace 创建、容器 ensure、注册表更新
"""

import os
from typing import Any, Dict, Optional

from .config import resolve_sandbox_config_for_agent
from .docker import ensure_sandbox_container
from .prune import maybe_prune_sandboxes
from .runtime_status import resolve_sandbox_runtime_status
from .shared import (
    get_default_workspace_root,
    resolve_sandbox_scope_key,
    resolve_sandbox_workspace_dir,
)
from .types import SandboxContext, SandboxWorkspaceInfo
from .workspace import ensure_sandbox_workspace

from flocks.utils.log import Log

log = Log.create(service="sandbox.context")


async def resolve_sandbox_context(
    config_data: Optional[Dict[str, Any]] = None,
    session_key: Optional[str] = None,
    agent_id: Optional[str] = None,
    main_session_key: Optional[str] = None,
    workspace_dir: Optional[str] = None,
) -> Optional[SandboxContext]:
    """
    解析沙箱上下文。

    对齐 OpenClaw resolveSandboxContext：
    1. 判定是否需要沙箱化
    2. 解析配置
    3. 触发自动清理
    4. 创建沙箱工作区
    5. 确保容器就绪
    6. 返回完整上下文

    Args:
        config_data: 完整配置字典
        session_key: 当前会话标识
        agent_id: Agent 标识
        main_session_key: 主会话标识
        workspace_dir: Agent 工作区目录

    Returns:
        SandboxContext 或 None（不需要沙箱化时）
    """
    raw_session_key = (session_key or "").strip()
    if not raw_session_key:
        return None

    # 判定是否需要沙箱化
    runtime = resolve_sandbox_runtime_status(
        config_data=config_data,
        session_key=raw_session_key,
        agent_id=agent_id,
        main_session_key=main_session_key,
    )
    if not runtime.sandboxed:
        return None

    # 解析配置
    cfg = resolve_sandbox_config_for_agent(config_data, runtime.agent_id)

    # 触发自动清理
    await maybe_prune_sandboxes(cfg)

    # 解析工作区路径
    agent_workspace_dir = os.path.expanduser(
        workspace_dir or os.getcwd()
    )
    workspace_root = os.path.expanduser(
        cfg.workspace_root or get_default_workspace_root()
    )
    scope_key = resolve_sandbox_scope_key(cfg.scope, raw_session_key)

    sandbox_workspace_dir = (
        workspace_root
        if cfg.scope == "shared"
        else resolve_sandbox_workspace_dir(workspace_root, scope_key)
    )

    # 决定实际工作目录
    effective_workspace_dir = (
        agent_workspace_dir
        if cfg.workspace_access == "rw"
        else sandbox_workspace_dir
    )

    # 创建沙箱工作区
    if effective_workspace_dir == sandbox_workspace_dir:
        await ensure_sandbox_workspace(
            workspace_dir=sandbox_workspace_dir,
            seed_from=agent_workspace_dir,
        )
    else:
        os.makedirs(effective_workspace_dir, exist_ok=True)

    # 确保容器就绪
    container_name = await ensure_sandbox_container(
        session_key=raw_session_key,
        workspace_dir=effective_workspace_dir,
        agent_workspace_dir=agent_workspace_dir,
        cfg=cfg,
    )

    log.info(
        "sandbox.context_resolved",
        {
            "session_key": raw_session_key,
            "container": container_name,
            "workspace_access": cfg.workspace_access,
            "scope": cfg.scope,
        },
    )

    return SandboxContext(
        enabled=True,
        session_key=raw_session_key,
        workspace_dir=effective_workspace_dir,
        agent_workspace_dir=agent_workspace_dir,
        workspace_access=cfg.workspace_access,
        container_name=container_name,
        container_workdir=cfg.docker.workdir,
        docker=cfg.docker,
        tools=cfg.tools,
    )


async def ensure_sandbox_workspace_for_session(
    config_data: Optional[Dict[str, Any]] = None,
    session_key: Optional[str] = None,
    agent_id: Optional[str] = None,
    main_session_key: Optional[str] = None,
    workspace_dir: Optional[str] = None,
) -> Optional[SandboxWorkspaceInfo]:
    """
    确保沙箱工作区存在（轻量版，不创建容器）。

    对齐 OpenClaw ensureSandboxWorkspaceForSession。
    """
    raw_session_key = (session_key or "").strip()
    if not raw_session_key:
        return None

    runtime = resolve_sandbox_runtime_status(
        config_data=config_data,
        session_key=raw_session_key,
        agent_id=agent_id,
        main_session_key=main_session_key,
    )
    if not runtime.sandboxed:
        return None

    cfg = resolve_sandbox_config_for_agent(config_data, runtime.agent_id)

    agent_workspace_dir = os.path.expanduser(workspace_dir or os.getcwd())
    workspace_root = os.path.expanduser(
        cfg.workspace_root or get_default_workspace_root()
    )
    scope_key = resolve_sandbox_scope_key(cfg.scope, raw_session_key)

    sandbox_workspace_dir = (
        workspace_root
        if cfg.scope == "shared"
        else resolve_sandbox_workspace_dir(workspace_root, scope_key)
    )

    effective_workspace_dir = (
        agent_workspace_dir
        if cfg.workspace_access == "rw"
        else sandbox_workspace_dir
    )

    if effective_workspace_dir == sandbox_workspace_dir:
        await ensure_sandbox_workspace(
            workspace_dir=sandbox_workspace_dir,
            seed_from=agent_workspace_dir,
        )
    else:
        os.makedirs(effective_workspace_dir, exist_ok=True)

    return SandboxWorkspaceInfo(
        workspace_dir=effective_workspace_dir,
        container_workdir=cfg.docker.workdir,
    )
