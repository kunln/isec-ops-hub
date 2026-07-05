"""
沙箱共享工具函数

对齐 OpenClaw sandbox/shared.ts：
- scope key 解析
- 工作区目录解析
- session key 哈希/slug 化
"""

import hashlib
import os
import re

from .defaults import DEFAULT_SANDBOX_WORKSPACE_ROOT


def slugify_session_key(value: str) -> str:
    """
    将 session key 转换为文件系统安全的 slug。

    对齐 OpenClaw slugifySessionKey。
    """
    trimmed = value.strip() or "session"
    hash_hex = hashlib.sha1(trimmed.encode()).hexdigest()[:8]
    safe = re.sub(r"[^a-z0-9._-]+", "-", trimmed.lower())
    safe = safe.strip("-")
    base = safe[:32] or "session"
    return f"{base}-{hash_hex}"


def resolve_sandbox_workspace_dir(root: str, session_key: str) -> str:
    """
    计算沙箱工作区目录路径。

    Args:
        root: 工作区根目录
        session_key: 会话标识

    Returns:
        工作区绝对路径
    """
    resolved_root = os.path.expanduser(root)
    slug = slugify_session_key(session_key)
    return os.path.join(resolved_root, slug)


def resolve_sandbox_scope_key(
    scope: str,
    session_key: str,
) -> str:
    """
    根据 scope 和 session key 计算 scope key。

    对齐 OpenClaw resolveSandboxScopeKey:
    - shared → "shared"
    - session → session_key 原值
    - agent → "agent:{agent_id}"
    """
    trimmed = session_key.strip() or "main"
    if scope == "shared":
        return "shared"
    if scope == "session":
        return trimmed
    # scope == "agent"
    agent_id = _resolve_agent_id_from_session_key(trimmed)
    return f"agent:{agent_id}"


def resolve_sandbox_agent_id(scope_key: str) -> str | None:
    """从 scope key 中提取 agent id."""
    trimmed = scope_key.strip()
    if not trimmed or trimmed == "shared":
        return None
    parts = [p for p in trimmed.split(":") if p]
    if len(parts) >= 2 and parts[0] == "agent":
        return parts[1]
    return _resolve_agent_id_from_session_key(trimmed)


def _resolve_agent_id_from_session_key(session_key: str) -> str:
    """
    从 session key 中提取 agent id。

    flocks 的 session key 格式可能是 "agent_id:session_id" 或纯 session_id。
    """
    if ":" in session_key:
        return session_key.split(":")[0]
    return "default"


def get_default_workspace_root() -> str:
    """获取默认沙箱工作区根目录."""
    return os.path.expanduser(DEFAULT_SANDBOX_WORKSPACE_ROOT)
