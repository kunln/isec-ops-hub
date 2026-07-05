"""
Session management tools — 查询、创建、更新、删除 Flocks Session 的元数据。

提供以下工具：
- session_list   : 列出所有（或指定 project）的 session
- session_get    : 获取单个 session 的完整元数据
- session_create : 创建新 session
- session_update : 更新 session 元数据（标题、agent、状态等）
- session_delete : 删除 session（软删除，同时清理子 session）
- session_archive: 归档 / 取消归档 session
"""

from __future__ import annotations

from typing import Any, Optional

from flocks.tool.registry import (
    ParameterType,
    ToolCategory,
    ToolContext,
    ToolParameter,
    ToolRegistry,
    ToolResult,
)
from flocks.utils.log import Log

log = Log.create(service="tool.session_manage")


def _session_to_dict(session, bindings: list | None = None) -> dict[str, Any]:
    """Serialize SessionInfo to a readable dict.

    If ``bindings`` is provided (list of SessionBinding for this session),
    a ``channels`` field is appended with the IM platform details.
    """
    d: dict[str, Any] = {
        "id": session.id,
        "slug": session.slug,
        "project_id": session.project_id,
        "title": session.title,
        "status": session.status,
        "category": session.category,
        "agent": session.agent,
        "model": session.model,
        "provider": session.provider,
        "parent_id": session.parent_id,
        "directory": session.directory,
        "memory_enabled": session.memory_enabled,
        "time": {
            "created": session.time.created,
            "updated": session.time.updated,
            "archived": session.time.archived,
        },
        "summary": session.summary.model_dump() if session.summary else None,
    }
    if bindings is not None:
        d["channels"] = [
            {
                "channel_id": b.channel_id,
                "chat_type": b.chat_type.value if b.chat_type else None,
                "chat_id": b.chat_id,
                "account_id": b.account_id,
            }
            for b in bindings
        ]
    return d


async def _enrich_with_channels(sessions_dict: list[dict]) -> list[dict]:
    """Attach channel binding info to a list of serialized session dicts.

    Best-effort: if the binding table is unavailable, sessions are returned as-is
    with an empty ``channels`` list.
    """
    try:
        from flocks.channel.inbound.session_binding import SessionBindingService
        svc = SessionBindingService()
        all_bindings = await svc.list_bindings()
        index: dict[str, list] = {}
        for b in all_bindings:
            index.setdefault(b.session_id, []).append(b)
        for s in sessions_dict:
            s["channels"] = [
                {
                    "channel_id": b.channel_id,
                    "chat_type": b.chat_type.value if b.chat_type else None,
                    "chat_id": b.chat_id,
                    "account_id": b.account_id,
                }
                for b in index.get(s["id"], [])
            ]
    except Exception as e:
        log.debug("session_manage.enrich_channels.error", {"error": str(e)})
        for s in sessions_dict:
            s.setdefault("channels", [])
    return sessions_dict


# ---------------------------------------------------------------------------
# session_list
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="session_list",
    description=(
        "列出 Flocks 的所有 Session 元数据。"
        "可按 project_id、status、category 过滤，支持分页。"
    ),
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="project_id",
            type=ParameterType.STRING,
            required=False,
            description="按 project_id 过滤；不填则列出所有项目的 session",
        ),
        ToolParameter(
            name="status",
            type=ParameterType.STRING,
            required=False,
            enum=["active", "archived"],
            description="按状态过滤：active（默认）或 archived",
        ),
        ToolParameter(
            name="category",
            type=ParameterType.STRING,
            required=False,
            enum=["user", "task"],
            description="按分类过滤：user（人工会话）或 task（任务触发会话）",
        ),
        ToolParameter(
            name="limit",
            type=ParameterType.INTEGER,
            required=False,
            description="最多返回条数（默认 50）",
        ),
        ToolParameter(
            name="offset",
            type=ParameterType.INTEGER,
            required=False,
            description="跳过前 N 条（用于翻页，默认 0）",
        ),
    ],
)
async def session_list(
    ctx: ToolContext,
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> ToolResult:
    from flocks.session.session import SessionInfo
    from flocks.storage.storage import Storage

    # 直接扫描 Storage，支持 active/archived 双状态，且 project_id 过滤始终生效
    try:
        prefix = f"session:{project_id}:" if project_id else "session:"
        keys = await Storage.list_keys(prefix=prefix)
        sessions = []
        for key in keys:
            try:
                s = await Storage.get(key, SessionInfo)
                if s and s.status != "deleted":
                    sessions.append(s)
            except Exception:
                continue
        sessions.sort(key=lambda s: s.time.updated, reverse=True)
    except Exception as e:
        return ToolResult(success=False, error=f"查询 session 列表失败: {e}")

    if status:
        sessions = [s for s in sessions if s.status == status]

    if category:
        sessions = [s for s in sessions if s.category == category]

    total = len(sessions)
    off = offset or 0
    lim = limit or 50
    page = sessions[off: off + lim]

    sessions_dict = await _enrich_with_channels([_session_to_dict(s) for s in page])

    return ToolResult(
        success=True,
        output={
            "total": total,
            "offset": off,
            "limit": lim,
            "sessions": sessions_dict,
        },
    )


# ---------------------------------------------------------------------------
# session_get
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="session_get",
    description="获取指定 session 的完整元数据，包含时间戳、agent、状态、摘要等。",
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="session_id",
            type=ParameterType.STRING,
            required=True,
            description="Session ID",
        ),
    ],
)
async def session_get(ctx: ToolContext, session_id: str) -> ToolResult:
    from flocks.session.session import Session

    session = await Session.get_by_id(session_id)
    if not session:
        return ToolResult(success=False, error=f"未找到 session '{session_id}'")

    result = _session_to_dict(session)
    enriched = await _enrich_with_channels([result])
    return ToolResult(success=True, output=enriched[0])


# ---------------------------------------------------------------------------
# session_create
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="session_create",
    description="创建一个新的 Flocks Session。",
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="title",
            type=ParameterType.STRING,
            required=False,
            description="Session 标题；不填则自动生成",
        ),
        ToolParameter(
            name="project_id",
            type=ParameterType.STRING,
            required=False,
            description="归属的 project ID（默认 'default'）",
        ),
        ToolParameter(
            name="directory",
            type=ParameterType.STRING,
            required=False,
            description="工作目录路径（默认使用当前目录）",
        ),
        ToolParameter(
            name="agent",
            type=ParameterType.STRING,
            required=False,
            description="指定 agent 类型，如 hephaestus、rex、build、plan 等",
        ),
        ToolParameter(
            name="parent_id",
            type=ParameterType.STRING,
            required=False,
            description="父 session ID（创建子 session 时使用）",
        ),
    ],
)
async def session_create(
    ctx: ToolContext,
    title: Optional[str] = None,
    project_id: Optional[str] = None,
    directory: Optional[str] = None,
    agent: Optional[str] = None,
    parent_id: Optional[str] = None,
) -> ToolResult:
    import os
    from flocks.session.session import Session

    try:
        session = await Session.create(
            project_id=project_id or "default",
            directory=directory or os.getcwd(),
            title=title,
            parent_id=parent_id,
            **({"agent": agent} if agent else {}),
        )
    except Exception as e:
        return ToolResult(success=False, error=f"创建 session 失败: {e}")

    return ToolResult(
        success=True,
        output={
            "message": f"Session 已创建",
            "session": _session_to_dict(session),
        },
    )


# ---------------------------------------------------------------------------
# session_update
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="session_update",
    description=(
        "更新指定 session 的元数据字段。"
        "支持修改标题、agent、model、provider、memory_enabled 等。"
    ),
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="session_id",
            type=ParameterType.STRING,
            required=True,
            description="要更新的 Session ID",
        ),
        ToolParameter(
            name="title",
            type=ParameterType.STRING,
            required=False,
            description="新标题",
        ),
        ToolParameter(
            name="agent",
            type=ParameterType.STRING,
            required=False,
            description="新 agent 类型",
        ),
        ToolParameter(
            name="model",
            type=ParameterType.STRING,
            required=False,
            description="新 model ID",
        ),
        ToolParameter(
            name="provider",
            type=ParameterType.STRING,
            required=False,
            description="新 provider ID",
        ),
        ToolParameter(
            name="memory_enabled",
            type=ParameterType.BOOLEAN,
            required=False,
            description="是否启用 memory 系统",
        ),
    ],
)
async def session_update(
    ctx: ToolContext,
    session_id: str,
    title: Optional[str] = None,
    agent: Optional[str] = None,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    memory_enabled: Optional[bool] = None,
) -> ToolResult:
    from flocks.session.session import Session

    session = await Session.get_by_id(session_id)
    if not session:
        return ToolResult(success=False, error=f"未找到 session '{session_id}'")

    updates: dict[str, Any] = {}
    if title is not None:
        updates["title"] = title
    if agent is not None:
        updates["agent"] = agent
    if model is not None:
        updates["model"] = model
    if provider is not None:
        updates["provider"] = provider
    if memory_enabled is not None:
        updates["memory_enabled"] = memory_enabled

    if not updates:
        return ToolResult(success=False, error="未提供任何要更新的字段")

    try:
        updated = await Session.update(session.project_id, session_id, **updates)
    except Exception as e:
        return ToolResult(success=False, error=f"更新 session 失败: {e}")

    if not updated:
        return ToolResult(success=False, error="更新失败，session 可能已被删除")

    return ToolResult(
        success=True,
        output={
            "message": "Session 已更新",
            "session": _session_to_dict(updated),
        },
    )


# ---------------------------------------------------------------------------
# session_delete
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="session_delete",
    description=(
        "删除指定 session（软删除）。"
        "同时会递归删除其所有子 session，并清空消息记录。"
    ),
    category=ToolCategory.SYSTEM,
    requires_confirmation=True,
    parameters=[
        ToolParameter(
            name="session_id",
            type=ParameterType.STRING,
            required=True,
            description="要删除的 Session ID",
        ),
    ],
)
async def session_delete(ctx: ToolContext, session_id: str) -> ToolResult:
    from flocks.session.session import Session

    session = await Session.get_by_id(session_id)
    if not session:
        return ToolResult(success=False, error=f"未找到 session '{session_id}'")

    try:
        ok = await Session.delete(session.project_id, session_id)
    except Exception as e:
        return ToolResult(success=False, error=f"删除 session 失败: {e}")

    if not ok:
        return ToolResult(success=False, error="删除失败")

    return ToolResult(
        success=True,
        output=f"Session '{session_id}'（{session.title}）已删除",
    )


# ---------------------------------------------------------------------------
# session_archive
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="session_archive",
    description="归档或取消归档指定 session。归档后 session 仍可查询，但不再活跃。",
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="session_id",
            type=ParameterType.STRING,
            required=True,
            description="Session ID",
        ),
        ToolParameter(
            name="archive",
            type=ParameterType.BOOLEAN,
            required=False,
            description="true=归档（默认），false=取消归档（恢复为 active）",
        ),
    ],
)
async def session_archive(
    ctx: ToolContext,
    session_id: str,
    archive: Optional[bool] = True,
) -> ToolResult:
    from flocks.session.session import Session, SessionInfo
    from flocks.storage.storage import Storage

    # get_by_id 会跳过 archived session，需直接扫 Storage
    session = None
    keys = await Storage.list_keys(prefix="session:")
    for key in keys:
        try:
            s = await Storage.get(key, SessionInfo)
            if s and s.id == session_id and s.status != "deleted":
                session = s
                break
        except Exception:
            continue

    if not session:
        return ToolResult(success=False, error=f"未找到 session '{session_id}'")

    try:
        if archive is False:
            ok = await Session.unarchive(session.project_id, session_id)
            action = "取消归档"
        else:
            ok = await Session.archive(session.project_id, session_id)
            action = "归档"
    except Exception as e:
        return ToolResult(success=False, error=f"操作失败: {e}")

    if not ok:
        return ToolResult(
            success=False,
            error=f"操作失败，session 当前状态为 '{session.status}'，无法执行{action}",
        )

    return ToolResult(
        success=True,
        output=f"Session '{session_id}'（{session.title}）已{action}",
    )
