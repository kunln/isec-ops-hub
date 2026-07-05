"""
沙箱容器自动清理

对齐 OpenClaw sandbox/prune.ts：
- 清理空闲超时的容器
- 清理超过最大存活时间的容器
- 节流: 最多每 5 分钟检查一次
"""

import time
from typing import Optional

from .docker import exec_docker, remove_container
from .registry import read_registry, remove_registry_entry, write_registry
from .types import SandboxConfig

from flocks.utils.log import Log

log = Log.create(service="sandbox.prune")

# 节流: 最少间隔 5 分钟
_PRUNE_INTERVAL_MS = 5 * 60 * 1000
_last_prune_at_ms: float = 0


async def maybe_prune_sandboxes(cfg: SandboxConfig) -> None:
    """
    按需清理过期沙箱容器。

    对齐 OpenClaw maybePruneSandboxes: 最多每 5 分钟执行一次。
    """
    global _last_prune_at_ms

    now = time.time() * 1000
    if now - _last_prune_at_ms < _PRUNE_INTERVAL_MS:
        return
    _last_prune_at_ms = now

    await prune_sandboxes(cfg)


async def prune_sandboxes(cfg: SandboxConfig) -> int:
    """
    清理过期沙箱容器。

    Returns:
        清理的容器数量
    """
    registry = await read_registry()
    if not registry.entries:
        return 0

    now = time.time() * 1000
    idle_ms = cfg.prune.idle_hours * 3600 * 1000
    max_age_ms = cfg.prune.max_age_days * 86400 * 1000
    removed = 0

    for entry in list(registry.entries):
        idle_duration = now - entry.last_used_at_ms
        age = now - entry.created_at_ms

        should_remove = False
        reason = ""

        if idle_duration > idle_ms:
            should_remove = True
            reason = f"idle {idle_duration / 3600000:.1f}h"
        elif age > max_age_ms:
            should_remove = True
            reason = f"age {age / 86400000:.1f}d"

        if should_remove:
            log.info(
                "sandbox.pruning",
                {
                    "container": entry.container_name,
                    "reason": reason,
                },
            )
            await remove_container(entry.container_name)
            await remove_registry_entry(entry.container_name)
            removed += 1

    return removed
