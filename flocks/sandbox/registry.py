"""
容器注册表

对齐 OpenClaw sandbox/registry.ts：
- JSON 文件持久化容器元数据
- 跟踪 containerName, sessionKey, createdAtMs, lastUsedAtMs, image, configHash
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

from .defaults import SANDBOX_REGISTRY_PATH, SANDBOX_STATE_DIR

from flocks.utils.log import Log

log = Log.create(service="sandbox.registry")


class RegistryEntry:
    """容器注册表条目."""

    def __init__(
        self,
        container_name: str,
        session_key: str,
        created_at_ms: float,
        last_used_at_ms: float,
        image: str,
        config_hash: Optional[str] = None,
    ):
        self.container_name = container_name
        self.session_key = session_key
        self.created_at_ms = created_at_ms
        self.last_used_at_ms = last_used_at_ms
        self.image = image
        self.config_hash = config_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "containerName": self.container_name,
            "sessionKey": self.session_key,
            "createdAtMs": self.created_at_ms,
            "lastUsedAtMs": self.last_used_at_ms,
            "image": self.image,
            "configHash": self.config_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistryEntry":
        return cls(
            container_name=data.get("containerName", ""),
            session_key=data.get("sessionKey", ""),
            created_at_ms=data.get("createdAtMs", 0),
            last_used_at_ms=data.get("lastUsedAtMs", 0),
            image=data.get("image", ""),
            config_hash=data.get("configHash"),
        )


class Registry:
    """容器注册表（JSON 文件）."""

    def __init__(self):
        self.entries: List[RegistryEntry] = []

    def to_dict(self) -> Dict[str, Any]:
        return {"entries": [e.to_dict() for e in self.entries]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Registry":
        registry = cls()
        for entry_data in data.get("entries", []):
            registry.entries.append(RegistryEntry.from_dict(entry_data))
        return registry


def _ensure_state_dir() -> None:
    """确保注册表目录存在."""
    os.makedirs(SANDBOX_STATE_DIR, exist_ok=True)


async def read_registry() -> Registry:
    """读取容器注册表."""
    try:
        if not os.path.exists(SANDBOX_REGISTRY_PATH):
            return Registry()
        with open(SANDBOX_REGISTRY_PATH, "r") as f:
            data = json.load(f)
        return Registry.from_dict(data)
    except Exception as e:
        log.warn("registry.read_failed", {"error": str(e)})
        return Registry()


async def write_registry(registry: Registry) -> None:
    """写入容器注册表."""
    try:
        _ensure_state_dir()
        with open(SANDBOX_REGISTRY_PATH, "w") as f:
            json.dump(registry.to_dict(), f, indent=2)
    except Exception as e:
        log.warn("registry.write_failed", {"error": str(e)})


async def update_registry(
    container_name: str,
    session_key: str,
    created_at_ms: float,
    last_used_at_ms: float,
    image: str,
    config_hash: Optional[str] = None,
) -> None:
    """更新或添加注册表条目."""
    registry = await read_registry()

    # 查找现有条目
    existing = None
    for entry in registry.entries:
        if entry.container_name == container_name:
            existing = entry
            break

    now = time.time() * 1000

    if existing:
        existing.last_used_at_ms = last_used_at_ms
        if config_hash is not None:
            existing.config_hash = config_hash
    else:
        registry.entries.append(
            RegistryEntry(
                container_name=container_name,
                session_key=session_key,
                created_at_ms=created_at_ms,
                last_used_at_ms=last_used_at_ms,
                image=image,
                config_hash=config_hash,
            )
        )

    await write_registry(registry)


async def remove_registry_entry(container_name: str) -> None:
    """移除注册表条目."""
    registry = await read_registry()
    registry.entries = [
        e for e in registry.entries if e.container_name != container_name
    ]
    await write_registry(registry)


async def find_registry_entry(
    container_name: str,
) -> Optional[RegistryEntry]:
    """查找注册表条目."""
    registry = await read_registry()
    for entry in registry.entries:
        if entry.container_name == container_name:
            return entry
    return None
