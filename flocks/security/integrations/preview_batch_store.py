"""Short-lived storage for confirmed Runtime v2 preview batches.

Only bounded, normalized Evidence Event-like summaries are accepted.  The
store rejects raw payload containers and secret-like fields, enforces a TTL,
and marks a batch as consumed after a successful Confirm Ingest run.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from flocks.security.safe_export import is_raw_payload_key, is_sensitive_key, safe_export_value
from flocks.storage.storage import Storage

PREVIEW_BATCH_PREFIX = "security/integration_preview_batches/"
PREVIEW_BATCH_STORAGE_TYPE = "security.integration_preview_batches"
DEFAULT_PREVIEW_BATCH_TTL_SECONDS = 30 * 60
MAX_PREVIEW_BATCH_ITEMS = 200
MAX_PREVIEW_BATCH_BYTES = 512 * 1024

_PREVIEW_ITEM_FIELDS = frozenset(
    {
        "external_event_id",
        "external_id",
        "event_id",
        "title",
        "description",
        "severity",
        "source",
        "source_type",
        "asset_id",
        "ioc",
        "occurred_at",
        "alert_type",
        "key_fields",
        "payload_hash",
        "query_hint",
        "metadata",
        "package_id",
        "capability",
        "integration_instance_id",
        "preview_only",
    }
)


class PreviewBatchError(ValueError):
    """Stable validation error raised while resolving or consuming a batch."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return None
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if is_sensitive_key(key_text) or is_raw_payload_key(key_text):
                continue
            safe[key_text] = _safe_value(child, depth=depth + 1)
        return safe
    if isinstance(value, list | tuple):
        return [_safe_value(item, depth=depth + 1) for item in list(value)[:50]]
    return safe_export_value(value, max_string_length=1000, max_list_items=50, max_depth=max(0, 5 - depth))


def sanitize_preview_item(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        return {}
    sanitized: dict[str, Any] = {}
    for key, value in item.items():
        key_text = str(key)
        normalized = key_text.strip().lower().replace("-", "_")
        if normalized not in _PREVIEW_ITEM_FIELDS:
            continue
        if is_sensitive_key(key_text) or is_raw_payload_key(key_text):
            continue
        sanitized[normalized] = _safe_value(value)
    return sanitized


def sanitize_preview_items(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [safe for item in items[:MAX_PREVIEW_BATCH_ITEMS] if (safe := sanitize_preview_item(item))]


def _safe_mapping(value: Any) -> dict[str, Any]:
    safe = _safe_value(value if isinstance(value, Mapping) else {})
    return safe if isinstance(safe, dict) else {}


class PreviewBatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    preview_batch_id: str
    preview_run_id: str
    sync_profile_id: str
    instance_id: str
    package_id: str
    capability: str
    item_count: int
    items: list[dict[str, Any]] = Field(default_factory=list)
    cursor: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    expires_at: str
    consumed_at: str | None = None
    consumed_by_run_id: str | None = None

    @field_validator("items", mode="before")
    @classmethod
    def _sanitize_items(cls, value: Any) -> list[dict[str, Any]]:
        return sanitize_preview_items(value)

    @field_validator("cursor", "summary", "metadata", mode="before")
    @classmethod
    def _sanitize_mappings(cls, value: Any) -> dict[str, Any]:
        return _safe_mapping(value)


class PreviewBatchStore:
    """Storage-backed short-term PreviewBatch store."""

    def __init__(
        self,
        *,
        ttl_seconds: int = DEFAULT_PREVIEW_BATCH_TTL_SECONDS,
        max_items: int = MAX_PREVIEW_BATCH_ITEMS,
        max_bytes: int = MAX_PREVIEW_BATCH_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.max_items = min(max(1, int(max_items)), MAX_PREVIEW_BATCH_ITEMS)
        self.max_bytes = max(1024, int(max_bytes))
        self.clock = clock or _utc_now
        self._consume_lock = asyncio.Lock()

    async def create(
        self,
        *,
        preview_run_id: str,
        sync_profile_id: str,
        instance_id: str,
        package_id: str,
        capability: str,
        items: list[dict[str, Any]],
        cursor: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        preview_batch_id: str | None = None,
    ) -> PreviewBatch:
        await self.delete_expired()
        if len(items) > self.max_items:
            raise PreviewBatchError("preview_batch_too_large", f"Preview batch exceeds the {self.max_items} item limit")
        safe_items = sanitize_preview_items(items)
        if len(safe_items) != len(items):
            raise PreviewBatchError("preview_batch_invalid", "Preview batch contains unsupported items")

        now = self.clock().astimezone(UTC)
        batch = PreviewBatch(
            preview_batch_id=preview_batch_id or f"previewbatch_{uuid4().hex}",
            preview_run_id=preview_run_id,
            sync_profile_id=sync_profile_id,
            instance_id=instance_id,
            package_id=package_id,
            capability=capability,
            item_count=len(safe_items),
            items=safe_items,
            cursor=cursor or {},
            summary=summary or {},
            metadata=metadata or {},
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat(),
        )
        encoded = json.dumps(batch.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise PreviewBatchError("preview_batch_too_large", f"Preview batch exceeds the {self.max_bytes} byte limit")
        await Storage.set(_batch_key(batch.preview_batch_id), batch, PREVIEW_BATCH_STORAGE_TYPE)
        return batch

    async def get(self, preview_batch_id: str) -> PreviewBatch | None:
        batch = await Storage.get(_batch_key(preview_batch_id), PreviewBatch)
        if batch is not None and _parse_time(batch.expires_at) <= self.clock().astimezone(UTC):
            await Storage.delete(_batch_key(preview_batch_id))
            return None
        return batch

    async def delete_expired(self) -> int:
        entries = await Storage.list_entries(PREVIEW_BATCH_PREFIX, PreviewBatch)
        now = self.clock().astimezone(UTC)
        expired_keys = [key for key, batch in entries if _parse_time(batch.expires_at) <= now]
        deleted = 0
        for key in expired_keys:
            deleted += int(await Storage.delete(key))
        return deleted

    async def find_by_preview_run_id(self, preview_run_id: str) -> PreviewBatch | None:
        await self.delete_expired()
        entries = await Storage.list_entries(PREVIEW_BATCH_PREFIX, PreviewBatch)
        matches = [batch for _, batch in entries if batch.preview_run_id == preview_run_id]
        if not matches:
            return None
        matches.sort(key=lambda batch: batch.created_at, reverse=True)
        return matches[0]

    async def require_available(
        self,
        preview_batch_id: str,
        *,
        sync_profile_id: str | None = None,
        instance_id: str | None = None,
        package_id: str | None = None,
        capability: str | None = None,
    ) -> PreviewBatch:
        batch = await self.get(preview_batch_id)
        if batch is None:
            raise PreviewBatchError("preview_batch_expired", "Preview batch was not found or has expired")
        if _parse_time(batch.expires_at) <= self.clock().astimezone(UTC):
            raise PreviewBatchError("preview_batch_expired", "Preview batch has expired; run Preview Sync again")
        if batch.consumed_at or batch.consumed_by_run_id:
            raise PreviewBatchError("preview_batch_consumed", "Preview batch has already been consumed")
        expected = {
            "sync_profile_id": sync_profile_id,
            "instance_id": instance_id,
            "package_id": package_id,
            "capability": capability,
        }
        for field, value in expected.items():
            if value is not None and getattr(batch, field) != value:
                raise PreviewBatchError("preview_batch_mismatch", "Preview batch does not match the selected Sync Profile")
        return batch

    async def consume(self, preview_batch_id: str, *, consumed_by_run_id: str) -> PreviewBatch:
        async with self._consume_lock:
            batch = await self.require_available(preview_batch_id)
            consumed = batch.model_copy(
                update={
                    "consumed_at": self.clock().astimezone(UTC).isoformat(),
                    "consumed_by_run_id": consumed_by_run_id,
                }
            )
            await Storage.set(_batch_key(preview_batch_id), consumed, PREVIEW_BATCH_STORAGE_TYPE)
            return consumed


def _batch_key(preview_batch_id: str) -> str:
    return f"{PREVIEW_BATCH_PREFIX}{preview_batch_id}"


default_preview_batch_store = PreviewBatchStore()

__all__ = [
    "DEFAULT_PREVIEW_BATCH_TTL_SECONDS",
    "MAX_PREVIEW_BATCH_BYTES",
    "MAX_PREVIEW_BATCH_ITEMS",
    "PreviewBatch",
    "PreviewBatchError",
    "PreviewBatchStore",
    "default_preview_batch_store",
    "sanitize_preview_item",
    "sanitize_preview_items",
]
