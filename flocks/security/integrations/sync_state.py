"""Controlled Sync Profile run-state updates for Integration Runtime v2.

This helper updates Sync Profile run metadata after a successful manual ingest
only. It does not call connectors, perform HTTP, read credentials, resolve
secret refs, dispatch evidence, or create Security objects.
"""

from __future__ import annotations

import inspect
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from flocks.security.integrations.adapter import sanitize_adapter_mapping
from flocks.security.integrations.sync_profile_store import default_sync_profile_store
from flocks.security.store import utc_now

_REDACTED = "[REDACTED]"
_RAW_LIKE_KEYS = {
    "raw", "raw_payload", "raw_response", "raw_data", "request", "response", "body",
    "request_body", "response_body", "packet", "pcap", "payload", "payload_bytes", "logs", "events",
}
_SECRET_LIKE_KEYS = {
    "api_key", "apikey", "secret", "token", "password", "credential", "authorization",
    "bearer", "access_token", "refresh_token", "cookie", "credential_value", "secret_ref",
}
_SECRET_VALUE_HINTS = (
    "bearer ", "begin private key", "api_key=", "apikey=", "password=", "secret=",
    "token=", "authorization:", "cookie:", "x-api-key",
)


class SyncStateUpdateRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sync_profile_id: str
    run_id: str
    status: str
    cursor: dict[str, Any] = Field(default_factory=dict)
    update_cursor: bool = False
    synced_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cursor", "metadata", mode="before")
    @classmethod
    def _sanitize_mapping(cls, value: Any) -> dict[str, Any]:
        sanitized = sanitize_sync_cursor(value if isinstance(value, dict) else {})
        return sanitized if isinstance(sanitized, dict) else {}


class SyncStateUpdateResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    sync_profile_id: str
    run_id: str
    status: str
    cursor_updated: bool = False
    last_run_updated: bool = False
    last_status_updated: bool = False
    last_synced_at_updated: bool = False
    errors: list[str] = Field(default_factory=list)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _normalize_key(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_")


def _is_raw_like_key(key: Any) -> bool:
    return _normalize_key(key) in _RAW_LIKE_KEYS


def _is_secret_like_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    return normalized in _SECRET_LIKE_KEYS or any(part in _SECRET_LIKE_KEYS for part in normalized.split("_"))


def _is_secret_like_value(value: Any) -> bool:
    return isinstance(value, str) and any(hint in value.lower() for hint in _SECRET_VALUE_HINTS)


def sanitize_sync_cursor(value: Any) -> Any:
    """Return cursor-safe data with raw containers removed and secrets redacted."""

    value = sanitize_adapter_mapping(value)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if _is_raw_like_key(key) or _is_secret_like_key(key):
                continue
            sanitized[str(key)] = sanitize_sync_cursor(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_sync_cursor(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_sync_cursor(item) for item in value]
    if _is_secret_like_value(value) or value == _REDACTED:
        return _REDACTED
    return value


async def update_sync_profile_run_state(
    request: SyncStateUpdateRequest,
    *,
    sync_profile_store=None,
) -> SyncStateUpdateResult:
    """Update Sync Profile run state without crossing Integration/Security boundaries."""

    request = request if isinstance(request, SyncStateUpdateRequest) else SyncStateUpdateRequest.model_validate(request)
    sync_profile_store = sync_profile_store or default_sync_profile_store
    profile = await _maybe_await(sync_profile_store.get_profile(request.sync_profile_id))
    if profile is None:
        return SyncStateUpdateResult(
            sync_profile_id=request.sync_profile_id,
            run_id=request.run_id,
            status=request.status,
            errors=["Sync profile not found"],
        )

    safe_cursor = sanitize_sync_cursor(request.cursor) if request.update_cursor and request.cursor else None
    updated = await _maybe_await(sync_profile_store.update_profile_run_state(
        request.sync_profile_id,
        last_run_id=request.run_id,
        last_status=request.status,
        last_synced_at=request.synced_at or utc_now(),
        cursor=safe_cursor if isinstance(safe_cursor, dict) and safe_cursor else None,
    ))
    if updated is None:
        return SyncStateUpdateResult(
            sync_profile_id=request.sync_profile_id,
            run_id=request.run_id,
            status=request.status,
            errors=["Sync profile not found"],
        )
    return SyncStateUpdateResult(
        sync_profile_id=request.sync_profile_id,
        run_id=request.run_id,
        status=request.status,
        cursor_updated=isinstance(safe_cursor, dict) and bool(safe_cursor),
        last_run_updated=True,
        last_status_updated=True,
        last_synced_at_updated=True,
    )
