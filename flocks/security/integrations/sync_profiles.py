"""Integration Sync Profile metadata skeleton.

Sync Profiles store declarative sync configuration metadata only. They do not
call connectors, perform HTTP requests, read credentials, execute sync, or
create Security objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _SyncProfileBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class SyncProfile(_SyncProfileBaseModel):
    """Safe metadata describing how an integration may be synced later."""

    sync_profile_id: str
    package_id: str
    capability: str
    display_name: str
    instance_id: str | None = None
    enabled: bool = False
    schedule: dict[str, Any] = Field(default_factory=dict)
    default_params: dict[str, Any] = Field(default_factory=dict)
    cursor_ref: str | None = None
    status: str = "draft"
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyncProfileCreate(_SyncProfileBaseModel):
    """Create payload for Sync Profile metadata."""

    package_id: str
    capability: str
    display_name: str
    instance_id: str | None = None
    enabled: bool = False
    schedule: dict[str, Any] = Field(default_factory=dict)
    default_params: dict[str, Any] = Field(default_factory=dict)
    cursor_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyncProfileUpdate(_SyncProfileBaseModel):
    """Patch payload for Sync Profile metadata."""

    package_id: str | None = None
    capability: str | None = None
    display_name: str | None = None
    instance_id: str | None = None
    enabled: bool | None = None
    schedule: dict[str, Any] | None = None
    default_params: dict[str, Any] | None = None
    cursor_ref: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None
