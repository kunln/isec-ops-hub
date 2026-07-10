"""Sync Profile metadata skeleton.

Sync Profiles persist synchronization metadata, cursor references, parameters,
and scheduling intent only. They intentionally do not execute synchronization,
call connectors, perform HTTP requests, read credentials, dispatch evidence, or
create Security objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _SyncProfileBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")


class SyncProfile(_SyncProfileBaseModel):
    """Synchronization metadata for one Integration Instance capability."""

    sync_profile_id: str
    display_name: str
    instance_id: str
    package_id: str
    capability: str
    mode: str = "manual"
    enabled: bool = True
    schedule: str | None = None
    cursor: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    deduplicate: bool = True
    create_analysis_cases: bool = False
    run_initial_analysis: bool = False
    last_run_id: str | None = None
    last_status: str = "never_run"
    last_synced_at: str | None = None
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyncProfileCreate(_SyncProfileBaseModel):
    """Create payload for Sync Profile metadata.

    package_id is derived from the referenced Integration Instance and is not
    accepted in create payloads.
    """

    display_name: str
    instance_id: str
    capability: str
    mode: str = "manual"
    enabled: bool = True
    schedule: str | None = None
    cursor: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    deduplicate: bool = True
    create_analysis_cases: bool = False
    run_initial_analysis: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyncProfileUpdate(_SyncProfileBaseModel):
    """Patch payload for Sync Profile metadata."""

    display_name: str | None = None
    capability: str | None = None
    mode: str | None = None
    enabled: bool | None = None
    schedule: str | None = None
    cursor: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    deduplicate: bool | None = None
    create_analysis_cases: bool | None = None
    run_initial_analysis: bool | None = None
    last_run_id: str | None = None
    last_status: str | None = None
    last_synced_at: str | None = None
    metadata: dict[str, Any] | None = None
