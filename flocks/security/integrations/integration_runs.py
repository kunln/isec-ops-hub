"""Integration Run v2 metadata skeleton.

Integration Runs record safe run summaries only. This module does not execute
connectors, perform HTTP requests, read credentials, sync data, or create
Security objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.connector_runs import sanitize_connector_request_summary, sanitize_error_message
from flocks.security.models import ConnectorSyncRun
from flocks.security.store import utc_now


class _IntegrationRunBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class IntegrationRun(_IntegrationRunBaseModel):
    """Safe Integration Runtime v2 run metadata."""

    integration_run_id: str
    package_id: str | None = None
    capability: str | None = None
    instance_id: str | None = None
    sync_profile_id: str | None = None
    connector_run_id: str | None = None
    status: str = "pending"
    trigger: str | None = None
    started_at: str = ""
    finished_at: str | None = None
    requested_by: str | None = None
    request_summary: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    item_refs: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationRunCreate(_IntegrationRunBaseModel):
    """Create payload for Integration Run metadata."""

    package_id: str | None = None
    capability: str | None = None
    instance_id: str | None = None
    sync_profile_id: str | None = None
    connector_run_id: str | None = None
    status: str = "pending"
    trigger: str | None = None
    requested_by: str | None = None
    request_summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationRunUpdate(_IntegrationRunBaseModel):
    """Patch payload for Integration Run metadata."""

    status: str | None = None
    finished_at: str | None = None
    result_summary: dict[str, Any] | None = None
    error_message: str | None = None
    item_refs: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None


def build_integration_run_from_connector_sync_run(run: ConnectorSyncRun) -> IntegrationRun:
    """Convert a legacy ConnectorSyncRun record into safe Integration Run metadata."""

    now = utc_now()
    return IntegrationRun(
        integration_run_id=f"intrun_{run.id}",
        connector_run_id=run.id,
        package_id=run.metadata.get("package_id") if isinstance(run.metadata, dict) else None,
        capability=run.metadata.get("capability") if isinstance(run.metadata, dict) else None,
        status=run.status,
        trigger=run.metadata.get("trigger") if isinstance(run.metadata, dict) else None,
        started_at=run.started_at,
        finished_at=run.finished_at,
        requested_by=run.requested_by,
        request_summary=sanitize_connector_request_summary(run.request_summary),
        result_summary=dict(run.result_summary),
        error_message=sanitize_error_message(run.error_message) if run.error_message else None,
        item_refs=list(run.item_refs),
        created_at=run.created_at or now,
        updated_at=run.updated_at or now,
        metadata={"source": "connector_sync_run"},
    )


# Backward-compatible alias requested by PR #37 consumers.
integration_run_from_connector_run = build_integration_run_from_connector_sync_run
