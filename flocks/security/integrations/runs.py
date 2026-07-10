"""Integration Run v2 models and compatibility helpers.

Integration Runs are a safe, upper-layer run-history view for future Sync
Profile, Capability Runtime, and Evidence Dispatcher work. They do not execute
connectors, perform HTTP, read credentials, or create Security objects.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from flocks.security.models import ConnectorSyncRun
from flocks.security.safe_export import is_raw_payload_key, is_sensitive_key, redact_sensitive_value, safe_export_value

MAX_ERROR_MESSAGE_LENGTH = 500
_ALLOWED_ITEM_REF_KEYS = {
    "type",
    "id",
    "title",
    "status",
    "hash",
    "external_event_id",
    "alert_id",
    "analysis_case_id",
    "incident_id",
    "asset_id",
    "vulnerability_id",
    "source",
    "severity",
    "payload_hash",
}
_SECRET_PATTERNS = [
    re.compile(r"(?i)(Authorization:\s*Bearer\s+)[^\s,;]+"),
    re.compile(r'(?i)(\"(?:api_key|apikey|token|password|secret|authorization|cookie|credential)\"\s*:\s*)\"[^\"]*\"'),
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization|cookie|credential)\s*[:=]\s*[^\s,;]+"),
]


def sanitize_integration_error_message(message: Any, max_length: int = MAX_ERROR_MESSAGE_LENGTH) -> str:
    """Return a short, credential-redacted error string for run history."""

    text = str(message or "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<redacted>", text)
    text = " ".join(text.split())
    return text[:max_length]


def safe_export_summary(value: dict[str, Any] | None) -> dict[str, Any]:
    """Safe-export summary/metadata and omit raw payload containers entirely."""

    if not value:
        return {}
    exported: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if is_raw_payload_key(key_text) or key_text.lower().replace("-", "_") in {"request", "response", "body"}:
            continue
        if is_sensitive_key(key_text):
            exported[key_text] = redact_sensitive_value(item)
            continue
        exported[key_text] = safe_export_value(item, max_string_length=512, max_list_items=20, max_depth=5)
    return exported


def safe_export_item_refs(value: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Return lightweight item references only; raw payloads and secrets are omitted."""

    refs: list[dict[str, Any]] = []
    for item in value or []:
        if not isinstance(item, dict):
            continue
        ref: dict[str, Any] = {}
        for key, raw_value in item.items():
            key_text = str(key)
            normalized = key_text.lower().replace("-", "_")
            if normalized not in _ALLOWED_ITEM_REF_KEYS or is_raw_payload_key(key_text) or normalized in {"request", "response", "body"} or is_sensitive_key(key_text):
                continue
            ref[key_text] = safe_export_value(raw_value, max_string_length=256, max_list_items=5, max_depth=2)
        if ref:
            refs.append(ref)
    return refs


class _IntegrationRunBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class IntegrationRun(_IntegrationRunBaseModel):
    run_id: str
    run_type: str = "manual"
    package_id: str | None = None
    instance_id: str | None = None
    sync_profile_id: str | None = None
    capability: str | None = None
    connector_id: str | None = None
    connector_name: str | None = None
    vendor: str | None = None
    product: str | None = None
    mode: str = "manual"
    status: str = "pending"
    started_at: str = ""
    finished_at: str | None = None
    requested_by: str | None = None
    request_summary: dict[str, Any] = Field(default_factory=dict)
    plan_summary: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    item_refs: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("request_summary", "plan_summary", "result_summary", "metadata", mode="before")
    @classmethod
    def _clean_summary_fields(cls, value: Any) -> dict[str, Any]:
        return safe_export_summary(value if isinstance(value, dict) else {})

    @field_validator("item_refs", mode="before")
    @classmethod
    def _clean_item_refs(cls, value: Any) -> list[dict[str, Any]]:
        return safe_export_item_refs(value if isinstance(value, list) else [])

    @field_validator("error_message", mode="before")
    @classmethod
    def _clean_error_message(cls, value: Any) -> str | None:
        if value in (None, ""):
            return None
        return sanitize_integration_error_message(value)


class IntegrationRunCreate(_IntegrationRunBaseModel):
    run_type: str = "manual"
    package_id: str | None = None
    instance_id: str | None = None
    sync_profile_id: str | None = None
    capability: str | None = None
    connector_id: str | None = None
    connector_name: str | None = None
    vendor: str | None = None
    product: str | None = None
    mode: str = "manual"
    status: str = "pending"
    requested_by: str | None = None
    request_summary: dict[str, Any] = Field(default_factory=dict)
    plan_summary: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    item_refs: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationRunUpdate(_IntegrationRunBaseModel):
    status: str | None = None
    finished_at: str | None = None
    request_summary: dict[str, Any] | None = None
    plan_summary: dict[str, Any] | None = None
    result_summary: dict[str, Any] | None = None
    error_message: str | None = None
    item_refs: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None


def build_integration_run_from_connector_sync_run(connector_run: ConnectorSyncRun) -> IntegrationRun:
    """Build a non-mutating Integration Run v2 view from a ConnectorSyncRun."""

    return IntegrationRun(
        run_id=f"intrun_{connector_run.id}",
        run_type="connector_sync",
        connector_id=connector_run.connector_id,
        connector_name=connector_run.connector_name,
        vendor=connector_run.vendor,
        product=connector_run.product,
        mode=connector_run.mode,
        status=connector_run.status,
        started_at=connector_run.started_at,
        finished_at=connector_run.finished_at,
        requested_by=connector_run.requested_by,
        request_summary=connector_run.request_summary,
        result_summary=connector_run.result_summary,
        error_message=connector_run.error_message,
        item_refs=connector_run.item_refs,
        created_at=connector_run.created_at,
        updated_at=connector_run.updated_at,
        metadata={**connector_run.metadata, "source": "ConnectorSyncRun", "source_run_id": connector_run.id},
    )


integration_run_from_connector_run = build_integration_run_from_connector_sync_run
