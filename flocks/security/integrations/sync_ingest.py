"""Explicit Confirm Ingest for a previously captured Runtime v2 preview batch."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from flocks.security.integrations.adapter import sanitize_adapter_mapping
from flocks.security.integrations.evidence_dispatcher import EvidenceDispatchRequest, dispatch_evidence_events
from flocks.security.integrations.instance_store import default_integration_instance_store
from flocks.security.integrations.preview_batch_store import (
    PreviewBatch,
    PreviewBatchError,
    default_preview_batch_store,
    sanitize_preview_item,
)
from flocks.security.integrations.run_store import default_integration_run_store
from flocks.security.integrations.runs import IntegrationRunCreate, safe_export_item_refs, safe_export_summary
from flocks.security.integrations.sync_profile_store import default_sync_profile_store
from flocks.security.integrations.sync_state import SyncStateUpdateRequest, update_sync_profile_run_state

_SECRET_LIKE_KEYS = {
    "api_key", "apikey", "secret", "token", "password", "passwd", "credential", "authorization",
    "bearer", "access_token", "refresh_token", "cookie", "credential_value", "secret_ref", "sign",
    "auth_timestamp",
}
_SECRET_VALUE_HINTS = (
    "bearer ", "begin private key", "api_key=", "apikey=", "password=", "passwd=", "secret=",
    "token=", "authorization:", "cookie:", "x-api-key", "sign=", "auth_timestamp=",
)

_INGEST_LOCK = asyncio.Lock()


def _normalize_key(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_")


def _is_secret_like_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    return normalized in _SECRET_LIKE_KEYS or any(part in _SECRET_LIKE_KEYS for part in normalized.split("_"))


def _is_secret_like_value(value: Any) -> bool:
    return isinstance(value, str) and any(hint in value.lower() for hint in _SECRET_VALUE_HINTS)


def _validate_no_secrets(value: Any, path: str = "params_override") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _is_secret_like_key(key):
                raise ValueError(f"secret-like key is not allowed in {path}")
            _validate_no_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_secrets(child, f"{path}[{index}]")
    elif _is_secret_like_value(value):
        raise ValueError(f"secret-like value is not allowed in {path}")


class ManualSyncIngestRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sync_profile_id: str
    preview_batch_id: str | None = None
    preview_run_id: str | None = None
    requested_by: str | None = None
    params_override: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    preview_only: bool = False
    confirmed: bool = False
    create_analysis_cases: bool = False
    run_initial_analysis: bool = False

    @field_validator("params_override", mode="before")
    @classmethod
    def _validate_params_override(cls, value: Any) -> dict[str, Any]:
        params = value if isinstance(value, dict) else {}
        _validate_no_secrets(params)
        sanitized = sanitize_adapter_mapping(params)
        return sanitized if isinstance(sanitized, dict) else {}

    @model_validator(mode="after")
    def _force_safety_flags(self) -> "ManualSyncIngestRequest":
        object.__setattr__(self, "dry_run", True)
        object.__setattr__(self, "preview_only", False)
        object.__setattr__(self, "create_analysis_cases", False)
        object.__setattr__(self, "run_initial_analysis", False)
        return self


class ManualSyncIngestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    dry_run: bool = True
    preview_only: bool = False
    confirmed: bool = False
    sync_profile_id: str
    preview_batch_id: str | None = None
    preview_run_id: str | None = None
    run_id: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    capability: str | None = None
    adapter_id: str | None = None
    fetched_count: int = 0
    mapped_count: int = 0
    ingested_count: int = 0
    created_alerts: int = 0
    created_analysis_cases: int = 0
    skipped_duplicates: int = 0
    item_refs: list[dict[str, Any]] = Field(default_factory=list)
    event_summaries: list[dict[str, Any]] = Field(default_factory=list)
    request_summary: dict[str, Any] = Field(default_factory=dict)
    adapter_summary: dict[str, Any] = Field(default_factory=dict)
    mapping_summary: dict[str, Any] = Field(default_factory=dict)
    dispatch_summary: dict[str, Any] = Field(default_factory=dict)
    safety_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _batch_items_to_ingest_events(batch: PreviewBatch) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(batch.items):
        event = sanitize_preview_item({**item, "preview_only": False})
        event_id = (
            event.get("external_event_id")
            or event.get("external_id")
            or event.get("event_id")
            or f"{batch.sync_profile_id}:{index}"
        )
        event["external_event_id"] = str(event_id)
        event["external_id"] = str(event_id)
        event["event_id"] = str(event_id)
        event["preview_only"] = False
        events.append(event)
    return events


async def _record_run(run_store: Any, payload: IntegrationRunCreate) -> Any:
    return await _maybe_await(run_store.create_run(payload))


async def ingest_sync_profile_run(
    request: ManualSyncIngestRequest,
    *,
    sync_profile_store=None,
    instance_store=None,
    run_store=None,
    preview_batch_store=None,
    adapter_registry=None,
    mapping_rules: list[Any] | None = None,
) -> ManualSyncIngestResult:
    """Ingest exactly the normalized items shown by Preview Sync.

    ``adapter_registry`` remains an accepted keyword for source compatibility,
    but is deliberately never resolved or called on this confirmation path.
    """

    del adapter_registry
    request = (
        ManualSyncIngestRequest(**request.model_dump(mode="json"))
        if isinstance(request, ManualSyncIngestRequest)
        else ManualSyncIngestRequest.model_validate(request)
    )
    sync_profile_store = sync_profile_store or default_sync_profile_store
    instance_store = instance_store or default_integration_instance_store
    run_store = run_store or default_integration_run_store
    preview_batch_store = preview_batch_store or default_preview_batch_store

    if request.confirmed is not True:
        return ManualSyncIngestResult(
            status="confirmation_required",
            sync_profile_id=request.sync_profile_id,
            confirmed=False,
            errors=["confirmed=True is required for manual sync ingest"],
        )

    try:
        _validate_no_secrets(request.params_override)
    except ValueError as exc:
        return ManualSyncIngestResult(
            status="validation_failed",
            sync_profile_id=request.sync_profile_id,
            confirmed=True,
            errors=[str(exc)],
        )

    profile = await _maybe_await(sync_profile_store.get_profile(request.sync_profile_id))
    if profile is None:
        return ManualSyncIngestResult(
            status="not_found",
            sync_profile_id=request.sync_profile_id,
            confirmed=True,
            errors=["Sync profile not found"],
        )

    base = {
        "sync_profile_id": profile.sync_profile_id,
        "package_id": profile.package_id,
        "instance_id": profile.instance_id,
        "capability": profile.capability,
        "confirmed": True,
        "preview_batch_id": request.preview_batch_id,
        "preview_run_id": request.preview_run_id,
        "request_summary": safe_export_summary(
            {
                "dry_run": True,
                "preview_only": False,
                "confirmed": True,
                "preview_batch_id": request.preview_batch_id,
                "preview_run_id": request.preview_run_id,
            }
        ),
        "safety_summary": {
            "dry_run": True,
            "preview_only": False,
            "confirmed": True,
            "adapter_called": False,
            "device_called": False,
            "credentials_read": False,
            "secret_ref_resolved": False,
            "create_analysis_cases": False,
            "run_initial_analysis": False,
            "cursor_updated": False,
            "last_run_id_updated": False,
            "last_status_updated": False,
            "last_synced_at_updated": False,
        },
        "limitations": [
            "manual preview confirmation required",
            "uses the selected normalized PreviewBatch only",
            "no adapter or vendor device re-query",
            "no analysis cases or incidents",
            "no notifications or remediation",
        ],
    }

    async def validation_failed(code: str, message: str) -> ManualSyncIngestResult:
        run = await _record_run(
            run_store,
            IntegrationRunCreate(
                run_type="sync_profile_ingest",
                package_id=profile.package_id,
                instance_id=profile.instance_id,
                sync_profile_id=profile.sync_profile_id,
                capability=profile.capability,
                mode=profile.mode,
                status=code,
                requested_by=request.requested_by,
                request_summary=base["request_summary"],
                result_summary={
                    "status": code,
                    "created_alerts": 0,
                    "created_analysis_cases": 0,
                    "skipped_duplicates": 0,
                    "ingested_count": 0,
                },
                error_message=message,
                metadata={
                    "source": "ManualSyncIngest",
                    "dry_run": True,
                    "preview_only": False,
                    "confirmed": True,
                },
            ),
        )
        return ManualSyncIngestResult(status=code, run_id=run.run_id, errors=[message], **base)

    if not request.preview_batch_id and not request.preview_run_id:
        return await validation_failed(
            "preview_batch_required",
            "preview confirmation required: provide preview_batch_id from Preview Sync",
        )

    instance = await _maybe_await(instance_store.get_instance(profile.instance_id))
    if instance is None:
        return await validation_failed("preview_batch_mismatch", "Integration instance was not found")

    async with _INGEST_LOCK:
        batch_id = request.preview_batch_id
        if not batch_id and request.preview_run_id:
            by_run = await _maybe_await(preview_batch_store.find_by_preview_run_id(request.preview_run_id))
            if by_run is None:
                return await validation_failed("preview_batch_expired", "Preview batch was not found or has expired")
            batch_id = by_run.preview_batch_id

        assert batch_id is not None
        try:
            batch = await _maybe_await(
                preview_batch_store.require_available(
                    batch_id,
                    sync_profile_id=profile.sync_profile_id,
                    instance_id=profile.instance_id,
                    package_id=profile.package_id,
                    capability=profile.capability,
                )
            )
            if request.preview_run_id and batch.preview_run_id != request.preview_run_id:
                raise PreviewBatchError("preview_batch_mismatch", "Preview run does not match PreviewBatch")
        except PreviewBatchError as exc:
            return await validation_failed(exc.code, exc.message)

        events = _batch_items_to_ingest_events(batch)
        dispatch_result = await dispatch_evidence_events(
            EvidenceDispatchRequest(
                events=events,
                connector_context={
                    "package_id": profile.package_id,
                    "instance_id": profile.instance_id,
                    "connector_id": profile.instance_id,
                    "connector_name": getattr(instance, "display_name", None),
                    "vendor": getattr(instance, "vendor", None),
                    "product": getattr(instance, "product", None),
                },
                preview_only=False,
                create_analysis_cases=False,
                run_initial_analysis=False,
                deduplicate=bool(getattr(profile, "deduplicate", True)),
            )
        )
        if dispatch_result.errors:
            return await validation_failed("validation_failed", "PreviewBatch evidence dispatch failed")

        item_refs = safe_export_item_refs(
            [
                {
                    "id": event.get("external_event_id"),
                    "external_event_id": event.get("external_event_id"),
                    "source": event.get("source"),
                    "severity": event.get("severity"),
                    "payload_hash": event.get("payload_hash"),
                }
                for event in events
            ]
        )
        ingested_count = int(dispatch_result.created_alerts)
        result_summary = safe_export_summary(
            {
                "status": "ingested",
                "preview_batch_id": batch.preview_batch_id,
                "preview_run_id": batch.preview_run_id,
                "fetched_count": batch.item_count,
                "mapped_count": len(events),
                "ingested_count": ingested_count,
                "created_alerts": dispatch_result.created_alerts,
                "created_analysis_cases": dispatch_result.created_analysis_cases,
                "skipped_duplicates": dispatch_result.skipped_duplicates,
            }
        )
        run = await _record_run(
            run_store,
            IntegrationRunCreate(
                run_type="sync_profile_ingest",
                package_id=profile.package_id,
                instance_id=profile.instance_id,
                sync_profile_id=profile.sync_profile_id,
                capability=profile.capability,
                mode=profile.mode,
                status="ingested",
                requested_by=request.requested_by,
                request_summary=safe_export_summary(
                    {
                        **base["request_summary"],
                        "preview_batch_id": batch.preview_batch_id,
                        "preview_run_id": batch.preview_run_id,
                    }
                ),
                result_summary=result_summary,
                item_refs=item_refs,
                metadata={
                    "source": "ManualSyncIngest",
                    "dry_run": True,
                    "preview_only": False,
                    "confirmed": True,
                    "preview_batch_id": batch.preview_batch_id,
                },
            ),
        )
        try:
            await _maybe_await(preview_batch_store.consume(batch.preview_batch_id, consumed_by_run_id=run.run_id))
        except PreviewBatchError as exc:
            return ManualSyncIngestResult(status=exc.code, run_id=run.run_id, errors=[exc.message], **base)

        state_update = await update_sync_profile_run_state(
            SyncStateUpdateRequest(
                sync_profile_id=profile.sync_profile_id,
                run_id=run.run_id,
                status="ingested",
                cursor=batch.cursor,
                update_cursor=bool(batch.cursor),
            ),
            sync_profile_store=sync_profile_store,
        )

    safety_summary = {
        **base["safety_summary"],
        "cursor_updated": state_update.cursor_updated,
        "last_run_id_updated": state_update.last_run_updated,
        "last_status_updated": state_update.last_status_updated,
        "last_synced_at_updated": state_update.last_synced_at_updated,
    }
    dispatch_summary = {
        "preview_only": dispatch_result.preview_only,
        "create_analysis_cases": False,
        "run_initial_analysis": False,
        "preview_batch_consumed": True,
        "cursor_updated": state_update.cursor_updated,
        "last_run_id_updated": state_update.last_run_updated,
        "last_status_updated": state_update.last_status_updated,
        "last_synced_at_updated": state_update.last_synced_at_updated,
    }
    adapter_summary = batch.summary.get("adapter_summary") if isinstance(batch.summary.get("adapter_summary"), dict) else {}
    return ManualSyncIngestResult(
        status="ingested",
        run_id=run.run_id,
        preview_batch_id=batch.preview_batch_id,
        preview_run_id=batch.preview_run_id,
        adapter_id=str(batch.metadata.get("adapter_id")) if batch.metadata.get("adapter_id") else None,
        fetched_count=batch.item_count,
        mapped_count=len(events),
        ingested_count=ingested_count,
        created_alerts=dispatch_result.created_alerts,
        created_analysis_cases=dispatch_result.created_analysis_cases,
        skipped_duplicates=dispatch_result.skipped_duplicates,
        item_refs=item_refs,
        event_summaries=dispatch_result.event_summaries,
        adapter_summary=safe_export_summary(adapter_summary),
        mapping_summary={"mode": "confirmed_preview_batch", "mapping_rules": len(mapping_rules or [])},
        dispatch_summary=dispatch_summary,
        safety_summary=safety_summary,
        warnings=dispatch_result.warnings,
        errors=[*dispatch_result.errors, *state_update.errors],
        **{
            key: value
            for key, value in base.items()
            if key not in {"preview_batch_id", "preview_run_id", "safety_summary"}
        },
    )
