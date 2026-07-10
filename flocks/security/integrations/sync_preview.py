"""Manual Sync Preview skeleton for Integration Runtime v2.

This module wires Sync Profile metadata to a safe adapter preview path. It does
not execute real synchronization, call vendor connectors, perform HTTP, resolve
credentials, persist evidence, create Security objects, send notifications, or
remediate.
"""

from __future__ import annotations

import inspect
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from flocks.security.integrations.adapter import IntegrationAdapterRequest, sanitize_adapter_mapping
from flocks.security.integrations.adapter_registry import create_default_adapter_registry
from flocks.security.integrations.evidence_dispatcher import EvidenceDispatchRequest, dispatch_evidence_events
from flocks.security.integrations.instance_store import default_integration_instance_store
from flocks.security.integrations.run_store import default_integration_run_store
from flocks.security.integrations.runs import IntegrationRunCreate, safe_export_item_refs, safe_export_summary
from flocks.security.integrations.sync_profile_store import default_sync_profile_store

_SECRET_LIKE_KEYS = {
    "api_key", "apikey", "secret", "token", "password", "credential", "authorization",
    "bearer", "access_token", "refresh_token", "cookie", "credential_value", "secret_ref",
}
_SECRET_VALUE_HINTS = (
    "bearer ", "begin private key", "api_key=", "apikey=", "password=", "secret=",
    "token=", "authorization:", "cookie:", "x-api-key",
)
_RAW_LIKE_KEYS = {
    "raw", "raw_payload", "raw_response", "raw_data", "request", "response", "body",
    "request_body", "response_body", "packet", "pcap", "payload", "logs", "events",
}


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


class ManualSyncPreviewRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sync_profile_id: str
    requested_by: str | None = None
    params_override: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    preview_only: bool = True

    @field_validator("params_override", mode="before")
    @classmethod
    def _validate_params_override(cls, value: Any) -> dict[str, Any]:
        params = value if isinstance(value, dict) else {}
        _validate_no_secrets(params)
        sanitized = sanitize_adapter_mapping(params)
        return sanitized if isinstance(sanitized, dict) else {}

    @model_validator(mode="after")
    def _force_preview_flags(self) -> "ManualSyncPreviewRequest":
        object.__setattr__(self, "dry_run", True)
        object.__setattr__(self, "preview_only", True)
        return self


class ManualSyncPreviewResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    dry_run: bool = True
    preview_only: bool = True
    sync_profile_id: str
    run_id: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    capability: str | None = None
    adapter_id: str | None = None
    fetched_count: int = 0
    mapped_count: int = 0
    preview_count: int = 0
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


def _safe_item_metadata(item: dict[str, Any]) -> dict[str, Any]:
    sanitized = sanitize_adapter_mapping(item)
    if not isinstance(sanitized, dict):
        return {}
    return {
        str(key): value
        for key, value in sanitized.items()
        if _normalize_key(key) not in _RAW_LIKE_KEYS and not _is_secret_like_key(key) and not _is_secret_like_value(value)
    }


def _adapter_items_to_preview_events(items: list[dict[str, Any]], profile: Any, instance: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        metadata = _safe_item_metadata(item)
        event_id = item.get("id") or item.get("item_id") or f"{profile.sync_profile_id}:{index}"
        events.append(
            {
                "external_event_id": str(event_id),
                "event_id": str(event_id),
                "event_type": profile.capability,
                "source": profile.package_id,
                "title": item.get("title") or item.get("name") or "Adapter preview item",
                "severity": item.get("severity"),
                "asset": item.get("asset") or item.get("target"),
                "metadata": metadata,
                "preview_only": True,
                "integration_instance_id": getattr(instance, "instance_id", None),
            }
        )
    return events


async def _record_run(run_store: Any, payload: IntegrationRunCreate) -> Any:
    return await _maybe_await(run_store.create_run(payload))


async def preview_sync_profile_run(
    request: ManualSyncPreviewRequest,
    *,
    sync_profile_store=None,
    instance_store=None,
    run_store=None,
    adapter_registry=None,
    mapping_rules: list[Any] | None = None,
) -> ManualSyncPreviewResult:
    request = ManualSyncPreviewRequest(**request.model_dump(mode="json")) if isinstance(request, ManualSyncPreviewRequest) else ManualSyncPreviewRequest.model_validate(request)
    sync_profile_store = sync_profile_store or default_sync_profile_store
    instance_store = instance_store or default_integration_instance_store
    run_store = run_store or default_integration_run_store
    adapter_registry = adapter_registry or create_default_adapter_registry(include_fake=True)

    try:
        _validate_no_secrets(request.params_override)
    except ValueError as exc:
        return ManualSyncPreviewResult(status="validation_failed", sync_profile_id=request.sync_profile_id, errors=[str(exc)])

    profile = await _maybe_await(sync_profile_store.get_profile(request.sync_profile_id))
    if profile is None:
        return ManualSyncPreviewResult(status="not_found", sync_profile_id=request.sync_profile_id, errors=["Sync profile not found"])

    base = {
        "sync_profile_id": profile.sync_profile_id,
        "package_id": profile.package_id,
        "instance_id": profile.instance_id,
        "capability": profile.capability,
        "request_summary": safe_export_summary({"dry_run": True, "preview_only": True, "params": {**profile.params, **request.params_override}}),
        "safety_summary": {"dry_run": True, "preview_only": True, "credentials_read": False, "secret_ref_resolved": False},
        "limitations": ["preview only", "no real sync", "no vendor connector calls", "no persisted evidence dispatch"],
    }

    async def validation_failed(message: str, adapter_id: str | None = None) -> ManualSyncPreviewResult:
        run = await _record_run(run_store, IntegrationRunCreate(
            run_type="sync_profile_preview", package_id=profile.package_id, instance_id=profile.instance_id,
            sync_profile_id=profile.sync_profile_id, capability=profile.capability, mode=profile.mode,
            status="validation_failed", requested_by=request.requested_by, request_summary=base["request_summary"],
            result_summary={"status": "validation_failed", "error": message}, error_message=message,
            metadata={"source": "ManualSyncPreview", "dry_run": True, "preview_only": True},
        ))
        return ManualSyncPreviewResult(status="validation_failed", run_id=run.run_id, adapter_id=adapter_id, errors=[message], **base)

    instance = await _maybe_await(instance_store.get_instance(profile.instance_id))
    if instance is None:
        return await validation_failed("Integration instance not found")

    try:
        adapter = adapter_registry.require_adapter(profile.package_id, profile.capability)
    except Exception as exc:
        return await validation_failed(str(exc))

    adapter_id = getattr(adapter, "adapter_id", None)
    if profile.package_id != "fake.integration" and not adapter_registry:
        return await validation_failed("Only fake or injected adapters are allowed for preview", adapter_id)

    adapter_request = IntegrationAdapterRequest(
        package_id=profile.package_id, instance_id=profile.instance_id, capability=profile.capability,
        mode=profile.mode, params={**profile.params, **request.params_override}, cursor=profile.cursor,
        credential_ref=getattr(instance, "credential_profile_id", None), dry_run=True, requested_by=request.requested_by,
        metadata={"sync_profile_id": profile.sync_profile_id},
    )
    adapter_result = await adapter.run_capability(adapter_request)
    if adapter_result.status != "success":
        return await validation_failed("Adapter preview failed or capability unsupported", adapter_id)

    mapped_events = _adapter_items_to_preview_events(adapter_result.items, profile, instance)
    dispatch_result = await dispatch_evidence_events(EvidenceDispatchRequest(
        events=mapped_events, connector_context={"package_id": profile.package_id, "instance_id": profile.instance_id},
        preview_only=True, create_analysis_cases=False, run_initial_analysis=False,
    ))
    raw_item_refs = []
    for ref in adapter_result.item_refs:
        ref_data = {
            "id": (ref.item_id if hasattr(ref, "item_id") else ref.get("item_id") or ref.get("id")),
            "type": (ref.item_type if hasattr(ref, "item_type") else ref.get("item_type") or ref.get("type")),
            "source": (ref.source if hasattr(ref, "source") else ref.get("source")),
        }
        raw_item_refs.append({key: value for key, value in ref_data.items() if value not in (None, "")})
    item_refs = safe_export_item_refs(raw_item_refs)
    result_summary = safe_export_summary({
        "status": "previewed", "fetched_count": adapter_result.item_count, "mapped_count": len(mapped_events),
        "preview_count": dispatch_result.item_count, "adapter_summary": adapter_result.summary,
    })
    run = await _record_run(run_store, IntegrationRunCreate(
        run_type="sync_profile_preview", package_id=profile.package_id, instance_id=profile.instance_id,
        sync_profile_id=profile.sync_profile_id, capability=profile.capability, mode=profile.mode,
        status="previewed", requested_by=request.requested_by, request_summary=base["request_summary"],
        result_summary=result_summary, item_refs=item_refs,
        metadata={"source": "ManualSyncPreview", "dry_run": True, "preview_only": True},
    ))
    return ManualSyncPreviewResult(
        status="previewed", run_id=run.run_id, adapter_id=adapter_id, fetched_count=adapter_result.item_count,
        mapped_count=len(mapped_events), preview_count=dispatch_result.item_count, item_refs=item_refs,
        event_summaries=dispatch_result.event_summaries, adapter_summary=safe_export_summary(adapter_result.summary),
        mapping_summary={"mode": "safe_passthrough_preview", "mapping_rules": len(mapping_rules or [])},
        dispatch_summary={"preview_only": dispatch_result.preview_only, "create_analysis_cases": 0, "run_initial_analysis": False},
        warnings=[*adapter_result.warnings, *dispatch_result.warnings], errors=adapter_result.errors + dispatch_result.errors,
        **base,
    )
