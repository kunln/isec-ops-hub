"""Evidence Dispatcher skeleton for lightweight Integration evidence events.

This module bridges Mapping Engine output to the existing evidence ingestion
preview/build path. It intentionally does not call connectors, perform HTTP,
read credentials, create incidents, send notifications, or remediate anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from flocks.security.evidence_ingestion import ingest_external_events, summarize_external_event

_RAW_OR_VERBOSE_KEYS = {
    "raw",
    "raw_event",
    "raw_payload",
    "raw_data",
    "source",
    "request",
    "response",
    "request_body",
    "response_body",
    "body",
    "packet",
    "pcap",
    "payload",
    "incident_id",
    "remediation",
    "remediation_action",
    "action",
    "logs",
    "events",
}
_CREDENTIAL_KEYS = {
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "authorization",
    "cookie",
}
_REQUIRED_EVENT_FIELDS = ("title", "severity", "external_event_id")


@dataclass(slots=True)
class EvidenceDispatchRequest:
    events: list[dict[str, Any]]
    connector_context: dict[str, Any] | None = None
    create_analysis_cases: bool = False
    run_initial_analysis: bool = False
    deduplicate: bool = True
    preview_only: bool = True


@dataclass(slots=True)
class EvidenceDispatchResult:
    item_count: int
    preview_only: bool
    created_alerts: int = 0
    created_analysis_cases: int = 0
    skipped_duplicates: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    event_summaries: list[dict[str, Any]] = field(default_factory=list)


def _is_forbidden_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _RAW_OR_VERBOSE_KEYS or lowered in _CREDENTIAL_KEYS or any(sensitive in lowered for sensitive in _CREDENTIAL_KEYS)


def _safe_value(value: Any, warnings: list[str], path: str) -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if _is_forbidden_key(key_text):
                warnings.append(f"dropped unsafe field from preview summary: {child_path}")
                continue
            safe[key_text] = _safe_value(child, warnings, child_path)
        return safe
    if isinstance(value, list):
        return [_safe_value(item, warnings, path) for item in value]
    return value


def _event_warnings(event: dict[str, Any], index: int) -> list[str]:
    warnings: list[str] = []
    for field_name in _REQUIRED_EVENT_FIELDS:
        if event.get(field_name) in (None, "", [], {}):
            warnings.append(f"event[{index}] missing {field_name}")
    for key in event:
        if _is_forbidden_key(str(key)):
            warnings.append(f"event[{index}] contains unsafe field {key}; field is omitted from preview summary")
    return warnings


def _safe_summary(event: dict[str, Any], *, connector_context: dict[str, Any] | None, index: int, warnings: list[str]) -> dict[str, Any]:
    warnings.extend(_event_warnings(event, index))
    summary = summarize_external_event(event, connector_context=connector_context)
    return _safe_value(summary, warnings, "summary")


def preview_evidence_events(events: list[dict[str, Any]], connector_context: dict[str, Any] | None = None) -> EvidenceDispatchResult:
    """Preview lightweight Evidence Events without writing to the Security store."""

    warnings: list[str] = []
    summaries = [
        _safe_summary(event, connector_context=connector_context, index=index, warnings=warnings)
        for index, event in enumerate(events)
    ]
    return EvidenceDispatchResult(item_count=len(events), preview_only=True, warnings=warnings, event_summaries=summaries)


async def dispatch_evidence_events(request: EvidenceDispatchRequest, *, store=None) -> EvidenceDispatchResult:
    """Dispatch Evidence Events, defaulting to read-only preview mode.

    Non-preview dispatch is only performed when ``request.preview_only`` is
    explicitly false, and delegates to the existing evidence ingestion pipeline.
    """

    if request.preview_only:
        return preview_evidence_events(request.events, connector_context=request.connector_context)

    warnings: list[str] = []
    summaries = [
        _safe_summary(event, connector_context=request.connector_context, index=index, warnings=warnings)
        for index, event in enumerate(request.events)
    ]
    ingested = await ingest_external_events(
        request.events,
        connector_context=request.connector_context,
        create_analysis_cases=request.create_analysis_cases,
        run_initial_analysis=request.run_initial_analysis,
        deduplicate=request.deduplicate,
        store=store,
    )
    errors = [str(item.get("error")) for item in ingested.get("items", []) if item.get("error")]
    return EvidenceDispatchResult(
        item_count=len(request.events),
        preview_only=False,
        created_alerts=int(ingested.get("created_alerts", 0)),
        created_analysis_cases=int(ingested.get("created_analysis_cases", 0)),
        skipped_duplicates=int(ingested.get("skipped_duplicates", 0)),
        errors=errors,
        warnings=warnings,
        event_summaries=summaries,
    )
