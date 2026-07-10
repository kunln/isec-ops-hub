"""Evidence Dispatcher skeleton for lightweight Integration Evidence Events.

This module intentionally does not call connectors, perform HTTP, access
credentials, create incidents, send notifications, or perform remediation.
Preview mode is read-only and only returns safe summaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from flocks.security.evidence_ingestion import ingest_external_events, summarize_external_event
from flocks.security.store import SecurityStore

_SENSITIVE_KEYWORDS = ("api_key", "apikey", "secret", "token", "password", "authorization", "cookie")
_RAW_KEYS = {
    "raw",
    "raw_event",
    "raw_data",
    "raw_payload",
    "payload",
    "source",
    "request",
    "response",
    "request_body",
    "response_body",
    "http_body",
    "http_req_body",
    "http_resp_body",
    "body",
    "logs",
    "events",
    "pcap",
    "packet",
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
    return lowered in _RAW_KEYS or any(keyword in lowered for keyword in _SENSITIVE_KEYWORDS)


def _safe_mapping(value: Any, warnings: list[str], prefix: str = "") -> Any:
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if _is_forbidden_key(key_text):
                warnings.append(f"dropped unsafe field: {path}")
                continue
            safe[key_text] = _safe_mapping(child, warnings, path)
        return safe
    if isinstance(value, list):
        return [_safe_mapping(item, warnings, prefix) for item in value]
    return value


def _safe_event(event: dict[str, Any], warnings: list[str], index: int) -> dict[str, Any]:
    for field_name in _REQUIRED_EVENT_FIELDS:
        if event.get(field_name) in (None, "", [], {}):
            warnings.append(f"event[{index}] missing {field_name}")
    safe = _safe_mapping(event, warnings)
    return safe if isinstance(safe, dict) else {}


def _safe_summary(summary: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    safe = _safe_mapping(summary, warnings)
    return safe if isinstance(safe, dict) else {}


def preview_evidence_events(
    events: list[dict[str, Any]],
    connector_context: dict[str, Any] | None = None,
) -> EvidenceDispatchResult:
    """Build read-only safe summaries for lightweight Evidence Events."""

    warnings: list[str] = []
    summaries: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        safe_event = _safe_event(event, warnings, index)
        summary = summarize_external_event(safe_event, connector_context=connector_context)
        summaries.append(_safe_summary(summary, warnings))
    return EvidenceDispatchResult(
        item_count=len(events),
        preview_only=True,
        warnings=warnings,
        event_summaries=summaries,
    )


async def dispatch_evidence_events(
    request: EvidenceDispatchRequest,
    *,
    store: SecurityStore | None = None,
) -> EvidenceDispatchResult:
    """Preview or explicitly dispatch lightweight Evidence Events to ingestion."""

    preview = preview_evidence_events(request.events, connector_context=request.connector_context)
    if request.preview_only:
        return preview

    ingestion = await ingest_external_events(
        [_safe_event(event, preview.warnings, index) for index, event in enumerate(request.events)],
        connector_context=request.connector_context,
        create_analysis_cases=request.create_analysis_cases,
        run_initial_analysis=request.run_initial_analysis,
        deduplicate=request.deduplicate,
        store=store,
    )
    errors = [str(item.get("error")) for item in ingestion.get("items", []) if item.get("error")]
    return EvidenceDispatchResult(
        item_count=len(request.events),
        preview_only=False,
        created_alerts=int(ingestion.get("created_alerts", 0)),
        created_analysis_cases=int(ingestion.get("created_analysis_cases", 0)),
        skipped_duplicates=int(ingestion.get("skipped_duplicates", 0)),
        errors=errors,
        warnings=preview.warnings,
        event_summaries=preview.event_summaries,
    )
