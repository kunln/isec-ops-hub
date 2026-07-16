"""Lightweight external evidence ingestion for Security Extension.

This module intentionally summarizes temporary connector/API/MCP responses into
Alert and Analysis Case evidence references. It must not persist full raw logs,
full API response bodies, packet captures, or other raw-event stores.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from flocks.security.analysis import build_analysis_case_from_alert, run_initial_analysis as refresh_initial_analysis
from flocks.security.models import AlertSource, SecuritySeverity
from flocks.security.schemas import AlertCreate, AnalysisCaseUpdate, AnalysisEvidenceItemCreate
from flocks.security.store import SecurityStore, default_store

MAX_KEY_FIELDS = 30
MAX_STRING_LENGTH = 1000
_CONTEXT_KEYS = {"connector_id", "connector_name", "vendor", "product", "source_type", "external_base_url"}
_DROP_FIELD_NAMES = {"raw", "raw_event", "raw_data", "payload", "request_body", "response_body", "body", "logs", "events"}
_PREFERRED_KEY_FIELDS = [
    "id", "event_id", "external_event_id", "timestamp", "occurred_at", "title", "severity", "action", "src_ip", "source_ip",
    "dst_ip", "destination_ip", "host", "hostname", "asset_id", "url", "path", "method", "rule", "rule_id", "signature",
    "attack_type", "alert_type", "ioc", "user", "username", "process", "command", "status", "category",
]


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _truncate(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING_LENGTH else value[:MAX_STRING_LENGTH] + "…[truncated]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_truncate(item) for item in value[:20]]
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for key, item in list(value.items())[:10]:
            if str(key).lower() in _DROP_FIELD_NAMES:
                continue
            compact[str(key)] = _truncate(item)
        return compact
    return _truncate(str(value))


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value not in (None, "", [], {}):
            return str(value)
    return None


def _first_reference(*values: Any) -> str | None:
    for value in values:
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            if candidate not in (None, "", [], {}):
                return str(candidate)
    return None


def _severity(value: Any) -> str:
    text = str(value or "medium").lower()
    aliases = {"informational": "info", "warning": "medium", "warn": "medium"}
    text = aliases.get(text, text)
    return text if text in {item.value for item in SecuritySeverity} else "medium"


def _source_type(value: Any) -> str:
    text = str(value or "other").lower()
    return text if text in {item.value for item in AlertSource} else "other"


def _key_fields(event: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    lowered = {str(key).lower(): key for key in event}
    for preferred in _PREFERRED_KEY_FIELDS:
        actual = lowered.get(preferred)
        if actual is not None and str(actual).lower() not in _DROP_FIELD_NAMES:
            result[str(actual)] = _truncate(event[actual])
        if len(result) >= MAX_KEY_FIELDS:
            return result
    for key, value in event.items():
        key_text = str(key)
        if key_text in result or key_text.lower() in _DROP_FIELD_NAMES:
            continue
        result[key_text] = _truncate(value)
        if len(result) >= MAX_KEY_FIELDS:
            break
    return result


def summarize_external_event(event: dict[str, Any], *, connector_context: dict | None = None) -> dict[str, Any]:
    """Return a compact evidence summary without embedding the full raw event."""
    context = connector_context or {}
    connector_id = _first_text(context.get("connector_id"), event.get("connector_id"), "external")
    evidence_source_type = _first_text(context.get("source_type"), event.get("source_type"), event.get("source"), "other")
    alert_source = _first_text(context.get("alert_source"), event.get("source"), evidence_source_type, "other")
    external_event_id = _first_text(event.get("external_event_id"), event.get("event_id"), event.get("id"))
    external_base_url = _first_text(context.get("external_base_url"))
    external_url = _first_text(event.get("external_url"), event.get("url_external"))
    if not external_url and external_base_url and external_event_id:
        external_url = f"{external_base_url.rstrip('/')}/{external_event_id}"

    title = _first_text(event.get("title"), event.get("name"), event.get("signature"), event.get("rule"), "External security event") or "External security event"
    description = _first_text(event.get("description"), event.get("message"), event.get("summary"), title) or title
    supplied_payload_hash = _first_text(event.get("payload_hash"))
    payload_hash = supplied_payload_hash or hashlib.sha256(_stable_json(event).encode("utf-8")).hexdigest()
    supplied_key_fields = event.get("key_fields")
    key_fields = _truncate(supplied_key_fields) if isinstance(supplied_key_fields, dict) else _key_fields(event)
    occurred_at = _first_text(event.get("occurred_at"), event.get("timestamp"), event.get("time"), event.get("created_at"))
    time_range_start = _first_text(event.get("time_range_start"), event.get("start_time"), occurred_at)
    time_range_end = _first_text(event.get("time_range_end"), event.get("end_time"), occurred_at)
    query_hint = _first_text(event.get("query_hint"), f"connector_id={connector_id} external_event_id={external_event_id or payload_hash}")
    ioc = _first_reference(event.get("ioc"), event.get("ioc_refs"), event.get("src_ip"), event.get("source_ip"), event.get("ip"), event.get("domain"), event.get("url"))

    summary = {
        "title": _truncate(title),
        "description": _truncate(description),
        "source": _source_type(alert_source),
        "severity": _severity(event.get("severity")),
        "asset_id": _first_reference(event.get("asset_id"), event.get("asset_refs"), event.get("host"), event.get("hostname"), event.get("dst_ip"), event.get("destination_ip")),
        "occurred_at": occurred_at,
        "ioc": ioc,
        "alert_type": _first_text(event.get("alert_type"), event.get("attack_type"), event.get("category"), evidence_source_type),
        "connector_id": connector_id,
        "connector_name": _first_text(context.get("connector_name"), event.get("connector_name")),
        "vendor": _first_text(context.get("vendor"), event.get("vendor")),
        "product": _first_text(context.get("product"), event.get("product")),
        "source_type": evidence_source_type,
        "external_event_id": external_event_id,
        "external_id": _first_text(event.get("external_id"), external_event_id),
        "external_url": external_url,
        "query_hint": query_hint,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "key_fields": key_fields,
        "payload_hash": payload_hash,
        "metadata": _truncate(event.get("metadata")) if isinstance(event.get("metadata"), dict) else {},
    }
    return summary


def build_alert_from_evidence_summary(summary: dict) -> AlertCreate:
    return AlertCreate(
        asset_id=summary.get("asset_id"),
        source=_source_type(summary.get("source")),
        title=summary.get("title") or "External security event",
        severity=_severity(summary.get("severity")),
        alert_type=summary.get("alert_type"),
        description=summary.get("description"),
        raw_event={"evidence_summary": True, "external_event_id": summary.get("external_event_id"), "payload_hash": summary.get("payload_hash"), "key_fields": summary.get("key_fields") or {}},
        ioc=[summary["ioc"]] if summary.get("ioc") else [],
        occurred_at=summary.get("occurred_at"),
        normalized_data={key: summary.get(key) for key in ["source", "severity", "connector_id", "connector_name", "vendor", "product", "external_event_id", "payload_hash"]},
    )


def build_evidence_item_from_summary(summary: dict, alert_id: str | None = None) -> AnalysisEvidenceItemCreate:
    connector_id = summary.get("connector_id") or "external"
    event_id = summary.get("external_event_id") or summary.get("payload_hash") or "unknown"
    prefix = "mcp" if str(summary.get("source_type") or "").lower() == "mcp" else "external"
    source_ref = f"{prefix}:{connector_id}:{event_id}"
    metadata = {"alert_id": alert_id} if alert_id else {}
    return AnalysisEvidenceItemCreate(
        title=summary.get("title") or "External evidence",
        description=summary.get("description") or "",
        source_ref=source_ref,
        related_fact_ids=[],
        connector_id=summary.get("connector_id"),
        connector_name=summary.get("connector_name"),
        vendor=summary.get("vendor"),
        product=summary.get("product"),
        source_type=summary.get("source_type"),
        external_event_id=summary.get("external_event_id"),
        external_url=summary.get("external_url"),
        query_hint=summary.get("query_hint"),
        time_range_start=summary.get("time_range_start"),
        time_range_end=summary.get("time_range_end"),
        payload_hash=summary.get("payload_hash"),
        key_fields=summary.get("key_fields") or {},
        metadata=metadata,
    )


def _dedup_key(summary: dict) -> str:
    connector_id = summary.get("connector_id") or "external"
    external_event_id = summary.get("external_event_id")
    if external_event_id:
        return f"event:{connector_id}:{external_event_id}"
    return f"hash:{connector_id}:{summary.get('payload_hash')}"


async def _seen_keys(store: SecurityStore) -> set[str]:
    keys: set[str] = set()
    for alert in await store.list_alerts():
        data = alert.normalized_data or {}
        connector_id = data.get("connector_id") or "external"
        if data.get("external_event_id"):
            keys.add(f"event:{connector_id}:{data.get('external_event_id')}")
        if data.get("payload_hash"):
            keys.add(f"hash:{connector_id}:{data.get('payload_hash')}")
    return keys


async def ingest_external_events(
    events: list[dict],
    *,
    connector_context: dict | None = None,
    create_analysis_cases: bool = True,
    run_initial_analysis: bool = True,
    deduplicate: bool = True,
    store: SecurityStore | None = None,
) -> dict:
    active_store = store or default_store
    seen = await _seen_keys(active_store) if deduplicate else set()
    result = {"created_alerts": 0, "skipped_duplicates": 0, "created_analysis_cases": 0, "items": []}
    batch_seen: set[str] = set()
    for event in events:
        summary = summarize_external_event(event, connector_context=connector_context)
        item_result = {"status": "created", "alert_id": None, "analysis_case_id": None, "external_event_id": summary.get("external_event_id"), "payload_hash": summary.get("payload_hash"), "title": summary.get("title"), "source": summary.get("source"), "severity": summary.get("severity"), "error": None}
        try:
            key = _dedup_key(summary)
            hash_key = f"hash:{summary.get('connector_id') or 'external'}:{summary.get('payload_hash')}"
            if deduplicate and (key in seen or key in batch_seen or hash_key in seen or hash_key in batch_seen):
                item_result["status"] = "skipped"
                result["skipped_duplicates"] += 1
                result["items"].append(item_result)
                continue
            alert = await active_store.create_alert(build_alert_from_evidence_summary(summary))
            item_result["alert_id"] = alert.id
            result["created_alerts"] += 1
            evidence_item = build_evidence_item_from_summary(summary, alert.id)
            if create_analysis_cases:
                case_create = build_analysis_case_from_alert(alert)
                case_create.evidence_items = [*case_create.evidence_items, evidence_item]
                case_obj = await active_store.create_analysis_case(case_create)
                if run_initial_analysis:
                    update = refresh_initial_analysis(case_obj, [alert]).model_dump(mode="json", exclude_unset=True)
                    update["evidence_items"] = [*update.get("evidence_items", []), evidence_item.model_dump(mode="json")]
                    refreshed = await active_store.update_analysis_case(case_obj.id, AnalysisCaseUpdate(**update))
                    case_obj = refreshed or case_obj
                item_result["analysis_case_id"] = case_obj.id
                result["created_analysis_cases"] += 1
            seen.add(key)
            seen.add(hash_key)
            batch_seen.add(key)
            batch_seen.add(hash_key)
            result["items"].append(item_result)
        except Exception as exc:  # keep batch ingestion resilient
            item_result["status"] = "error"
            item_result["error"] = str(exc)
            result["items"].append(item_result)
    return result
