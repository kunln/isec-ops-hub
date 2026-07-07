"""Helpers for lightweight connector sync run history."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from flocks.security.store import SecurityStore, utc_now

SENSITIVE_KEYS = {"apikey", "api_key", "token", "password", "secret", "authorization", "auth", "credential", "sign", "auth_timestamp", "login_password", "login_password_encrypted"}
REQUEST_SUMMARY_KEYS = {
    "begin", "end", "mode", "limit", "max_pages", "create_analysis_cases",
    "run_initial_analysis", "deduplicate", "verify_ssl",
}
ITEM_REF_KEYS = {"status", "alert_id", "analysis_case_id", "external_event_id", "payload_hash", "title", "source", "severity", "error"}
_SECRET_PATTERNS = [
    re.compile(r"(?i)(Authorization:\s*Bearer\s+)[^\s,;]+"),
    re.compile(r'(?i)(\"(?:api_key|apikey|token|password|secret|authorization|sign|auth_timestamp|login_password|login_password_encrypted|credential)\"\s*:\s*)\"[^\"]*\"'),
    re.compile(r"(?i)(apikey|api_key|token|password|secret|authorization|sign|auth_timestamp|login_password|login_password_encrypted|credential)\s*[:=]\s*[^\s,;]+"),
]


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return lowered in SENSITIVE_KEYS or any(part in lowered for part in ("password", "secret", "token", "apikey"))


def sanitize_error_message(message: Any, max_length: int = 500) -> str:
    text = str(message)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<redacted>", text)
    return text[:max_length]


def _sanitize_base_url(value: Any) -> str | None:
    if not value:
        return None
    parsed = urlsplit(str(value))
    if parsed.scheme and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return str(value).split("/", 1)[0].split("?", 1)[0]


def sanitize_connector_request_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in REQUEST_SUMMARY_KEYS:
        if key in payload and not _is_sensitive_key(key):
            summary[key] = payload[key]
    base_url = _sanitize_base_url(payload.get("base_url"))
    if base_url:
        summary["base_url_host"] = base_url
    return summary


def summarize_ingestion_result(result: dict[str, Any]) -> dict[str, Any]:
    items = result.get("items") if isinstance(result.get("items"), list) else []
    return {
        "created_alerts": int(result.get("created_alerts") or 0),
        "skipped_duplicates": int(result.get("skipped_duplicates") or 0),
        "created_analysis_cases": int(result.get("created_analysis_cases") or 0),
        "items_count": len(items),
        "error_count": sum(1 for item in items if isinstance(item, dict) and item.get("status") == "error"),
    }


def item_refs_from_ingestion_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for item in result.get("items") or []:
        if not isinstance(item, dict):
            continue
        ref = {key: sanitize_error_message(value) if key == "error" else value for key, value in item.items() if key in ITEM_REF_KEYS and value not in (None, "", [], {})}
        refs.append(ref)
    return refs


def status_from_ingestion_result(result: dict[str, Any]) -> str:
    items = result.get("items") if isinstance(result.get("items"), list) else []
    has_error = any(isinstance(item, dict) and item.get("status") == "error" for item in items)
    has_success = any(isinstance(item, dict) and item.get("status") in {"created", "skipped"} for item in items)
    return "partial_success" if has_error and has_success else "success"


async def record_connector_run(
    store: SecurityStore,
    run_id: str,
    result: dict[str, Any] | None = None,
    error: Exception | str | None = None,
) -> None:
    update: dict[str, Any] = {"finished_at": utc_now()}
    if error is not None:
        update.update({"status": "failed", "error_message": sanitize_error_message(error)})
    elif result is not None:
        update.update({
            "status": status_from_ingestion_result(result),
            "result_summary": summarize_ingestion_result(result),
            "item_refs": item_refs_from_ingestion_result(result),
        })
    await store.update_connector_sync_run(run_id, update)
