"""Safe export and redaction helpers for customer-facing security outputs.

These helpers prepare bounded, redacted representations of metadata,
key_fields, raw_data, normalized_data, and evidence-derived details. They do not
mutate source objects and never emit raw payload values or credential-like
values.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SENSITIVE_KEYWORDS = {
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
    "sign",
    "authorization",
    "cookie",
    "session",
    "credential",
    "private_key",
    "access_key",
    "refresh_token",
    "auth_timestamp",
    "login_password",
    "login_password_encrypted",
}

RAW_PAYLOAD_KEYWORDS = {
    "raw",
    "raw_data",
    "raw_event",
    "raw_payload",
    "payload",
    "packet",
    "pcap",
    "full_content",
    "http_req_body",
    "http_resp_body",
    "http_req_hdr",
    "http_resp_hdr",
    "request_body",
    "response_body",
}


def _normalized_key(key: str) -> str:
    return str(key).strip().lower().replace("-", "_").replace(".", "_")


def is_sensitive_key(key: str) -> bool:
    """Return True when a field name is credential-like or secret-like."""

    normalized = _normalized_key(key)
    return any(keyword in normalized for keyword in SENSITIVE_KEYWORDS)


def is_raw_payload_key(key: str) -> bool:
    """Return True when a field name appears to contain raw payload content."""

    normalized = _normalized_key(key)
    return normalized in RAW_PAYLOAD_KEYWORDS or any(
        normalized.endswith(f"_{keyword}") or normalized.startswith(f"{keyword}_")
        for keyword in RAW_PAYLOAD_KEYWORDS
        if keyword != "raw"
    )


def redact_sensitive_value(value: Any) -> str:
    """Return the standard replacement for sensitive values."""

    return "[REDACTED]"


def summarize_large_value(value: Any) -> dict[str, Any]:
    """Return a metadata-only summary for values that must not be exported."""

    if isinstance(value, bytes | bytearray | memoryview):
        return {"type": "bytes", "length": len(value), "redacted": True}
    if isinstance(value, str):
        return {"type": "str", "length": len(value), "truncated": True}
    if isinstance(value, Mapping):
        return {"type": "dict", "length": len(value), "redacted": True}
    if isinstance(value, list | tuple | set | frozenset):
        return {"type": "list", "length": len(value), "redacted": True}
    return {"type": type(value).__name__, "redacted": True}


def _raw_payload_summary(value: Any) -> dict[str, Any]:
    summary = summarize_large_value(value)
    summary["redacted"] = True
    summary["reason"] = "raw_payload"
    return summary


def safe_export_value(
    value: Any,
    *,
    max_string_length: int = 512,
    max_list_items: int = 20,
    max_depth: int = 6,
) -> Any:
    """Return a bounded, redacted export-safe representation of ``value``."""

    if max_depth < 0:
        return {"type": type(value).__name__, "truncated": True, "reason": "max_depth"}
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value if len(value) <= max_string_length else summarize_large_value(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return summarize_large_value(value)
    if isinstance(value, Mapping):
        return safe_export_dict(
            dict(value),
            max_string_length=max_string_length,
            max_list_items=max_list_items,
            max_depth=max_depth,
        )
    if isinstance(value, list | tuple | set | frozenset):
        values = list(value)
        exported = [
            safe_export_value(
                item,
                max_string_length=max_string_length,
                max_list_items=max_list_items,
                max_depth=max_depth - 1,
            )
            for item in values[:max_list_items]
        ]
        if len(values) > max_list_items:
            exported.append({"type": "list_truncated", "length": len(values)})
        return exported
    if hasattr(value, "model_dump"):
        return safe_export_model(
            value,
            max_string_length=max_string_length,
            max_list_items=max_list_items,
            max_depth=max_depth,
        )
    return str(value)


def safe_export_dict(
    data: dict[str, Any],
    *,
    max_string_length: int = 512,
    max_list_items: int = 20,
    max_depth: int = 6,
) -> dict[str, Any]:
    """Return a redacted copy of ``data`` suitable for reports and exports."""

    if max_depth < 0:
        return {"type": "dict", "truncated": True, "reason": "max_depth"}

    exported: dict[str, Any] = {}
    for key, value in data.items():
        key_text = str(key)
        if is_sensitive_key(key_text):
            exported[key_text] = redact_sensitive_value(value)
        elif is_raw_payload_key(key_text):
            exported[key_text] = _raw_payload_summary(value)
        else:
            exported[key_text] = safe_export_value(
                value,
                max_string_length=max_string_length,
                max_list_items=max_list_items,
                max_depth=max_depth - 1,
            )
    return exported


def safe_export_model(
    model: Any,
    *,
    max_string_length: int = 512,
    max_list_items: int = 20,
    max_depth: int = 6,
) -> dict[str, Any]:
    """Dump a Pydantic model with JSON mode, then safely export its dict."""

    if not hasattr(model, "model_dump"):
        raise TypeError("safe_export_model expects a Pydantic-like model with model_dump")
    dumped = model.model_dump(mode="json")
    return safe_export_dict(
        dumped,
        max_string_length=max_string_length,
        max_list_items=max_list_items,
        max_depth=max_depth,
    )
