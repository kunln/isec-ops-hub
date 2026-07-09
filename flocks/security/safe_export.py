"""Safe Export helpers for Security data.

The helpers produce bounded, redacted exports for tests and operator workflows.
They do not read credentials, call connectors, perform HTTP, or create Security
objects.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_EXPORT_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "credential",
    "authorization",
    "cookie",
    "raw",
    "request",
    "response",
    "http_req_body",
    "http_resp_body",
)
MAX_EXPORT_STRING_LENGTH = 1024


class SafeExportResult(BaseModel):
    """Serializable safe export result."""

    model_config = ConfigDict(frozen=True)

    records: list[dict[str, Any]] = Field(default_factory=list)
    dropped_fields: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def is_sensitive_export_field(field_name: str) -> bool:
    lowered = field_name.lower()
    return any(keyword in lowered for keyword in SENSITIVE_EXPORT_KEYWORDS)


def redact_for_safe_export(data: Any) -> tuple[Any, list[str]]:
    """Return a redacted copy of data plus dropped sensitive field paths."""

    dropped: list[str] = []

    def clean(value: Any, prefix: str = "") -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, nested in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if is_sensitive_export_field(str(key)):
                    dropped.append(path)
                    continue
                result[str(key)] = clean(nested, path)
            return result
        if isinstance(value, list):
            return [clean(item, prefix) for item in value]
        if isinstance(value, str) and len(value) > MAX_EXPORT_STRING_LENGTH:
            return {"type": "str", "length": len(value), "truncated": True}
        return value

    return clean(data), dropped


def safe_export_records(records: list[dict[str, Any]]) -> SafeExportResult:
    """Safely export records without raw payloads or credential-like fields."""

    safe_records: list[dict[str, Any]] = []
    dropped_fields: list[str] = []
    for record in records:
        safe_record, dropped = redact_for_safe_export(record)
        safe_records.append(safe_record)
        dropped_fields.extend(dropped)
    warnings = ["sensitive/raw fields were dropped"] if dropped_fields else []
    return SafeExportResult(records=safe_records, dropped_fields=sorted(set(dropped_fields)), warnings=warnings)


def safe_export_json(records: list[dict[str, Any]]) -> str:
    """Serialize safe export records as deterministic JSON."""

    return json.dumps(safe_export_records(records).model_dump(), ensure_ascii=False, sort_keys=True)
