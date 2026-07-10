"""Pure-function Mapping Engine skeleton for lightweight Evidence Events.

This module intentionally does not call connectors, perform HTTP, access
credentials, or create Alert/Evidence/AnalysisCase/Incident objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Mapping, Sequence

RAW_PAYLOAD_KEYS = {"raw_payload", "request", "response", "body", "pcap", "packet"}
SENSITIVE_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "authorization",
    "cookie",
)
DEFAULT_DENYLIST = RAW_PAYLOAD_KEYS | {"http_req_body", "http_resp_body", "login_password", "login_password_encrypted"}
SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "超危": "critical",
    "严重": "critical",
    "高危": "high",
    "high": "high",
    "高": "high",
    "中危": "medium",
    "medium": "medium",
    "med": "medium",
    "中": "medium",
    "低危": "low",
    "low": "low",
    "低": "low",
    "info": "low",
    "informational": "low",
}


@dataclass(frozen=True)
class MappingRule:
    """Declarative mapping rule for one vendor-like event dictionary."""

    source_type: str
    package_id: str
    vendor: str
    product: str
    capability: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    key_fields_allowlist: Sequence[str] = field(default_factory=tuple)
    key_fields_denylist: Sequence[str] = field(default_factory=tuple)


@dataclass(frozen=True)
class EvidenceEventMappingResult:
    """Result for one Mapping Engine conversion."""

    event: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    dropped_sensitive_fields: list[str] = field(default_factory=list)


def get_path(source: Mapping[str, Any], path: str, default: Any = None) -> Any:
    """Safely fetch a dotted path from a mapping/list structure."""

    current: Any = source
    for part in str(path).split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return default
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return default
            current = current[index]
        else:
            return default
    return current


def first_of(source: Mapping[str, Any], paths: Sequence[Any], default: Any = None) -> Any:
    """Return the first non-empty path value or literal fallback."""

    for item in paths:
        if isinstance(item, str):
            value = get_path(source, item, None)
        else:
            value = item
        if value not in (None, "", [], {}):
            return value
    return default


def collect_values(source: Mapping[str, Any], paths: Sequence[str]) -> list[Any]:
    """Collect non-empty values from paths, flatten lists, and de-duplicate."""

    values: list[Any] = []
    seen: set[str] = set()
    for path in paths:
        value = get_path(source, path)
        items = value if isinstance(value, list) else [value]
        for item in items:
            if item in (None, "", [], {}):
                continue
            marker = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
            if marker not in seen:
                seen.add(marker)
                values.append(item)
    return values


def normalize_severity(value: Any, default: str = "medium") -> str:
    """Normalize English and Chinese severity values."""

    if value is None:
        return default
    normalized = SEVERITY_ALIASES.get(str(value).strip().lower())
    return normalized or default


def build_payload_hash(payload: Mapping[str, Any]) -> str:
    """Build a stable SHA-256 hash for a sanitized payload."""

    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in RAW_PAYLOAD_KEYS or any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)


def drop_sensitive_fields(payload: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Recursively drop raw-payload and credential-like fields."""

    dropped: list[str] = []

    def clean(value: Any, prefix: str = "") -> Any:
        if isinstance(value, Mapping):
            safe: dict[str, Any] = {}
            for key, child in value.items():
                key_str = str(key)
                path = f"{prefix}.{key_str}" if prefix else key_str
                if _is_sensitive_key(key_str) or key_str in DEFAULT_DENYLIST:
                    dropped.append(path)
                    continue
                safe[key_str] = clean(child, path)
            return safe
        if isinstance(value, list):
            return [clean(item, prefix) for item in value]
        return value

    return clean(payload), dropped


def filter_key_fields(
    source: Mapping[str, Any],
    allowlist: Sequence[str] | None = None,
    denylist: Sequence[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Filter key_fields with allowlist first, denylist/sensitive checks last."""

    allowed = list(allowlist or source.keys())
    denied = set(DEFAULT_DENYLIST) | {str(item) for item in (denylist or [])}
    candidate: dict[str, Any] = {}
    dropped: list[str] = []
    for key in allowed:
        top_key = str(key).split(".", 1)[0]
        if str(key) in denied or top_key in denied or _is_sensitive_key(str(key)) or _is_sensitive_key(top_key):
            dropped.append(str(key))
            continue
        value = get_path(source, str(key))
        if value is not None:
            candidate[str(key)] = value
    safe, nested_dropped = drop_sensitive_fields(candidate)
    return safe, dropped + nested_dropped


def _resolve(source: Mapping[str, Any], spec: Any) -> Any:
    if isinstance(spec, str):
        return get_path(source, spec)
    if isinstance(spec, Mapping):
        if "path" in spec:
            return get_path(source, str(spec["path"]))
        if "first_of" in spec:
            return first_of(source, list(spec["first_of"]))
        if "collect" in spec:
            return collect_values(source, list(spec["collect"]))
        if "normalize" in spec:
            normalize = spec["normalize"]
            if isinstance(normalize, Mapping):
                value = get_path(source, str(normalize.get("field", "")))
                mapped = normalize.get("map", {}).get(value, value)
                return normalize_severity(mapped)
            return normalize_severity(_resolve(source, normalize))
    return spec


def apply_mapping(source: Mapping[str, Any], rule: MappingRule) -> EvidenceEventMappingResult:
    """Map one vendor-like dictionary into a lightweight Evidence Event."""

    warnings: list[str] = []
    fields = rule.fields
    title = _resolve(source, fields.get("title")) if "title" in fields else None
    if not title:
        title = "Untitled security event"
        warnings.append("title missing; defaulted to Untitled security event")

    key_fields, dropped = filter_key_fields(source, rule.key_fields_allowlist, rule.key_fields_denylist)
    sanitized_source, source_dropped = drop_sensitive_fields(source)
    dropped.extend(source_dropped)
    payload_hash = build_payload_hash(sanitized_source)
    external_event_id = _resolve(source, fields.get("external_event_id")) if "external_event_id" in fields else None
    if not external_event_id:
        external_event_id = f"hash-{payload_hash[:16]}"

    event = {
        "source_type": rule.source_type,
        "package_id": rule.package_id,
        "vendor": rule.vendor,
        "product": rule.product,
        "capability": rule.capability,
        "external_event_id": str(external_event_id),
        "title": str(title),
        "description": _resolve(source, fields.get("description")) or "",
        "severity": normalize_severity(_resolve(source, fields.get("severity"))),
        "asset_refs": collect_values(source, fields.get("asset_refs", {}).get("collect", [])) if isinstance(fields.get("asset_refs"), Mapping) else (_resolve(source, fields.get("asset_refs")) or []),
        "ioc_refs": collect_values(source, fields.get("ioc_refs", {}).get("collect", [])) if isinstance(fields.get("ioc_refs"), Mapping) else (_resolve(source, fields.get("ioc_refs")) or []),
        "occurred_at": _resolve(source, fields.get("occurred_at")) or "",
        "key_fields": key_fields,
        "payload_hash": payload_hash,
        "external_refs": _resolve(source, fields.get("external_refs")) or [],
        "limitations": ["Mapping Engine skeleton: source payload is transient and not included in the event."],
    }
    return EvidenceEventMappingResult(event=event, warnings=warnings, dropped_sensitive_fields=sorted(set(dropped)))
