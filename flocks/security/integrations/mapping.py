"""Declarative Mapping Engine skeleton for lightweight Evidence Events.

This module intentionally contains pure functions only. It does not call v1
connectors, perform HTTP requests, read credentials, create Security objects,
or persist raw vendor responses.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


DEFAULT_TITLE = "Untitled security event"
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
SENSITIVE_NAME_PARTS = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "credential",
    "authorization",
    "auth_header",
    "raw",
    "raw_payload",
    "payload_raw",
    "raw_log",
    "raw_response",
    "request",
    "response",
    "http_req_body",
    "http_resp_body",
    "body",
)


class MappingRule(BaseModel):
    """Declarative rules for mapping a vendor-like dict into an Evidence Event."""

    model_config = ConfigDict(frozen=True)

    title: dict[str, Any] | str | None = None
    description: dict[str, Any] | str | None = None
    severity: dict[str, Any] | str | None = None
    occurred_at: dict[str, Any] | str | None = None
    external_event_id: dict[str, Any] | str | None = None
    asset_refs: dict[str, Any] | list[str] | None = None
    ioc_refs: dict[str, Any] | list[str] | None = None
    key_fields: dict[str, Any] | None = None
    external_refs: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list)


class EvidenceEventMappingResult(BaseModel):
    """Result of applying mapping rules to one vendor-like source dict."""

    event: dict[str, Any] | None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    dropped_sensitive_fields: list[str] = Field(default_factory=list)


def get_path(source: dict[str, Any], path: str) -> Any:
    """Return a dotted-path value from source without raising for missing paths."""

    current: Any = source
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def first_of(source: dict[str, Any], paths: list[str], default: Any = None) -> Any:
    """Return the first non-empty value found at the provided paths."""

    for path in paths:
        value = get_path(source, path)
        if value not in (None, "", [], {}):
            return value
    return default


def collect_values(source: dict[str, Any], paths: list[str]) -> list[str]:
    """Collect non-empty scalar or list values from paths as de-duplicated strings."""

    values: list[str] = []
    seen: set[str] = set()
    for path in paths:
        value = get_path(source, path)
        items = value if isinstance(value, list) else [value]
        for item in items:
            if item in (None, "", [], {}):
                continue
            text = str(item)
            if text not in seen:
                seen.add(text)
                values.append(text)
    return values


def normalize_severity(value: Any, mapping: dict[str, str] | None = None) -> str:
    """Normalize severity into the lightweight Evidence Event vocabulary."""

    if value is None or value == "":
        return "medium"
    normalized = str(value).strip().lower()
    if mapping:
        normalized = mapping.get(str(value), mapping.get(normalized, normalized))
        normalized = str(normalized).strip().lower()
    return normalized if normalized in ALLOWED_SEVERITIES else "medium"


def build_payload_hash(source: dict[str, Any]) -> str:
    """Build a stable hash over a safely serialized source dict."""

    safe_source, _ = drop_sensitive_fields(source)
    payload = json.dumps(safe_source, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def filter_key_fields(source: dict[str, Any], allowlist: list[str], denylist: list[str]) -> dict[str, Any]:
    """Copy allowlisted key fields while making denylist precedence explicit."""

    deny = set(denylist)
    return {field: get_path(source, field) for field in allowlist if field not in deny and get_path(source, field) not in (None, "", [], {})}


def _is_sensitive_field(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in SENSITIVE_NAME_PARTS)


def drop_sensitive_fields(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Drop sensitive/raw fields recursively and report dropped field paths."""

    dropped: list[str] = []

    def clean(value: Any, prefix: str = "") -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, nested in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if _is_sensitive_field(str(key)):
                    dropped.append(path)
                    continue
                result[key] = clean(nested, path)
            return result
        if isinstance(value, list):
            return [clean(item, prefix) for item in value]
        return value

    return clean(data), dropped


def _evaluate_rule(source: dict[str, Any], rule: Any, *, default: Any = None) -> Any:
    if rule is None:
        return default
    if isinstance(rule, str):
        return get_path(source, rule)
    if isinstance(rule, list):
        return collect_values(source, rule)
    if isinstance(rule, dict):
        if "first_of" in rule:
            return first_of(source, list(rule.get("first_of") or []), rule.get("default", default))
        if "collect" in rule:
            return collect_values(source, list(rule.get("collect") or []))
        if "normalize" in rule:
            spec = rule.get("normalize") or {}
            value = get_path(source, spec.get("field", ""))
            if value in (None, "") and "default" in spec:
                value = spec["default"]
            return normalize_severity(value, spec.get("map"))
        if "field" in rule:
            return get_path(source, str(rule["field"]))
    return default


def _unique_strings(values: Any) -> list[str]:
    items = values if isinstance(values, list) else [values]
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in (None, "", [], {}):
            continue
        text = str(item)
        if text not in seen:
            seen.add(text)
            result.append(text)
    return result


def apply_mapping(
    source: dict[str, Any],
    mapping: dict[str, Any],
    *,
    package_id: str,
    instance_id: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    capability: str | None = None,
) -> EvidenceEventMappingResult:
    """Map one vendor-like dict into a lightweight Evidence Event dict."""

    errors: list[str] = []
    warnings: list[str] = []
    try:
        rule = MappingRule.model_validate(mapping)
    except Exception as exc:  # pydantic validation is a rule failure, not runtime IO.
        return EvidenceEventMappingResult(event=None, errors=[f"invalid mapping rule: {exc}"], warnings=[], dropped_sensitive_fields=[])

    payload_hash = build_payload_hash(source)
    _, source_dropped = drop_sensitive_fields(source)

    title = _evaluate_rule(source, rule.title)
    if title in (None, ""):
        title = DEFAULT_TITLE
        warnings.append("title missing; defaulted to Untitled security event")

    description = _evaluate_rule(source, rule.description, default="") or ""
    severity_value = _evaluate_rule(source, rule.severity, default="medium")
    severity = normalize_severity(severity_value)
    occurred_at = _evaluate_rule(source, rule.occurred_at)
    external_event_id = _evaluate_rule(source, rule.external_event_id)
    if external_event_id in (None, ""):
        external_event_id = f"hash-{payload_hash[:16]}"
        warnings.append("external_event_id missing; generated from payload_hash")

    key_spec = rule.key_fields or {}
    key_fields = filter_key_fields(
        source,
        list(key_spec.get("allowlist") or []),
        list(key_spec.get("denylist") or []),
    )
    key_fields, key_dropped = drop_sensitive_fields(key_fields)

    external_refs = _evaluate_rule(source, rule.external_refs, default={}) if rule.external_refs else {}
    if not isinstance(external_refs, dict):
        external_refs = {}
    external_refs, external_dropped = drop_sensitive_fields(external_refs)

    event = {
        "source_type": "integration",
        "package_id": package_id,
        "instance_id": instance_id,
        "vendor": vendor,
        "product": product,
        "capability": capability,
        "external_event_id": str(external_event_id),
        "title": str(title),
        "description": str(description),
        "severity": severity,
        "asset_refs": _unique_strings(_evaluate_rule(source, rule.asset_refs, default=[])),
        "ioc_refs": _unique_strings(_evaluate_rule(source, rule.ioc_refs, default=[])),
        "occurred_at": occurred_at,
        "key_fields": key_fields,
        "payload_hash": payload_hash,
        "external_refs": external_refs,
        "limitations": list(rule.limitations),
    }
    event, event_dropped = drop_sensitive_fields(event)

    dropped = sorted(set(source_dropped + key_dropped + external_dropped + event_dropped))
    return EvidenceEventMappingResult(event=event, errors=errors, warnings=warnings, dropped_sensitive_fields=dropped)
