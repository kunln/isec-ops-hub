"""Tests for Safe Export helpers."""

from __future__ import annotations

import json

from flocks.security.safe_export import SafeExportResult, redact_for_safe_export, safe_export_json, safe_export_records


def test_safe_export_drops_sensitive_and_raw_fields() -> None:
    result = safe_export_records([
        {"id": "1", "title": "event", "api_key": "k", "raw_payload": "raw", "nested": {"token": "t", "value": "ok"}}
    ])

    assert isinstance(result, SafeExportResult)
    assert result.records == [{"id": "1", "title": "event", "nested": {"value": "ok"}}]
    assert {"api_key", "raw_payload", "nested.token"}.issubset(set(result.dropped_fields))
    assert result.warnings


def test_redact_for_safe_export_is_serializable_and_truncates_large_strings() -> None:
    safe, dropped = redact_for_safe_export({"value": "x" * 2048, "password": "secret"})
    assert dropped == ["password"]
    assert safe["value"] == {"type": "str", "length": 2048, "truncated": True}
    json.dumps(safe)


def test_safe_export_json_is_deterministic() -> None:
    first = safe_export_json([{"b": 1, "secret": "s"}])
    second = safe_export_json([{"b": 1, "secret": "s"}])
    assert first == second
    assert "\"s\"" not in first
