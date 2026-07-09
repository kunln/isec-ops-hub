"""Tests for the Integration Mapping Engine skeleton."""

from __future__ import annotations

import json

from flocks.security.integrations.builtin_mappings import MINGYU_RISK_MAPPING, TDA_ALERT_MAPPING
from flocks.security.integrations.mapping import (
    DEFAULT_TITLE,
    MappingRule,
    apply_mapping,
    build_payload_hash,
    drop_sensitive_fields,
    first_of,
    get_path,
)


def test_tda_like_source_mapping_success() -> None:
    source = {
        "threat_desc": "恶意域名访问",
        "rule_name": "DNS threat",
        "severity": "高危",
        "victim_addr": "10.0.0.5",
        "src": "1.2.3.4",
        "dst": "10.0.0.5",
        "domain": "evil.example",
        "url": "http://evil.example/a",
        "event_time": "2026-07-09T00:00:00Z",
        "merge_key": "tda-1",
    }
    result = apply_mapping(source, TDA_ALERT_MAPPING, package_id="tda", vendor="TDA", product="APT", capability="alerts")

    assert result.errors == []
    assert result.event is not None
    assert result.event["source_type"] == "integration"
    assert result.event["external_event_id"] == "tda-1"
    assert result.event["title"] == "恶意域名访问"
    assert result.event["severity"] == "high"
    assert result.event["asset_refs"] == ["10.0.0.5"]
    assert "evil.example" in result.event["ioc_refs"]


def test_mingyu_like_source_mapping_success() -> None:
    source = {
        "risk_name": "APT risk",
        "risk_level": "中危",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "attack_type": "C2",
        "event_time": "2026-07-09T01:00:00Z",
        "event_id": "mingyu-1",
    }
    result = apply_mapping(source, MINGYU_RISK_MAPPING, package_id="mingyu", vendor="Mingyu", product="APT")

    assert result.event is not None
    assert result.event["external_event_id"] == "mingyu-1"
    assert result.event["title"] == "APT risk"
    assert result.event["description"] == "C2"
    assert result.event["severity"] == "medium"
    assert result.event["asset_refs"] == ["192.0.2.10", "198.51.100.20"]


def test_first_of_and_unknown_path_do_not_raise() -> None:
    source = {"rule_name": "Fallback rule"}
    assert get_path(source, "missing.path") is None
    assert first_of(source, ["missing", "rule_name"], "default") == "Fallback rule"
    result = apply_mapping(source, {"title": {"first_of": ["missing", "rule_name"]}}, package_id="pkg")
    assert result.event is not None
    assert result.event["title"] == "Fallback rule"


def test_collect_ioc_refs_deduplicates() -> None:
    result = apply_mapping(
        {"name": "n", "src": "1.1.1.1", "dst": "1.1.1.1", "domain": ["a.test", "a.test"]},
        {"title": "name", "ioc_refs": {"collect": ["src", "dst", "domain"]}},
        package_id="pkg",
    )
    assert result.event is not None
    assert result.event["ioc_refs"] == ["1.1.1.1", "a.test"]


def test_severity_chinese_mapping_and_default_medium() -> None:
    high = apply_mapping({"name": "n", "severity": "超危"}, TDA_ALERT_MAPPING, package_id="pkg")
    missing = apply_mapping({"name": "n"}, {"title": "name", "severity": {"normalize": {"field": "missing"}}}, package_id="pkg")
    assert high.event is not None and high.event["severity"] == "critical"
    assert missing.event is not None and missing.event["severity"] == "medium"


def test_key_fields_allowlist_and_denylist_precedence() -> None:
    result = apply_mapping(
        {"name": "n", "merge_key": "m", "raw_payload": "raw", "http_req_body": "body"},
        {"title": "name", "key_fields": {"allowlist": ["merge_key", "raw_payload"], "denylist": ["raw_payload"]}},
        package_id="pkg",
    )
    assert result.event is not None
    assert result.event["key_fields"] == {"merge_key": "m"}
    assert "raw_payload" in result.dropped_sensitive_fields


def test_sensitive_fields_are_dropped_and_recorded() -> None:
    source = {
        "name": "n",
        "api_key": "k",
        "secret": "s",
        "token": "t",
        "password": "p",
        "login_password": "lp",
        "http_req_body": "body",
        "raw_payload": "raw",
    }
    cleaned, dropped = drop_sensitive_fields(source)
    assert cleaned == {"name": "n"}
    assert {"api_key", "secret", "token", "password", "login_password", "http_req_body", "raw_payload"}.issubset(set(dropped))
    result = apply_mapping(source, {"title": "name"}, package_id="pkg")
    assert result.event is not None
    assert set(dropped).issubset(set(result.dropped_sensitive_fields))
    rendered = json.dumps(result.event, ensure_ascii=False)
    for forbidden in ["api_key", "secret", "token", "password", "http_req_body", "raw_payload"]:
        assert forbidden not in rendered


def test_payload_hash_stable_and_missing_external_event_id_uses_hash() -> None:
    source = {"name": "n", "value": 1, "api_key": "not-output"}
    assert build_payload_hash(source) == build_payload_hash({"value": 1, "name": "n", "api_key": "not-output"})
    result = apply_mapping(source, {"title": "name"}, package_id="pkg")
    assert result.event is not None
    assert result.event["external_event_id"] == f"hash-{build_payload_hash(source)[:16]}"


def test_event_does_not_contain_full_raw_source() -> None:
    source = {"name": "n", "nested": {"kept_vendor_field": "not allowlisted"}, "raw": "raw"}
    result = apply_mapping(source, {"title": "name", "key_fields": {"allowlist": ["name"]}}, package_id="pkg")
    assert result.event is not None
    assert "nested" not in result.event
    assert "raw" not in result.event
    assert result.event["key_fields"] == {"name": "n"}


def test_missing_title_defaults_and_warns() -> None:
    result = apply_mapping({}, {}, package_id="pkg")
    assert result.event is not None
    assert result.event["title"] == DEFAULT_TITLE
    assert any("title missing" in warning for warning in result.warnings)


def test_mapping_result_errors_warnings_are_serializable() -> None:
    result = apply_mapping({}, {"title": 123}, package_id="pkg")
    payload = result.model_dump()
    json.dumps(payload)
    assert isinstance(payload["errors"], list)
    assert isinstance(payload["warnings"], list)
    assert MappingRule(title="name").model_dump()["title"] == "name"


def test_mapping_engine_does_not_call_connectors_or_create_security_objects(monkeypatch) -> None:
    calls: list[str] = []

    def record(*args, **kwargs):  # pragma: no cover - should never run
        calls.append("called")
        raise AssertionError("connector or security object creation should not be called")

    monkeypatch.setattr("flocks.security.evidence_ingestion.ingest_evidence", record, raising=False)
    result = apply_mapping({"name": "n"}, {"title": "name"}, package_id="pkg")
    assert result.event is not None
    assert calls == []
    assert "Alert" not in result.event
    assert "Evidence" not in result.event
    assert "AnalysisCase" not in result.event
    assert "Incident" not in result.event
