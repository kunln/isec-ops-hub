from dataclasses import asdict
import json

import pytest

from flocks.security.integrations import (
    MINGYU_RISK_MAPPING,
    TDA_ALERT_MAPPING,
    MappingRule,
    apply_mapping,
    build_payload_hash,
    collect_values,
    drop_sensitive_fields,
    filter_key_fields,
    first_of,
    get_path,
    normalize_severity,
)


def tda_source(**overrides):
    src = {
        "merge_key": "tda-1",
        "threat_desc": "恶意外联告警",
        "rule_name": "Fallback rule",
        "severity": "高危",
        "event_time": "2026-07-09T00:00:00Z",
        "src": "10.0.0.5",
        "dst": "8.8.8.8",
        "victim_addr": "10.0.0.10",
        "domain": "evil.example",
        "url": "http://evil.example/a",
        "api_key": "secret-api-key",
        "nested": {"token": "secret-token", "safe": "kept"},
        "http_req_body": "full request body",
        "raw_payload": {"too": "much"},
    }
    src.update(overrides)
    return src


def mingyu_source(**overrides):
    src = {
        "risk_id": "risk-1",
        "risk_name": "明御 APT 风险",
        "risk_level": "中危",
        "risk_time": "2026-07-09T01:00:00Z",
        "asset_ip": "192.168.1.10",
        "src_ip": "172.16.0.8",
        "dst_ip": "192.168.1.10",
        "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
    }
    src.update(overrides)
    return src


def test_tda_like_source_maps_successfully():
    result = apply_mapping(tda_source(), TDA_ALERT_MAPPING)
    event = result.event
    assert event["package_id"] == "asiainfo.tda"
    assert event["title"] == "恶意外联告警"
    assert event["severity"] == "high"
    assert event["asset_refs"] == ["10.0.0.10", "8.8.8.8"]
    assert "evil.example" in event["ioc_refs"]


def test_mingyu_like_source_maps_successfully():
    result = apply_mapping(mingyu_source(), MINGYU_RISK_MAPPING)
    event = result.event
    assert event["package_id"] == "dbappsecurity.mingyu_apt"
    assert event["title"] == "明御 APT 风险"
    assert event["severity"] == "medium"
    assert event["asset_refs"] == ["192.168.1.10"]


def test_first_of_uses_first_available_value():
    assert first_of({"b": "value"}, ["a", "b"]) == "value"


def test_unknown_path_does_not_raise():
    assert get_path({"a": {}}, "a.missing.path") is None
    assert apply_mapping({"severity": "unknown"}, TDA_ALERT_MAPPING).event["severity"] == "medium"


def test_collect_ioc_refs_deduplicates():
    src = {"src": "1.1.1.1", "dst": "1.1.1.1", "ioc": ["2.2.2.2", "2.2.2.2"]}
    assert collect_values(src, ["src", "dst", "ioc"]) == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("超危", "critical"), ("高危", "high"), ("中危", "medium"), ("低危", "low")],
)
def test_chinese_severity_mapping(value, expected):
    assert normalize_severity(value) == expected


def test_severity_defaults_to_medium():
    assert normalize_severity("not-a-level") == "medium"


def test_key_fields_allowlist_applies():
    key_fields, _ = filter_key_fields(tda_source(extra="nope"), ["merge_key", "extra"])
    assert key_fields == {"merge_key": "tda-1", "extra": "nope"}


def test_denylist_wins_over_allowlist():
    key_fields, dropped = filter_key_fields(tda_source(), ["merge_key", "http_req_body"], ["merge_key"])
    assert "merge_key" not in key_fields
    assert "http_req_body" not in key_fields
    assert set(dropped) >= {"merge_key", "http_req_body"}


def test_sensitive_and_raw_fields_are_dropped_and_recorded():
    result = apply_mapping(
        tda_source(secret="s", token="t", password="p", login_password="lp", http_req_body="body"),
        TDA_ALERT_MAPPING,
    )
    dumped = json.dumps(result.event, ensure_ascii=False)
    for forbidden in ["secret-api-key", "secret-token", "raw_payload", "http_req_body", "login_password"]:
        assert forbidden not in dumped
    assert {"api_key", "nested.token", "raw_payload", "http_req_body", "secret", "token", "password", "login_password"}.issubset(
        set(result.dropped_sensitive_fields)
    )


def test_payload_hash_is_stable():
    first = build_payload_hash({"b": 2, "a": 1})
    second = build_payload_hash({"a": 1, "b": 2})
    assert first == second


def test_external_event_id_uses_hash_when_missing():
    result = apply_mapping(tda_source(merge_key=None), TDA_ALERT_MAPPING)
    assert result.event["external_event_id"] == f"hash-{result.event['payload_hash'][:16]}"


def test_event_does_not_include_full_raw_source():
    result = apply_mapping(tda_source(), TDA_ALERT_MAPPING)
    assert "source" not in result.event
    assert "raw_payload" not in result.event
    assert result.event["key_fields"] != tda_source()


def test_missing_title_defaults_and_warns():
    result = apply_mapping({"severity": "低危"}, TDA_ALERT_MAPPING)
    assert result.event["title"] == "Untitled security event"
    assert result.warnings


def test_result_is_json_serializable():
    result = apply_mapping(tda_source(), TDA_ALERT_MAPPING)
    json.dumps(asdict(result), ensure_ascii=False)


def test_mapping_is_pure_and_does_not_call_connectors_or_create_security_objects(monkeypatch):
    def fail(*args, **kwargs):  # pragma: no cover - executed only on regression
        raise AssertionError("external side effect attempted")

    monkeypatch.setattr("flocks.security.connectors.tda.TDAConnector", fail, raising=False)
    result = apply_mapping(tda_source(), TDA_ALERT_MAPPING)
    event = result.event
    forbidden_objects = {"alert_id", "evidence_id", "analysis_case_id", "incident_id"}
    assert forbidden_objects.isdisjoint(event)


def test_drop_sensitive_fields_helper_returns_safe_payload_and_drops():
    safe, dropped = drop_sensitive_fields({"ok": 1, "authorization": "Bearer x", "nested": {"cookie": "c"}})
    assert safe == {"ok": 1, "nested": {}}
    assert dropped == ["authorization", "nested.cookie"]
