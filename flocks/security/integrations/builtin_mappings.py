"""Built-in example Mapping Engine rules for Integration Runtime v2."""

from __future__ import annotations

from flocks.security.integrations.mapping import MappingRule

TDA_ALERT_MAPPING = MappingRule(
    source_type="integration_event",
    package_id="asiainfo.tda",
    vendor="AsiaInfo",
    product="TDA",
    capability="alert.search",
    fields={
        "external_event_id": {"first_of": ["merge_key", "alarm_id", "id"]},
        "title": {"first_of": ["threat_desc", "rule_name"]},
        "description": {"first_of": ["event_desc", "description"]},
        "severity": {"path": "severity"},
        "asset_refs": {"collect": ["victim_addr", "dst", "asset_addr"]},
        "ioc_refs": {"collect": ["src", "dst", "attacker_addr", "domain", "url", "ioc"]},
        "occurred_at": {"first_of": ["event_time", "occurred_at", "timestamp"]},
    },
    key_fields_allowlist=("merge_key", "event_time", "threat_desc", "rule_name", "src", "dst", "victim_addr", "domain", "url"),
    key_fields_denylist=("http_req_body", "http_resp_body", "login_password", "login_password_encrypted"),
)

MINGYU_RISK_MAPPING = MappingRule(
    source_type="integration_event",
    package_id="dbappsecurity.mingyu_apt",
    vendor="DBAPPSecurity",
    product="Mingyu APT",
    capability="risk.search",
    fields={
        "external_event_id": {"first_of": ["risk_id", "event_id", "id"]},
        "title": {"first_of": ["risk_name", "alert_name", "name"]},
        "description": {"first_of": ["risk_desc", "description", "detail"]},
        "severity": {"first_of": ["risk_level", "severity", "level"]},
        "asset_refs": {"collect": ["asset_ip", "host_ip", "dst_ip", "victim_ip"]},
        "ioc_refs": {"collect": ["src_ip", "dst_ip", "domain", "url", "file_md5", "ioc"]},
        "occurred_at": {"first_of": ["risk_time", "event_time", "time"]},
    },
    key_fields_allowlist=("risk_id", "risk_time", "risk_name", "asset_ip", "src_ip", "dst_ip", "domain", "file_md5"),
    key_fields_denylist=("http_req_body", "raw_payload", "password", "token", "secret"),
)
