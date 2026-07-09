"""Built-in example Mapping Engine rules for Integration Runtime v2."""

TDA_ALERT_MAPPING = {
    "title": {"first_of": ["threat_desc", "rule_name", "name"], "default": "Untitled security event"},
    "description": {"first_of": ["rule_name", "threat_desc"], "default": ""},
    "severity": {
        "normalize": {
            "field": "severity",
            "map": {"超危": "critical", "高危": "high", "中危": "medium", "低危": "low", "critical": "critical", "high": "high", "medium": "medium", "low": "low"},
            "default": "medium",
        }
    },
    "occurred_at": "event_time",
    "external_event_id": "merge_key",
    "asset_refs": {"collect": ["victim_addr", "dst"]},
    "ioc_refs": {"collect": ["src", "dst", "attacker_addr", "domain", "url"]},
    "key_fields": {
        "allowlist": ["merge_key", "event_time", "threat_desc", "rule_name", "src", "dst"],
        "denylist": ["http_req_body", "http_resp_body", "login_password", "login_password_encrypted", "raw_payload"],
    },
    "external_refs": {},
    "limitations": ["Example TDA-like mapping; fixture-oriented skeleton only."],
}

MINGYU_RISK_MAPPING = {
    "title": {"first_of": ["risk_name", "attack_type", "name"], "default": "Untitled security event"},
    "description": {"first_of": ["attack_type", "risk_name"], "default": ""},
    "severity": {
        "normalize": {
            "field": "risk_level",
            "map": {"超危": "critical", "高危": "high", "中危": "medium", "低危": "low", "critical": "critical", "high": "high", "medium": "medium", "low": "low"},
            "default": "medium",
        }
    },
    "occurred_at": "event_time",
    "external_event_id": "event_id",
    "asset_refs": {"collect": ["src_ip", "dst_ip"]},
    "ioc_refs": {"collect": ["src_ip", "dst_ip", "domain", "url"]},
    "key_fields": {
        "allowlist": ["event_id", "event_time", "risk_name", "risk_level", "src_ip", "dst_ip", "attack_type"],
        "denylist": ["http_req_body", "http_resp_body", "login_password", "login_password_encrypted", "raw_payload"],
    },
    "external_refs": {},
    "limitations": ["Example Mingyu-like mapping; fixture-oriented skeleton only."],
}
