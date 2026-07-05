"""Normalize connector raw responses into Security Extension domain payloads."""

from __future__ import annotations

from typing import Any


DEFAULT_SEVERITY_MAPPING = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "严重": "critical",
    "高危": "high",
    "中危": "medium",
    "低危": "low",
}

DEFAULT_STATUS_MAPPING = {
    "new": "new",
    "open": "open",
    "active": "open",
    "confirmed": "confirmed",
    "fixed": "fixed",
    "resolved": "resolved",
    "closed": "closed",
    "false_positive": "false_positive",
    "误报": "false_positive",
}


def _get(raw: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return default


def normalize_severity(value: Any, mapping: dict[str, str] | None = None) -> str:
    mapping = {**DEFAULT_SEVERITY_MAPPING, **(mapping or {})}
    return mapping.get(str(value or "").strip().lower(), "medium")


def normalize_status(value: Any, default: str, mapping: dict[str, str] | None = None) -> str:
    mapping = {**DEFAULT_STATUS_MAPPING, **(mapping or {})}
    return mapping.get(str(value or "").strip().lower(), default)


def normalize_asset(raw: dict[str, Any], connector_id: str) -> dict[str, Any]:
    normalized = {
        "id": _get(raw, "id", "asset_id", default=""),
        "name": _get(raw, "name", "hostname", "domain", "ip", default="Unknown Asset"),
        "asset_type": _get(raw, "asset_type", "type", default="other"),
        "ip": _get(raw, "ip", "address"),
        "hostname": _get(raw, "hostname", "host_name"),
        "domain": _get(raw, "domain", "fqdn"),
        "business_system": _get(raw, "business_system", "system"),
        "business_owner": _get(raw, "business_owner", "owner"),
        "importance": _get(raw, "importance", "criticality", default="medium"),
        "exposure_level": _get(raw, "exposure_level", "exposure", default="unknown"),
        "environment": _get(raw, "environment", "env", default="unknown"),
        "open_ports": list(_get(raw, "open_ports", "ports", default=[])),
        "services": list(_get(raw, "services", default=[])),
        "protocols": list(_get(raw, "protocols", default=[])),
        "security_controls": dict(_get(raw, "security_controls", "controls", default={})),
        "tags": list(_get(raw, "tags", default=[])),
        "description": _get(raw, "description"),
    }
    return {
        **normalized,
        "raw_data": {"connector_id": connector_id, "response": raw},
        "normalized_data": {key: value for key, value in normalized.items() if value not in (None, "", [], {})},
    }


def normalize_vulnerability(
    raw: dict[str, Any],
    connector_id: str,
    severity_mapping: dict[str, str] | None = None,
    status_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    normalized = {
        "id": _get(raw, "id", "vulnerability_id", default=""),
        "asset_id": _get(raw, "asset_id", "assetId", default=""),
        "cve_id": _get(raw, "cve_id", "cve"),
        "title": _get(raw, "title", "name", default="Untitled vulnerability"),
        "severity": normalize_severity(_get(raw, "severity", "risk_level"), severity_mapping),
        "cvss_score": _get(raw, "cvss_score", "cvss"),
        "epss_score": _get(raw, "epss_score", "epss"),
        "kev": bool(_get(raw, "kev", "known_exploited", default=False)),
        "exploit_available": bool(_get(raw, "exploit_available", "poc", default=False)),
        "description": _get(raw, "description"),
        "affected_component": _get(raw, "affected_component", "component"),
        "remediation": _get(raw, "remediation", "fix"),
        "status": normalize_status(_get(raw, "status"), "open", status_mapping),
        "discovered_at": _get(raw, "discovered_at", "first_seen"),
    }
    return {
        **normalized,
        "raw_data": {"connector_id": connector_id, "response": raw},
        "normalized_data": {key: value for key, value in normalized.items() if value not in (None, "", [], {})},
    }


def normalize_alert(
    raw: dict[str, Any],
    connector_id: str,
    severity_mapping: dict[str, str] | None = None,
    status_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    ioc = _get(raw, "ioc", "iocs", default=[])
    if isinstance(ioc, str):
        ioc = [ioc]
    normalized = {
        "id": _get(raw, "id", "alert_id", default=""),
        "asset_id": _get(raw, "asset_id", "assetId"),
        "source": _get(raw, "source", default="other"),
        "title": _get(raw, "title", "name", default="Untitled alert"),
        "severity": normalize_severity(_get(raw, "severity", "risk_level"), severity_mapping),
        "alert_type": _get(raw, "alert_type", "type"),
        "description": _get(raw, "description"),
        "raw_event": raw,
        "raw_data": {"connector_id": connector_id, "response": raw},
        "ioc": list(ioc),
        "mitre_technique": _get(raw, "mitre_technique", "mitre"),
        "status": normalize_status(_get(raw, "status"), "new", status_mapping),
        "occurred_at": _get(raw, "occurred_at", "timestamp", "first_seen"),
    }
    normalized["normalized_data"] = {
        key: value
        for key, value in normalized.items()
        if key not in {"raw_event", "raw_data"} and value not in (None, "", [], {})
    }
    return normalized


def normalize_honeypot_event(raw: dict[str, Any], connector_id: str) -> dict[str, Any]:
    normalized = {
        "id": _get(raw, "id", "event_id", default=""),
        "sensor_id": _get(raw, "sensor_id", "sensor"),
        "source_ip": _get(raw, "source_ip", "src_ip"),
        "target_ip": _get(raw, "target_ip", "dst_ip"),
        "protocol": _get(raw, "protocol"),
        "service": _get(raw, "service"),
        "event_type": _get(raw, "event_type", "type"),
        "payload": _get(raw, "payload"),
        "geo": dict(_get(raw, "geo", default={})),
        "threat_label": _get(raw, "threat_label", "label"),
        "occurred_at": _get(raw, "occurred_at", "timestamp"),
    }
    return {
        **normalized,
        "raw_data": {"connector_id": connector_id, "response": raw},
        "normalized_data": {key: value for key, value in normalized.items() if value not in (None, "", [], {})},
    }
