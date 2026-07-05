"""Built-in mock connector for validating connector standardization."""

from __future__ import annotations

from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from flocks.security.connectors.models import (
    ConnectorCapability,
    ConnectorHealthCheckResult,
    ConnectorManifest,
    ConnectorTestResult,
)
from flocks.security.connectors.normalizer import (
    normalize_alert,
    normalize_asset,
    normalize_honeypot_event,
    normalize_vulnerability,
)


MOCK_CONNECTOR_ID = "mock-security-demo"

RAW_SAMPLE_RESPONSE: dict[str, Any] = {
    "assets": [
        {
            "id": "ast_mock_portal",
            "name": "Mock Internet Portal",
            "type": "web_app",
            "ip": "203.0.113.20",
            "hostname": "mock-portal-01",
            "domain": "mock-portal.example.com",
            "system": "Mock Customer Portal",
            "owner": "Security Demo Team",
            "criticality": "critical",
            "exposure": "external",
            "env": "production",
            "ports": [80, 443],
            "services": ["nginx", "mock-upload-service"],
            "protocols": ["http", "https"],
            "controls": {"edr": True, "waf": True, "ndr": True, "centralized_logging": False},
            "tags": ["mock", "internet-facing"],
        }
    ],
    "vulnerabilities": [
        {
            "id": "vul_mock_rce",
            "asset_id": "ast_mock_portal",
            "cve": "CVE-MOCK-2026-0001",
            "name": "Mock Upload Handler Remote Command Execution",
            "severity": "critical",
            "cvss": 9.8,
            "epss": 0.88,
            "known_exploited": True,
            "poc": True,
            "component": "Mock Upload Handler",
            "fix": "Upgrade upload handler and disable command execution paths.",
            "status": "confirmed",
        }
    ],
    "alerts": [
        {
            "id": "alr_mock_webshell",
            "asset_id": "ast_mock_portal",
            "source": "xdr",
            "name": "Mock suspicious upload followed by shell execution",
            "severity": "high",
            "type": "webshell_or_command_execution",
            "iocs": ["198.51.100.44", "mock-portal.example.com"],
            "mitre": "T1059",
            "status": "new",
            "timestamp": "2026-06-01T08:00:00+00:00",
        }
    ],
    "honeypot_events": [
        {
            "id": "hpt_mock_probe",
            "sensor": "mock-edge-sensor-01",
            "src_ip": "198.51.100.44",
            "dst_ip": "203.0.113.20",
            "protocol": "http",
            "service": "web",
            "type": "exploit_probe",
            "payload": "GET /upload?cmd=id HTTP/1.1",
            "label": "mock_exploit_probe",
            "timestamp": "2026-06-01T08:01:00+00:00",
        }
    ],
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def build_mock_manifest() -> ConnectorManifest:
    normalized = normalize_mock_response(RAW_SAMPLE_RESPONSE)
    return ConnectorManifest(
        id=MOCK_CONNECTOR_ID,
        name="Mock Security Demo Connector",
        vendor="Flocks",
        product="Security Demo",
        product_version="2026.06",
        deployment="local_mock",
        auth_methods=["none"],
        capabilities=[
            ConnectorCapability.ASSET_SEARCH,
            ConnectorCapability.ASSET_GET,
            ConnectorCapability.VULNERABILITY_SEARCH,
            ConnectorCapability.VULNERABILITY_GET,
            ConnectorCapability.ALERT_SEARCH,
            ConnectorCapability.ALERT_GET,
            ConnectorCapability.ALERT_TRIAGE_CONTEXT,
            ConnectorCapability.HONEYPOT_EVENT_SEARCH,
        ],
        field_mapping={
            "asset": {
                "type": "asset_type",
                "criticality": "importance",
                "exposure": "exposure_level",
                "env": "environment",
            },
            "vulnerability": {
                "cve": "cve_id",
                "name": "title",
                "known_exploited": "kev",
                "poc": "exploit_available",
            },
            "alert": {
                "name": "title",
                "type": "alert_type",
                "mitre": "mitre_technique",
            },
        },
        severity_mapping={
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        },
        status_mapping={
            "new": "new",
            "confirmed": "confirmed",
            "closed": "closed",
            "false_positive": "false_positive",
        },
        pagination={"type": "offset", "page_size": 100},
        rate_limit={"requests_per_minute": 600, "burst": 50},
        permissions=["asset:read", "vulnerability:read", "alert:read", "honeypot:read"],
        risk_level="low",
        description="Local mock connector used to validate manifest, capability, health-check and raw-to-normalized mapping behavior.",
        raw_response=RAW_SAMPLE_RESPONSE,
        normalized_data=normalized,
        health_check=ConnectorHealthCheckResult(
            status="ok",
            message="Mock connector is available locally.",
            checked_at=utc_now(),
            latency_ms=0,
            details={"mode": "local_mock"},
        ),
    )


def normalize_mock_response(raw_response: dict[str, Any]) -> dict[str, Any]:
    return {
        "assets": [normalize_asset(item, MOCK_CONNECTOR_ID) for item in raw_response.get("assets", [])],
        "vulnerabilities": [
            normalize_vulnerability(item, MOCK_CONNECTOR_ID)
            for item in raw_response.get("vulnerabilities", [])
        ],
        "alerts": [normalize_alert(item, MOCK_CONNECTOR_ID) for item in raw_response.get("alerts", [])],
        "honeypot_events": [
            normalize_honeypot_event(item, MOCK_CONNECTOR_ID)
            for item in raw_response.get("honeypot_events", [])
        ],
    }


async def test_mock_connection() -> ConnectorTestResult:
    started = perf_counter()
    normalized = normalize_mock_response(RAW_SAMPLE_RESPONSE)
    latency_ms = max(0, round((perf_counter() - started) * 1000))
    health = ConnectorHealthCheckResult(
        status="ok",
        message="Mock connector test succeeded. No external network call was made.",
        checked_at=utc_now(),
        latency_ms=latency_ms,
        details={
            "assets": len(normalized["assets"]),
            "vulnerabilities": len(normalized["vulnerabilities"]),
            "alerts": len(normalized["alerts"]),
            "honeypot_events": len(normalized["honeypot_events"]),
        },
    )
    manifest = build_mock_manifest()
    return ConnectorTestResult(
        connector_id=MOCK_CONNECTOR_ID,
        success=True,
        status="ok",
        message=health.message,
        health_check=health,
        capabilities=manifest.capabilities,
        raw_response=RAW_SAMPLE_RESPONSE,
        normalized_data=normalized,
    )
