"""Idempotent demo data for the Security Extension."""

from __future__ import annotations

from typing import Any

from flocks.security.models import Alert, Asset, HoneypotEvent, Vulnerability
from flocks.security.schemas import SecurityListFilters
from flocks.security.store import SecurityStore, default_store, utc_now
from flocks.storage.storage import Storage


SAMPLE_MANIFEST_KEY = "security/sample-data/manifest"

SAMPLE_IDS = {
    "asset": "ast_sample_internet_portal",
    "vulnerability": "vul_sample_portal_critical",
    "alert": "alr_sample_webshell_xdr",
    "honeypot_event": "hpt_sample_exploit_probe",
}


async def load_sample_data(store: SecurityStore | None = None) -> dict[str, Any]:
    store = store or default_store
    now = utc_now()

    asset = await store.upsert_asset(
        Asset(
            id=SAMPLE_IDS["asset"],
            name="Internet Portal",
            asset_type="web_app",
            ip="203.0.113.10",
            hostname="portal-web-01",
            domain="portal.example.com",
            business_system="Customer Internet Portal",
            business_owner="Security Demo Team",
            importance="critical",
            exposure_level="external",
            environment="production",
            open_ports=[80, 443],
            services=["nginx", "demo-upload-service"],
            protocols=["http", "https"],
            security_controls={
                "edr": True,
                "waf": True,
                "ndr": True,
                "vulnerability_scanner": True,
                "centralized_logging": False,
            },
            tags=["sample", "internet-facing", "mvp-demo"],
            description="Public-facing demo web portal used by the Security Extension MVP.",
            created_at=now,
            updated_at=now,
        )
    )

    vulnerability = await store.upsert_vulnerability(
        Vulnerability(
            id=SAMPLE_IDS["vulnerability"],
            asset_id=asset.id,
            cve_id="CVE-DEMO-2026-0001",
            title="Demo Remote Command Execution Exposure",
            severity="critical",
            cvss_score=9.8,
            epss_score=0.85,
            kev=True,
            exploit_available=True,
            description=(
                "Fictitious placeholder vulnerability for MVP demonstration. "
                "It models a public web component with remote command execution risk."
            ),
            affected_component="Demo Portal Upload Handler",
            remediation="Apply vendor patch, disable vulnerable upload handler, and enforce WAF virtual patching.",
            status="confirmed",
            discovered_at=now,
            created_at=now,
            updated_at=now,
        )
    )

    alert = await store.upsert_alert(
        Alert(
            id=SAMPLE_IDS["alert"],
            asset_id=asset.id,
            source="xdr",
            title="疑似 WebShell 上传或异常命令执行",
            severity="high",
            alert_type="webshell_or_command_execution",
            description="XDR detected suspicious upload behavior followed by abnormal command execution patterns.",
            raw_event={
                "src_ip": "198.51.100.23",
                "dst_ip": "203.0.113.10",
                "url": "https://portal.example.com/upload",
                "process": "sh -c whoami",
                "note": "Demo event, not real customer telemetry.",
            },
            ioc=["198.51.100.23", "portal.example.com"],
            mitre_technique="T1059",
            status="new",
            occurred_at=now,
            created_at=now,
            updated_at=now,
        )
    )

    honeypot_event = await store.upsert_honeypot_event(
        HoneypotEvent(
            id=SAMPLE_IDS["honeypot_event"],
            sensor_id="demo-edge-sensor-01",
            source_ip="198.51.100.23",
            target_ip="203.0.113.10",
            protocol="http",
            service="web",
            event_type="exploit_probe",
            payload="GET /upload?cmd=whoami HTTP/1.1",
            geo={"country": "Reserved", "note": "RFC 5737 documentation address"},
            threat_label="demo_exploit_probe",
            occurred_at=now,
            created_at=now,
            updated_at=now,
        )
    )

    manifest = {
        "loaded_at": now,
        "assets": [asset.id],
        "vulnerabilities": [vulnerability.id],
        "alerts": [alert.id],
        "honeypot_events": [honeypot_event.id],
    }
    await Storage.set(SAMPLE_MANIFEST_KEY, manifest, "security.sample_manifest")

    return {
        "loaded": True,
        "manifest": manifest,
        "ids": SAMPLE_IDS,
    }


async def clear_sample_data(store: SecurityStore | None = None) -> dict[str, Any]:
    store = store or default_store
    manifest = await Storage.get(SAMPLE_MANIFEST_KEY) or {}
    deleted: dict[str, int] = {
        "assets": 0,
        "vulnerabilities": 0,
        "alerts": 0,
        "incidents": 0,
        "honeypot_events": 0,
    }

    sample_alert_ids = set(manifest.get("alerts") or [SAMPLE_IDS["alert"]])
    incidents = await store.list_incidents(SecurityListFilters(limit=500))
    for incident in incidents:
        if incident.created_by == "security_triage" and sample_alert_ids & set(incident.alert_ids):
            if await store.delete_incident(incident.id):
                deleted["incidents"] += 1

    for event_id in manifest.get("honeypot_events", [SAMPLE_IDS["honeypot_event"]]):
        if await store.delete_honeypot_event(event_id):
            deleted["honeypot_events"] += 1
    for alert_id in manifest.get("alerts", [SAMPLE_IDS["alert"]]):
        if await store.delete_alert(alert_id):
            deleted["alerts"] += 1
    for vuln_id in manifest.get("vulnerabilities", [SAMPLE_IDS["vulnerability"]]):
        if await store.delete_vulnerability(vuln_id):
            deleted["vulnerabilities"] += 1
    for asset_id in manifest.get("assets", [SAMPLE_IDS["asset"]]):
        if await store.delete_asset(asset_id):
            deleted["assets"] += 1

    manifest_deleted = await Storage.delete(SAMPLE_MANIFEST_KEY)
    return {
        "cleared": True,
        "deleted": deleted,
        "manifest_deleted": manifest_deleted,
    }
