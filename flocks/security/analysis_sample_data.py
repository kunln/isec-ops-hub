"""Demo Analysis Case sample data for current-version closure flows."""

from __future__ import annotations

from typing import Any

from flocks.security.models import AnalysisCase, AlertSource, SecuritySeverity
from flocks.security.schemas import AlertCreate, AnalysisCaseCreate, IncidentCreate
from flocks.security.store import SecurityStore, default_store, utc_now

DEMO_PREFIX = "[Demo Closure]"


def _fact(kind: str, statement: str, source: str, strength: str = "medium") -> dict[str, Any]:
    return {"fact_type": kind, "statement": statement, "source_ref": source, "confidence": "high", "strength": strength, "observed_at": utc_now()}


def _gap(kind: str, source_type: str, description: str) -> dict[str, Any]:
    return {"gap_type": kind, "missing_source_type": source_type, "description": description, "impact": "Limits end-to-end confirmation.", "suggested_connector_capability": f"collect {source_type}"}


def _item(title: str, source: str, description: str) -> dict[str, Any]:
    return {"title": title, "source_ref": source, "description": description}


def _case(title: str, verdict: str, severity: str, facts: list[dict[str, Any]], gaps: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "title": f"{DEMO_PREFIX} {title}",
        "description": f"Demo closure sample: {title}",
        "verdict": verdict,
        "severity": severity,
        "confidence": extra.pop("confidence", "medium"),
        "evidence_coverage": extra.pop("evidence_coverage", "ec1_single_source"),
        "analysis_mode": extra.pop("analysis_mode", "single_source"),
        "notification_decision": extra.pop("notification_decision", "no_notify_store_only"),
        "incident_decision": extra.pop("incident_decision", "continue_monitoring"),
        "disposition": extra.pop("disposition", "open"),
        "case_status": extra.pop("case_status", "new"),
        "facts": facts,
        "evidence_items": extra.pop("evidence_items", [_item("Primary alert evidence", "demo:alert", facts[0]["statement"])]),
        "evidence_gaps": gaps,
        "hypotheses": extra.pop("hypotheses", [{"name": "Evidence-led demo hypothesis", "status": "open", "reason": facts[0]["statement"]}]),
        "recommendations": extra.pop("recommendations", ["Review facts and evidence gaps before any escalation.", "No automatic remediation is performed by this demo data."]),
        **extra,
    }


def _samples() -> list[dict[str, Any]]:
    return [
        _case("WAF SQL Injection blocked", "confirmed_attack_attempt_blocked", "medium", [_fact("waf_block_observed", "WAF blocked SQL injection payload against /login.", "demo:waf:sqli", "strong")], [_gap("scope_boundary", "backend_access_log", "Backend access log not queried for post-block validation.")], notification_decision="daily_digest", incident_decision="do_not_escalate", disposition="closed_blocked_attempt", case_status="resolved", confirmation_records=[{"confirmation_type": "confirm_blocked_attempt", "decision": "confirmed", "reviewer": "demo-analyst", "comment": "Blocked at WAF."}]),
        _case("WAF RCE monitor allow", "suspicious_true_positive", "high", [_fact("waf_allow_observed", "WAF monitored an RCE-like request that was allowed for observation.", "demo:waf:rce", "strong")], [_gap("missing_backend_validation", "backend_access_log", "Need application response and backend access logs."), _gap("missing_endpoint_validation", "edr", "Need EDR process telemetry for target host.")], notification_decision="confirmation_request", incident_decision="needs_human_confirmation", case_status="awaiting_confirmation", notification_records=[{"notification_type": "confirmation_request", "channel": "in_app", "status": "sent", "title": "Confirm WAF RCE monitor case", "recipients": ["secops-demo"]}]),
        _case("EDR suspicious PowerShell", "suspicious_true_positive", "high", [_fact("process_execution_observed", "EDR observed encoded PowerShell spawned by office process.", "demo:edr:powershell", "strong")], [_gap("missing_network_context", "network_traffic", "Outbound network telemetry not loaded.")], notification_decision="confirmation_request", incident_decision="escalate_to_incident"),
        _case("WebShell suspected", "suspicious_true_positive", "critical", [_fact("process_execution_observed", "Web worker spawned shell command.", "demo:edr:webshell", "strong"), _fact("file_artifact_observed", "Suspicious JSP artifact appeared under web root.", "demo:file:webshell", "strong")], [_gap("missing_network_context", "network_traffic", "Need traffic/session evidence for remote control path.")], notification_decision="realtime_notify", incident_decision="needs_human_confirmation"),
        _case("Impossible travel login", "suspicious_true_positive", "medium", [_fact("authentication_event_observed", "Two successful logins for one user were observed from distant geographies within 10 minutes.", "demo:iam:travel", "strong")], [_gap("missing_user_confirmation", "identity_provider", "User confirmation and device posture are not available.")], notification_decision="confirmation_request", incident_decision="needs_human_confirmation"),
        _case("Database sensitive query", "suspicious_true_positive", "high", [_fact("database_query_observed", "Database audit observed bulk select from customer table.", "demo:db:query", "strong"), _fact("sensitive_data_access_observed", "Sensitive columns were included in the query projection.", "demo:db:sensitive", "strong")], [_gap("missing_business_context", "change_ticket", "No change ticket or business justification linked.")], notification_decision="confirmation_request"),
        _case("Authorized scanner false positive", "false_positive_rule_noise", "low", [_fact("scanner_activity_observed", "Source IP matches approved vulnerability scanner window.", "demo:scanner:approved", "strong")], [_gap("scope_boundary", "scanner_schedule", "Scanner schedule should be retained for audit evidence.")], incident_decision="do_not_escalate", disposition="closed_false_positive", case_status="resolved", confirmation_records=[{"confirmation_type": "confirm_false_positive", "decision": "confirmed", "reviewer": "demo-analyst", "comment": "Approved scanner."}]),
        _case("Benign business activity", "benign_business_activity", "informational", [_fact("business_activity_observed", "Admin export matched a scheduled business report.", "demo:app:report", "strong")], [_gap("scope_boundary", "business_owner_confirmation", "Owner confirmation is represented as demo data only.")], incident_decision="do_not_escalate", disposition="closed_benign", case_status="resolved", confirmation_records=[{"confirmation_type": "confirm_benign", "decision": "confirmed", "reviewer": "demo-owner", "comment": "Expected business activity."}]),
        _case("Weak generic alert", "insufficient_evidence", "low", [_fact("generic_alert_observed", "A generic SIEM rule fired without payload details.", "demo:siem:generic", "weak")], [_gap("insufficient_source_detail", "raw_event", "Raw event payload and correlated telemetry are missing.")], evidence_coverage="ec0_signal"),
        _case("Escalated incident case", "confirmed_incident", "critical", [_fact("multi_source_compromise_observed", "EDR execution and WAF exploit signal align on the same asset.", "demo:multi:incident", "critical")], [_gap("post_incident_scope", "forensic_image", "Full forensic image collection remains out of scope for demo.")], notification_decision="realtime_notify", incident_decision="escalate_to_incident", case_status="escalated", disposition="escalated_to_incident"),
    ]


async def load_analysis_sample_data(store: SecurityStore | None = None) -> dict[str, Any]:
    store = store or default_store
    existing = {case.title: case for case in await store.list_analysis_cases() if case.title.startswith(DEMO_PREFIX)}
    loaded_ids: list[str] = []
    created_count = 0
    for sample in _samples():
        if sample["title"] in existing:
            loaded_ids.append(existing[sample["title"]].id)
            continue
        alert = await store.create_alert(AlertCreate(title=sample["title"].replace(DEMO_PREFIX, "").strip(), source=AlertSource.WAF if "WAF" in sample["title"] else AlertSource.OTHER, severity=SecuritySeverity(sample["severity"] if sample["severity"] != "informational" else "info"), description=sample["description"], raw_data={"demo": True}))
        sample["related_alert_ids"] = [alert.id]
        case = await store.create_analysis_case(AnalysisCaseCreate(**sample))
        loaded_ids.append(case.id)
        created_count += 1
    # Ensure escalated demo case has a linked Incident without duplicating.
    cases = await store.list_analysis_cases()
    by_title = {case.title: case for case in cases}
    escalated = by_title.get(f"{DEMO_PREFIX} Escalated incident case")
    if escalated and not escalated.related_incident_id:
        incident = await store.create_incident(IncidentCreate(title=escalated.title, severity="critical", summary=escalated.summary or escalated.description, analysis="Demo incident linked from Analysis Case evidence.", recommendation="Continue evidence-led investigation; no automated remediation.", alert_ids=escalated.related_alert_ids, evidence=[fact.statement for fact in escalated.facts], confidence=escalated.confidence, created_by="analysis_case_demo", raw_data={"analysis_case_id": escalated.id, "demo": True}, normalized_data={"analysis_case_id": escalated.id, "demo": True}))
        escalated = await store.update_analysis_case(escalated.id, {"related_incident_id": incident.id}) or escalated
    return {"loaded": created_count, "case_ids": loaded_ids, "total_demo_cases": len(loaded_ids)}


async def clear_analysis_sample_data(store: SecurityStore | None = None) -> dict[str, Any]:
    store = store or default_store
    deleted = 0
    for case in await store.list_analysis_cases():
        if case.title.startswith(DEMO_PREFIX):
            deleted += int(await store.delete_analysis_case(case.id))
    return {"deleted": deleted}
