"""Rule-based fact extraction and initial Analysis Case decisions."""

from __future__ import annotations

import json
import re
from typing import Any

from flocks.security.models import (
    Alert,
    AnalysisCase,
    AnalysisCaseSeverity,
    AnalysisCaseVerdict,
    AnalysisDisposition,
    AnalysisMode,
    Confidence,
    EvidenceCoverage,
    FactStrength,
    IncidentDecision,
    NotificationDecision,
)
from flocks.security.schemas import (
    AnalysisCaseCreate,
    AnalysisCaseUpdate,
    AnalysisEvidenceGapCreate,
    AnalysisEvidenceItemCreate,
    AnalysisFactCreate,
)

ATTACK_PATTERNS = {
    "sql injection": ["sql injection", "sqli", "union select"],
    "xss": ["xss", "cross site scripting"],
    "rce": ["rce", "remote code execution"],
    "command injection": ["command injection"],
    "path traversal": ["path traversal", "../"],
    "webshell": ["webshell", "web shell"],
    "deserialization": ["deserialization"],
    "brute force": ["brute force"],
    "credential stuffing": ["credential stuffing"],
    "impossible travel": ["impossible travel"],
    "malware": ["malware", "mimikatz"],
    "beacon": ["beacon"],
    "c2": ["c2", "command and control"],
    "lateral movement": ["lateral movement"],
    "suspicious process": ["suspicious process"],
    "suspicious powershell": ["powershell"],
    "suspicious authentication": ["suspicious authentication"],
    "sensitive data access": ["sensitive data access"],
}
BLOCK_ACTIONS = ["block", "blocked", "deny", "denied", "drop", "dropped", "prevent", "quarantine"]
ALLOW_ACTIONS = ["allow", "allowed", "monitor", "pass", "unknown"]
NOISE_TERMS = ["false positive", "test rule", "scanner allowlist", "health check", "known benign pattern", "duplicated alert", "authorized scan"]


def _dump(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _value(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default) if not isinstance(obj, dict) else obj.get(name, default)


def _blob(alert: Alert) -> str:
    parts = [alert.title, alert.description, alert.source, alert.severity, alert.alert_type, alert.mitre_technique]
    parts.extend([alert.raw_event, alert.raw_data, alert.normalized_data, alert.ioc])
    return " ".join(_dump(part) for part in parts if part is not None).lower()


def _source_ref(alert: Alert) -> str:
    return f"alert:{alert.id}"


def _fact(alert: Alert, fact_type: str, statement: str, *, strength: FactStrength = FactStrength.MEDIUM, supports: list[str] | None = None, metadata: dict[str, Any] | None = None) -> AnalysisFactCreate:
    return AnalysisFactCreate(
        fact_type=fact_type,
        statement=statement,
        source_ref=_source_ref(alert),
        related_alert_id=alert.id,
        related_asset_id=alert.asset_id,
        confidence=Confidence.MEDIUM,
        strength=strength,
        supports=supports or [],
        observed_at=alert.occurred_at,
        metadata=metadata or {},
    )


def _has_any(text: str, terms: list[str]) -> bool:
    for term in terms:
        if len(term.strip()) <= 3 and term.strip().isalnum():
            if re.search(r"(?<![a-z0-9])" + re.escape(term.strip()) + r"(?![a-z0-9])", text):
                return True
        elif term in text:
            return True
    return False


def _dict_has_any(data: dict[str, Any], keys: list[str]) -> bool:
    lowered = {str(key).lower(): value for key, value in data.items()}
    return any(key in lowered and lowered[key] not in (None, "", [], {}) for key in keys)


def extract_facts_from_alert(alert: Alert) -> list[AnalysisFactCreate]:
    text = _blob(alert)
    facts = [_fact(alert, "alert_signal", f"Alert signal '{alert.title}' was observed" + (f": {alert.description}" if alert.description else ""), supports=["attack_attempt_exists"])]
    for pattern, terms in ATTACK_PATTERNS.items():
        if _has_any(text, terms):
            facts.append(_fact(alert, "attack_pattern_matched", f"Alert content matched attack pattern: {pattern}", strength=FactStrength.STRONG, supports=["attack_pattern_valid"], metadata={"pattern": pattern}))
            break
    if _has_any(text, BLOCK_ACTIONS):
        facts.append(_fact(alert, "protection_action_observed", "Protection action observed: blocked/denied/dropped/prevented", strength=FactStrength.STRONG, supports=["protection_action_observed", "attack_blocked"]))
    raw = {**(alert.raw_event or {}), **(alert.raw_data or {}), **(alert.normalized_data or {})}
    raw_lower = {str(k).lower(): v for k, v in raw.items()}
    if _dict_has_any(raw_lower, ["backend", "origin", "upstream", "status_code", "backend_response", "request_forwarded"]):
        facts.append(_fact(alert, "backend_request_observed", "Backend/origin request evidence is present in alert payload", supports=["backend_reached"]))
    typed_rules = [
        ("vulnerability_condition_present", ["cve", "vulnerability_id", "vuln_id", "exploit", "vulnerable", "asset vulnerability context"], ["exploitable_condition_present"]),
        ("threat_intel_match", ["reputation", "malicious_ip", "threat_intel", "blacklist", "ioc_match"], ["attack_attempt_exists"]),
        ("process_execution_observed", ["process_name", "command_line", "parent_process", "powershell", "cmd.exe", "bash", " wscript", "rundll32", "mshta", "encoded command"], ["host_compromise", "post_exploitation_activity"]),
        ("file_artifact_observed", ["file_path", "file_name", "sha256", "md5", "malware_file", "hash"], ["host_compromise"]),
        ("network_connection_observed", ["src_ip", "dst_ip", "destination_ip", "domain", "url", "port", "c2", "beacon"], ["post_exploitation_activity"]),
        ("authentication_event_observed", ["login", "failed login", "successful login", "impossible travel", "brute force", "password spray", "mfa"], ["identity_compromise"]),
        ("database_query_observed", ["sql", "query", "select", "update", "delete", "drop", "sensitive table", "database audit"], ["data_access_impact"]),
        ("sensitive_data_access_observed", ["sensitive", "privacy", "credential", "id card", "phone", "export", "dump", "bulk query", "large download"], ["data_access_impact"]),
        ("lateral_movement_observed", ["lateral", "smb", "rdp", "winrm", "psexec", "remote execution", "admin share"], ["post_exploitation_activity"]),
    ]
    for fact_type, terms, supports in typed_rules:
        if _has_any(text, terms):
            facts.append(_fact(alert, fact_type, f"Alert content contains evidence for {fact_type}", strength=FactStrength.STRONG, supports=supports))
    if _has_any(text, NOISE_TERMS):
        facts.append(_fact(alert, "rule_noise_observed", "Alert content explicitly indicates rule noise or authorized benign activity", strength=FactStrength.STRONG, supports=["rule_noise", "benign_activity"]))
    return _dedup_facts(facts)


def _evidence_items(alerts: list[Alert]) -> list[AnalysisEvidenceItemCreate]:
    return [AnalysisEvidenceItemCreate(title="Raw alert signal / Alert source evidence", description=f"Evidence captured from Alert {a.id}: {a.title}", source_ref=_source_ref(a), metadata={"source": str(a.source), "severity": str(a.severity), "raw_event_summary": _dump(a.raw_event)[:1000]}) for a in alerts]


def _evidence_gaps(alerts: list[Alert], facts: list[Any]) -> list[AnalysisEvidenceGapCreate]:
    text = " ".join(_blob(a) for a in alerts)
    fact_types = {str(_value(f, "fact_type")) for f in facts}
    gaps: list[AnalysisEvidenceGapCreate] = []
    def add(missing: str, desc: str, cap: str, impact: str) -> None:
        gaps.append(AnalysisEvidenceGapCreate(gap_type="evidence_gap", missing_source_type=missing, description=desc, suggested_connector_capability=cap, impact=impact))
    if "waf" in text or "web" in text or "attack_pattern_matched" in fact_types:
        add("edr", "未接入或未查询终端进程/文件/网络证据，无法确认主机侧是否成功利用", "endpoint.process_tree", "limits exploit success confirmation")
        if not any(str(_value(f, "fact_type")) == "protection_action_observed" for f in facts) or _has_any(text, ALLOW_ACTIONS):
            add("backend_access_log", "缺少后端访问日志，无法确认攻击请求是否到达业务后端", "web.backend_log.query", "limits backend reachability confirmation")
    if any(t in fact_types for t in ["database_query_observed", "sensitive_data_access_observed"]):
        add("database_audit", "缺少数据库审计上下文，无法确认敏感数据访问范围", "database.audit.query", "limits data impact confirmation")
    if "authentication_event_observed" in fact_types:
        add("identity_activity", "缺少身份认证上下文，无法确认账号是否被盗用或是否为正常登录", "identity.activity.query", "limits identity compromise confirmation")
    if "process_execution_observed" in fact_types:
        add("network_traffic", "缺少网络/身份侧证据，无法确认扩散路径或账号来源", "network.traffic.query", "limits post-exploitation path confirmation")
    add("asset_context", "缺少资产重要性/业务归属信息，影响严重性判断", "asset.context.query", "limits severity calibration")
    return _dedup_gaps(gaps)


def _severity(alerts: list[Alert], cap_medium: bool = False) -> AnalysisCaseSeverity:
    vals = [str(a.severity).split(".")[-1].lower() for a in alerts]
    order = ["informational", "low", "medium", "high", "critical"]
    sev = max(vals or ["medium"], key=lambda x: order.index(x) if x in order else 2)
    if cap_medium and sev in {"high", "critical"}:
        sev = "medium"
    return AnalysisCaseSeverity(sev if sev in order else "medium")


def infer_initial_case_decision(case: AnalysisCase | None, facts: list[Any], gaps: list[Any], alerts: list[Alert]) -> dict[str, Any]:
    fact_types = {str(_value(f, "fact_type")) for f in facts}
    text = " ".join([_blob(a) for a in alerts] + [str(_value(f, "statement", "")).lower() for f in facts])
    decision: dict[str, Any] = dict(verdict=AnalysisCaseVerdict.INSUFFICIENT_EVIDENCE, severity=_severity(alerts, cap_medium=True), confidence=Confidence.MEDIUM, evidence_coverage=EvidenceCoverage.EC0_SIGNAL, analysis_mode=AnalysisMode.SINGLE_SOURCE, notification_decision=NotificationDecision.NO_NOTIFY_STORE_ONLY, incident_decision=IncidentDecision.CONTINUE_MONITORING, disposition=AnalysisDisposition.OPEN)
    if "rule_noise_observed" in fact_types:
        decision.update(verdict=AnalysisCaseVerdict.FALSE_POSITIVE_RULE_NOISE, severity=AnalysisCaseSeverity.LOW, notification_decision=NotificationDecision.NO_NOTIFY_STORE_ONLY, incident_decision=IncidentDecision.DO_NOT_ESCALATE)
    elif "process_execution_observed" in fact_types and _has_any(text, ["powershell encoded", "encoded command", "web service spawned shell", "cmd.exe from web process", "mimikatz", "cobalt", "beacon", "malware", "privilege escalation", "lateral movement"]):
        multi = bool(fact_types & {"network_connection_observed", "file_artifact_observed", "lateral_movement_observed"})
        decision.update(verdict=AnalysisCaseVerdict.CONFIRMED_INCIDENT if multi else AnalysisCaseVerdict.SUSPICIOUS_TRUE_POSITIVE, severity=AnalysisCaseSeverity.CRITICAL if multi else AnalysisCaseSeverity.HIGH, confidence=Confidence.HIGH if multi else Confidence.MEDIUM, evidence_coverage=EvidenceCoverage.EC2_ENRICHED_SINGLE_SOURCE if multi else EvidenceCoverage.EC1_SINGLE_SOURCE, notification_decision=NotificationDecision.REALTIME_NOTIFY, incident_decision=IncidentDecision.ESCALATE_TO_INCIDENT if multi else IncidentDecision.NEEDS_HUMAN_CONFIRMATION)
    elif "authentication_event_observed" in fact_types and _has_any(text, ["impossible travel", "brute force", "multiple failed then success", "password spray"]):
        decision.update(verdict=AnalysisCaseVerdict.SUSPICIOUS_TRUE_POSITIVE, severity=_severity(alerts), evidence_coverage=EvidenceCoverage.EC1_SINGLE_SOURCE, notification_decision=NotificationDecision.CONFIRMATION_REQUEST, incident_decision=IncidentDecision.NEEDS_HUMAN_CONFIRMATION)
    elif "attack_pattern_matched" in fact_types and "protection_action_observed" in fact_types and not _has_any(text, ["action allow", "action monitor", "action pass", "\"action\": \"allow", "\"action\": \"monitor", "\"action\": \"pass"]):
        decision.update(verdict=AnalysisCaseVerdict.CONFIRMED_ATTACK_ATTEMPT_BLOCKED, severity=_severity(alerts), confidence=Confidence.HIGH, evidence_coverage=EvidenceCoverage.EC1_SINGLE_SOURCE, notification_decision=NotificationDecision.DAILY_DIGEST, incident_decision=IncidentDecision.DO_NOT_ESCALATE)
    elif "attack_pattern_matched" in fact_types:
        decision.update(verdict=AnalysisCaseVerdict.SUSPICIOUS_TRUE_POSITIVE, severity=_severity(alerts), evidence_coverage=EvidenceCoverage.EC1_SINGLE_SOURCE, notification_decision=NotificationDecision.CONFIRMATION_REQUEST, incident_decision=IncidentDecision.NEEDS_HUMAN_CONFIRMATION)
    elif fact_types & {"database_query_observed", "sensitive_data_access_observed"}:
        confirmed = _has_any(text, ["bulk export", "sensitive data dump", "large download", "dump"])
        decision.update(verdict=AnalysisCaseVerdict.CONFIRMED_INCIDENT if confirmed else AnalysisCaseVerdict.SUSPICIOUS_TRUE_POSITIVE, severity=AnalysisCaseSeverity.CRITICAL if confirmed else AnalysisCaseSeverity.HIGH, evidence_coverage=EvidenceCoverage.EC1_SINGLE_SOURCE, notification_decision=NotificationDecision.REALTIME_NOTIFY, incident_decision=IncidentDecision.ESCALATE_TO_INCIDENT if confirmed else IncidentDecision.NEEDS_HUMAN_CONFIRMATION)
    elif fact_types == {"alert_signal"}:
        decision.update(confidence=Confidence.LOW, severity=_severity(alerts, cap_medium=True))
    return decision


def _hypotheses(facts: list[Any], gaps: list[Any], alerts: list[Alert]) -> list[dict[str, Any]]:
    fact_types = {str(_value(f, "fact_type")) for f in facts}
    refs = sorted({str(_value(f, "source_ref")) for f in facts if _value(f, "source_ref")})
    def h(name: str, supported: bool | None, reason: str) -> dict[str, Any]:
        return {"name": name, "status": "supported" if supported else "unsupported" if supported is False else "unknown", "reason": reason, "supporting_source_refs": refs if supported else [], "contradicting_source_refs": []}
    return [
        h("attack_attempt_exists", "alert_signal" in fact_types, "Alert signal is present."),
        h("attack_pattern_valid", "attack_pattern_matched" in fact_types, "Rule-based pattern extraction result."),
        h("protection_action_observed", "protection_action_observed" in fact_types, "Protection action fact extraction result."),
        h("attack_blocked", "protection_action_observed" in fact_types, "Blocked/deny/drop/prevent action supports this."),
        h("backend_reached", "backend_request_observed" in fact_types if "backend_request_observed" in fact_types else None, "Requires explicit backend/upstream evidence."),
        h("exploitable_condition_present", "vulnerability_condition_present" in fact_types, "Vulnerability/exploit context extraction result."),
        h("exploit_success_possible", bool(fact_types & {"attack_pattern_matched", "vulnerability_condition_present"}), "Attack/vulnerability facts make success possible but not confirmed."),
        h("exploit_success_confirmed", bool(fact_types & {"process_execution_observed", "file_artifact_observed", "lateral_movement_observed"}), "Host/file/lateral evidence is required for confirmation."),
        h("host_compromise", bool(fact_types & {"process_execution_observed", "file_artifact_observed"}), "Endpoint artifacts support host impact."),
        h("data_access_impact", bool(fact_types & {"database_query_observed", "sensitive_data_access_observed"}), "Database or sensitive data facts support data impact."),
        h("post_exploitation_activity", bool(fact_types & {"network_connection_observed", "lateral_movement_observed"}), "Network/lateral facts support post exploitation."),
        h("identity_compromise", "authentication_event_observed" in fact_types, "Authentication facts support identity review."),
        h("benign_activity", "rule_noise_observed" in fact_types, "Only explicit benign/noise evidence supports this."),
        h("rule_noise", "rule_noise_observed" in fact_types, "Only explicit rule-noise evidence supports this."),
        h("insufficient_context", bool(gaps), "Evidence gaps remain and limit final confirmation."),
    ]


def _as_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return value


def _dedup_facts(facts: list[Any]) -> list[Any]:
    seen = set(); out = []
    for f in facts:
        key = (_value(f, "fact_type"), _value(f, "source_ref"), _value(f, "statement"))
        if key not in seen:
            seen.add(key); out.append(_as_payload(f))
    return out


def _dedup_items(items: list[Any]) -> list[Any]:
    seen = set(); out = []
    for item in items:
        key = (_value(item, "source_ref"), _value(item, "title"))
        if key not in seen:
            seen.add(key); out.append(_as_payload(item))
    return out


def _dedup_gaps(gaps: list[Any]) -> list[Any]:
    seen = set(); out = []
    for gap in gaps:
        key = (_value(gap, "gap_type"), _value(gap, "missing_source_type"), _value(gap, "description"))
        if key not in seen:
            seen.add(key); out.append(_as_payload(gap))
    return out


def build_analysis_case_from_alert(alert: Alert) -> AnalysisCaseCreate:
    facts = extract_facts_from_alert(alert)
    gaps = _evidence_gaps([alert], facts)
    decision = infer_initial_case_decision(None, facts, gaps, [alert])
    summary = f"Rule-based initial analysis for alert {alert.id}: {decision['verdict']} based on {len(facts)} facts and {len(gaps)} evidence gaps."
    return AnalysisCaseCreate(title=f"Analysis case from alert: {alert.title}", description=alert.description or "", primary_asset_id=alert.asset_id, related_asset_ids=[alert.asset_id] if alert.asset_id else [], related_alert_ids=[alert.id], facts=facts, evidence_items=_evidence_items([alert]), evidence_gaps=gaps, hypotheses=_hypotheses(facts, gaps, [alert]), timeline=[{"timestamp": alert.occurred_at, "title": "Alert observed", "description": alert.title, "source_ref": _source_ref(alert)}], summary=summary, recommendations=["Review evidence gaps before final confirmation.", "Do not auto-escalate or auto-remediate from rule-based initial analysis."], **decision)


def run_initial_analysis(case: AnalysisCase, related_alerts: list[Alert] | None = None) -> AnalysisCaseUpdate:
    alerts = related_alerts or []
    new_facts: list[Any] = list(case.facts)
    for alert in alerts:
        new_facts.extend(extract_facts_from_alert(alert))
    facts = _dedup_facts(new_facts)
    items = _dedup_items([*case.evidence_items, *_evidence_items(alerts)])
    gaps = _dedup_gaps([*case.evidence_gaps, *_evidence_gaps(alerts, facts)])
    decision = infer_initial_case_decision(case, facts, gaps, alerts)
    alert_ids = list(dict.fromkeys([*case.related_alert_ids, *[a.id for a in alerts]]))
    asset_ids = list(dict.fromkeys([*case.related_asset_ids, *[a.asset_id for a in alerts if a.asset_id]]))
    return AnalysisCaseUpdate(facts=facts, evidence_items=items, evidence_gaps=gaps, hypotheses=_hypotheses(facts, gaps, alerts), timeline=_dedup_items([*case.timeline, *[{"timestamp": a.occurred_at, "title": "Alert observed", "description": a.title, "source_ref": _source_ref(a)} for a in alerts]]), summary=f"Rule-based initial analysis refreshed: {decision['verdict']} based on {len(facts)} facts and {len(gaps)} evidence gaps.", recommendations=["Review evidence gaps before final confirmation.", "Do not auto-escalate or auto-remediate from rule-based initial analysis."], primary_asset_id=case.primary_asset_id or (asset_ids[0] if asset_ids else None), related_asset_ids=asset_ids, related_alert_ids=alert_ids, related_incident_id=case.related_incident_id, **decision)
