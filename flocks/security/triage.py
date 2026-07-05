"""Security alert triage and incident escalation logic."""

from __future__ import annotations

from flocks.security.correlation import correlate_alert
from flocks.security.models import AlertTriageResult, Confidence, IncidentSeverity
from flocks.security.schemas import AlertUpdate, IncidentCreate, SecurityListFilters
from flocks.security.store import SecurityStore, default_store


def _value(value: object) -> str:
    return getattr(value, "value", value)  # type: ignore[return-value]


def _incident_severity(risk_level: str, alert_severity: str) -> IncidentSeverity:
    if risk_level == "critical" or alert_severity == "critical":
        return IncidentSeverity.CRITICAL
    if risk_level == "high" or alert_severity == "high":
        return IncidentSeverity.HIGH
    if risk_level == "medium" or alert_severity == "medium":
        return IncidentSeverity.MEDIUM
    return IncidentSeverity.LOW


def _should_escalate(
    severity: IncidentSeverity,
    has_critical_asset: bool,
    has_external_asset: bool,
    high_vuln_count: int,
    honeypot_count: int,
) -> bool:
    if severity in {IncidentSeverity.HIGH, IncidentSeverity.CRITICAL}:
        return True
    if has_critical_asset and (has_external_asset or high_vuln_count > 0 or honeypot_count > 0):
        return True
    return high_vuln_count > 0 and honeypot_count > 0


def _triage_confidence(base: Confidence, has_honeypot: bool, has_high_vuln: bool) -> Confidence:
    base_value = str(_value(base))
    if base_value == "high":
        return Confidence.HIGH
    if has_honeypot and has_high_vuln:
        return Confidence.HIGH
    if base_value == "medium" or has_honeypot or has_high_vuln:
        return Confidence.MEDIUM
    return Confidence.LOW


async def _find_existing_incident(alert_id: str, store: SecurityStore):
    incidents = await store.list_incidents(SecurityListFilters(limit=500))
    for incident in incidents:
        if alert_id in incident.alert_ids and incident.created_by == "security_triage":
            return incident
    return None


async def triage_alert(
    alert_id: str,
    create_incident: bool = True,
    store: SecurityStore | None = None,
) -> AlertTriageResult:
    store = store or default_store
    correlation = await correlate_alert(alert_id, store=store)
    alert = correlation.alert
    asset = correlation.asset

    risk_level = str(_value(correlation.risk_score.level))
    alert_severity = str(_value(alert.severity))
    severity = _incident_severity(risk_level, alert_severity)

    high_vulns = [
        vuln for vuln in correlation.vulnerabilities
        if str(_value(vuln.severity)) in {"high", "critical"}
    ]
    has_critical_asset = bool(asset and str(_value(asset.importance)) == "critical")
    has_external_asset = bool(asset and str(_value(asset.exposure_level)) == "external")
    has_honeypot = bool(correlation.honeypot_events)
    confidence = _triage_confidence(correlation.confidence, has_honeypot, bool(high_vulns))
    should_create = _should_escalate(
        severity,
        has_critical_asset,
        has_external_asset,
        len(high_vulns),
        len(correlation.honeypot_events),
    )

    evidence: list[str] = [
        f"告警严重级别：{alert.severity}",
        f"风险评分：{correlation.risk_score.score} / {correlation.risk_score.level}",
    ]
    if asset:
        evidence.append(
            f"关联资产：{asset.name}，重要性 {asset.importance}，暴露级别 {asset.exposure_level}。"
        )
    if high_vulns:
        evidence.append(f"关联 {len(high_vulns)} 个 high/critical 漏洞。")
    if alert.ioc:
        evidence.append(f"告警包含 IOC：{', '.join(alert.ioc[:5])}。")
    if alert.mitre_technique:
        evidence.append(f"MITRE Technique：{alert.mitre_technique}。")
    if correlation.honeypot_events:
        evidence.append(f"发现 {len(correlation.honeypot_events)} 条同源或同目标诱捕事件。")
    if not correlation.honeypot_events and not high_vulns and not correlation.related_alerts:
        evidence.append("当前缺少多源交叉证据，不足以确认已成功入侵。")

    summary = (
        f"{alert.title} 的研判结论：当前风险为 {severity.value}，"
        f"置信度 {confidence.value}，"
        f"{'建议升级为安全事件' if should_create else '建议继续观察并补充证据'}。"
    )

    analysis = "\n".join([
        correlation.triage_summary,
        "证据层面：" + " ".join(evidence),
        "结论说明：该结论基于现有资产、漏洞、告警和诱捕数据生成；若缺少终端日志或应用日志，不直接断定入侵成功。",
    ])

    linked_asset_ids = [asset.id] if asset else []
    linked_vulnerability_ids = [vuln.id for vuln in correlation.vulnerabilities]
    linked_alert_ids = [alert.id, *[item.id for item in correlation.related_alerts]]
    incident_id: str | None = None

    if create_incident and should_create:
        existing = await _find_existing_incident(alert_id, store)
        if existing:
            incident_id = existing.id
        else:
            incident = await store.create_incident(
                IncidentCreate(
                    title=f"疑似安全事件：{alert.title}",
                    severity=severity,
                    status="open",  # type: ignore[arg-type]
                    summary=summary,
                    analysis=analysis,
                    recommendation="\n".join(correlation.recommended_actions),
                    asset_ids=linked_asset_ids,
                    vulnerability_ids=linked_vulnerability_ids,
                    alert_ids=linked_alert_ids,
                    honeypot_event_ids=[item.id for item in correlation.honeypot_events],
                    evidence=evidence,
                    timeline=[
                        {
                            "timestamp": alert.occurred_at or alert.created_at,
                            "source": alert.source,
                            "description": alert.title,
                            "alert_id": alert.id,
                        }
                    ],
                    confidence=confidence,
                    created_by="security_triage",
                )
            )
            incident_id = incident.id
        await store.update_alert(alert.id, AlertUpdate(status="incident_created"))  # type: ignore[arg-type]

    return AlertTriageResult(
        alert_id=alert.id,
        should_create_incident=should_create,
        severity=severity,
        confidence=confidence,
        summary=summary,
        analysis=analysis,
        evidence=evidence,
        recommended_actions=correlation.recommended_actions,
        linked_asset_ids=linked_asset_ids,
        linked_vulnerability_ids=linked_vulnerability_ids,
        linked_alert_ids=linked_alert_ids,
        incident_id=incident_id,
    )
