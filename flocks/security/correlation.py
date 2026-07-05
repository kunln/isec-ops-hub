"""Alert-to-asset/vulnerability/honeypot correlation."""

from __future__ import annotations

from flocks.security.models import Alert, AlertCorrelation, Confidence, HoneypotEvent
from flocks.security.scoring import calculate_asset_risk
from flocks.security.schemas import SecurityListFilters
from flocks.security.store import SecurityStore, default_store


def _dedupe_alerts(alerts: list[Alert], exclude_id: str) -> list[Alert]:
    seen: set[str] = set()
    result: list[Alert] = []
    for alert in alerts:
        if alert.id == exclude_id or alert.id in seen:
            continue
        seen.add(alert.id)
        result.append(alert)
    return result


def _ioc_overlap(left: list[str], right: list[str]) -> bool:
    return bool({value.lower() for value in left} & {value.lower() for value in right})


def _match_honeypot_events(alert: Alert, events: list[HoneypotEvent], asset_ip: str | None) -> list[HoneypotEvent]:
    iocs = {value.lower() for value in alert.ioc}
    matched: list[HoneypotEvent] = []
    for event in events:
        values = {
            str(event.source_ip or "").lower(),
            str(event.target_ip or "").lower(),
        }
        if asset_ip and event.target_ip == asset_ip:
            matched.append(event)
        elif iocs and values & iocs:
            matched.append(event)
    return matched


def _confidence(vuln_count: int, alert_count: int, honeypot_count: int) -> Confidence:
    evidence_groups = sum(1 for count in (vuln_count, alert_count, honeypot_count) if count > 0)
    if evidence_groups >= 2:
        return Confidence.HIGH
    if evidence_groups == 1:
        return Confidence.MEDIUM
    return Confidence.LOW


async def correlate_alert(alert_id: str, store: SecurityStore | None = None) -> AlertCorrelation:
    store = store or default_store
    alert = await store.get_alert(alert_id)
    if alert is None:
        raise ValueError(f"Alert not found: {alert_id}")

    asset = await store.get_asset(alert.asset_id) if alert.asset_id else None
    vulnerabilities = (
        await store.list_vulnerabilities(SecurityListFilters(asset_id=asset.id, limit=500))
        if asset
        else []
    )

    related: list[Alert] = []
    if alert.asset_id:
        related.extend(await store.list_alerts(SecurityListFilters(asset_id=alert.asset_id, limit=500)))

    all_alerts = await store.list_alerts(SecurityListFilters(limit=500))
    for candidate in all_alerts:
        if alert.ioc and _ioc_overlap(alert.ioc, candidate.ioc):
            related.append(candidate)
        if alert.mitre_technique and candidate.mitre_technique == alert.mitre_technique:
            related.append(candidate)

    related_alerts = _dedupe_alerts(related, alert.id)[:50]
    all_honeypot = await store.list_honeypot_events(SecurityListFilters(limit=500))
    honeypot_events = _match_honeypot_events(alert, all_honeypot, asset.ip if asset else None)[:50]

    scoring_alerts = [alert, *related_alerts]
    risk_score = calculate_asset_risk(asset, vulnerabilities, scoring_alerts, honeypot_events)
    confidence = _confidence(len(vulnerabilities), len(related_alerts), len(honeypot_events))

    context_parts = [
        f"告警 {alert.id} 关联到资产 {asset.name if asset else '未知资产'}。",
        f"发现 {len(vulnerabilities)} 个资产漏洞、{len(related_alerts)} 条相关告警、{len(honeypot_events)} 条诱捕事件。",
        f"当前风险评分为 {risk_score.score}（{risk_score.level}）。",
    ]

    recommended_actions = list(risk_score.recommendations)
    if alert.ioc:
        recommended_actions.append("围绕 IOC 检索近 7 天日志，确认是否存在横向移动、回连或重复探测。")
    if alert.mitre_technique:
        recommended_actions.append(f"按 MITRE {alert.mitre_technique} 对应技术检查主机、进程和网络行为证据。")
    if honeypot_events:
        recommended_actions.append("将诱捕源 IP 与边界设备、WAF、NDR 告警进行时间线比对。")

    return AlertCorrelation(
        alert=alert,
        asset=asset,
        vulnerabilities=vulnerabilities,
        related_alerts=related_alerts,
        honeypot_events=honeypot_events,
        risk_score=risk_score,
        triage_summary=" ".join(context_parts),
        recommended_actions=recommended_actions,
        confidence=confidence,
    )
