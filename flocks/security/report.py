"""Markdown incident report generation."""

from __future__ import annotations

from flocks.security.models import AnalysisCase
from flocks.security.schemas import SecurityListFilters
from flocks.security.store import SecurityStore, default_store


def _line_items(items: list[str], empty: str = "暂无") -> str:
    if not items:
        return f"- {empty}"
    return "\n".join(f"- {item}" for item in items)


async def find_analysis_case_for_incident(incident_id: str, store: SecurityStore | None = None) -> AnalysisCase | None:
    store = store or default_store
    incident = await store.get_incident(incident_id)
    if incident is None:
        return None
    for source in (incident.raw_data, incident.normalized_data):
        case_id = source.get("analysis_case_id") if isinstance(source, dict) else None
        if case_id:
            case = await store.get_analysis_case(str(case_id))
            if case is not None:
                return case
    for case in await store.list_analysis_cases(SecurityListFilters(limit=500)):
        if case.related_incident_id == incident_id:
            return case
    return None


def _analysis_case_evidence_section(case: AnalysisCase | None) -> list[str]:
    if case is None:
        return []
    facts = [f"- {fact.fact_type}: {fact.statement} (source: {fact.source_ref})" for fact in case.facts[:5]]
    gaps = [f"- {gap.gap_type}: {gap.description}" for gap in case.evidence_gaps[:5]]
    confirmations = [f"- {record.confirmation_type}: {record.decision} by {record.reviewer or 'unknown'} - {record.comment}" for record in case.confirmation_records[:5]]
    recommendations = [f"- {item}" for item in case.recommendations]
    return [
        "",
        "## Analysis Case Evidence",
        "",
        f"- Analysis Case: {case.title} ({case.id})",
        f"- verdict: {case.verdict}",
        f"- confidence: {case.confidence}",
        f"- evidence_coverage: {case.evidence_coverage}",
        "",
        "Top facts:",
        "",
        * (facts or ["- 暂无事实。"]),
        "",
        "Evidence gaps:",
        "",
        * (gaps or ["- 暂无证据缺口。"]),
        "",
        "Confirmation records:",
        "",
        * (confirmations or ["- 暂无人工确认记录。"]),
        "",
        "Recommendations:",
        "",
        * (recommendations or ["- 暂无建议。"]),
    ]


async def generate_incident_report(
    incident_id: str,
    store: SecurityStore | None = None,
) -> str:
    store = store or default_store
    incident = await store.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    assets = [
        asset
        for asset_id in incident.asset_ids
        if (asset := await store.get_asset(asset_id)) is not None
    ]
    vulnerabilities = [
        vuln
        for vuln_id in incident.vulnerability_ids
        if (vuln := await store.get_vulnerability(vuln_id)) is not None
    ]
    alerts = [
        alert
        for alert_id in incident.alert_ids
        if (alert := await store.get_alert(alert_id)) is not None
    ]

    analysis_case = await find_analysis_case_for_incident(incident_id, store)

    honeypot_events = []
    for event_id in incident.honeypot_event_ids:
        event = await store.get_honeypot_event(event_id)
        if event is not None:
            honeypot_events.append(event)
    for asset in assets:
        if asset.ip:
            honeypot_events.extend(
                await store.list_honeypot_events(SecurityListFilters(ip=asset.ip, limit=100))
            )
    honeypot_events = list({event.id: event for event in honeypot_events}.values())

    asset_lines = [
        (
            f"{asset.name}（{asset.ip or asset.hostname or asset.domain or asset.id}）："
            f"重要性 {asset.importance}，暴露级别 {asset.exposure_level}，环境 {asset.environment}"
        )
        for asset in assets
    ]
    vuln_lines = [
        (
            f"{vuln.cve_id or vuln.id} / {vuln.title}：{vuln.severity}，"
            f"KEV={vuln.kev}，exploit_available={vuln.exploit_available}，状态 {vuln.status}"
        )
        for vuln in vulnerabilities
    ]
    alert_lines = [
        (
            f"{alert.source} / {alert.title}：{alert.severity}，状态 {alert.status}，"
            f"MITRE={alert.mitre_technique or 'N/A'}，IOC={', '.join(alert.ioc) if alert.ioc else 'N/A'}"
        )
        for alert in alerts
    ]
    honeypot_lines = [
        (
            f"{event.source_ip or 'unknown'} -> {event.target_ip or 'unknown'} "
            f"{event.protocol or ''}/{event.service or ''}：{event.event_type or event.threat_label or event.id}"
        )
        for event in honeypot_events
    ]
    evidence_lines = incident.evidence or [
        f"{alert.source} / {alert.title} / {alert.severity}" for alert in alerts
    ]
    timeline_lines = [
        f"{item.get('timestamp') or 'unknown'}：{item.get('description') or item.get('event') or item}"
        for item in incident.timeline
    ]

    evidence_notice = (
        "当前报告区分已观测证据和分析推断。若未提供终端取证、应用日志或完整网络流量，"
        "结论不应被解读为已确认入侵成功。"
    )

    return "\n".join([
        "# 安全事件研判报告",
        "",
        "## 一、事件概览",
        "",
        f"- 事件标题：{incident.title}",
        f"- 事件等级：{incident.severity}",
        f"- 事件状态：{incident.status}",
        f"- 置信度：{incident.confidence}",
        f"- 创建来源：{incident.created_by}",
        f"- 创建时间：{incident.created_at}",
        "",
        incident.summary or "暂无摘要。",
        "",
        "## 二、影响资产",
        "",
        _line_items(asset_lines, "未关联资产，需要补充资产归属和暴露面信息。"),
        "",
        "## 三、关联漏洞与风险",
        "",
        _line_items(vuln_lines, "未关联漏洞；不代表资产不存在漏洞，仅表示当前事件缺少漏洞证据。"),
        "",
        "## 四、告警与证据",
        "",
        _line_items(alert_lines, "未关联告警。"),
        "",
        "证据摘录：",
        "",
        _line_items(evidence_lines, "暂无结构化证据摘录。"),
        "",
        "诱捕信号：",
        "",
        _line_items(honeypot_lines, "未发现关联诱捕事件。"),
        "",
        "事件时间线：",
        "",
        _line_items(timeline_lines, "暂无结构化时间线。"),
        "",
        "## 五、攻击研判",
        "",
        incident.analysis or "当前证据不足以确认攻击链路，需要继续核查。",
        "",
        "证据边界：",
        "",
        f"- {evidence_notice}",
        "- 如仅有探测、告警或诱捕命中，而缺少响应内容、落地文件、进程执行或外联证据，应表述为疑似攻击或利用尝试。",
        "",
        "## 六、风险等级与置信度",
        "",
        f"- 风险等级：{incident.severity}",
        f"- 置信度：{incident.confidence}",
        "- 风险等级反映当前处置优先级，置信度反映证据充分程度。",
        "",
        "## 七、处置建议",
        "",
        incident.recommendation or "建议补充日志、核查资产暴露面、验证漏洞状态，并持续监控相关 IOC。",
        "",
        "## 八、后续跟踪事项",
        "",
        "- 核查受影响资产近 7 天 Web、主机、EDR/XDR、NDR/WAF 日志。",
        "- 验证关联漏洞是否真实可达、是否已修复或缓解。",
        "- 对 IOC、源 IP、MITRE 技术编号建立临时监控规则。",
        "- 形成复盘记录，更新资产风险画像和处置知识库。",
        *_analysis_case_evidence_section(analysis_case),
    ])
