"""Asset risk profile builder for the Security Extension."""

from __future__ import annotations

from flocks.security.models import AssetRiskProfile
from flocks.security.schemas import SecurityListFilters
from flocks.security.scoring import calculate_asset_risk
from flocks.security.store import SecurityStore, default_store


async def build_asset_risk_profile(
    asset_id: str,
    store: SecurityStore | None = None,
) -> AssetRiskProfile:
    store = store or default_store
    asset = await store.get_asset(asset_id)
    if asset is None:
        raise ValueError(f"Asset not found: {asset_id}")

    vulnerabilities = await store.list_vulnerabilities(SecurityListFilters(asset_id=asset.id, limit=500))
    alerts = await store.list_alerts(SecurityListFilters(asset_id=asset.id, limit=500))
    incidents = await store.list_incidents(SecurityListFilters(asset_id=asset.id, limit=500))

    honeypot_events = []
    if asset.ip:
        honeypot_events = await store.list_honeypot_events(SecurityListFilters(ip=asset.ip, limit=500))

    risk_score = calculate_asset_risk(asset, vulnerabilities, alerts, honeypot_events)

    high_vulns = [item for item in vulnerabilities if str(item.severity) in {"high", "critical"}]
    high_alerts = [item for item in alerts if str(item.severity) in {"high", "critical"}]
    open_incidents = [item for item in incidents if str(item.status) in {"open", "investigating", "confirmed"}]

    confirmed_facts = [
        f"资产 {asset.name} 当前记录为 {asset.importance} 重要性、{asset.exposure_level} 暴露面、{asset.environment} 环境。",
        f"关联漏洞 {len(vulnerabilities)} 个，其中 high/critical {len(high_vulns)} 个。",
        f"关联告警 {len(alerts)} 条，其中 high/critical {len(high_alerts)} 条。",
        f"关联事件 {len(incidents)} 个，未关闭事件 {len(open_incidents)} 个。",
        f"关联诱捕事件 {len(honeypot_events)} 条。",
    ]
    if asset.open_ports:
        confirmed_facts.append(f"记录开放端口：{', '.join(str(port) for port in asset.open_ports[:20])}。")
    if asset.services:
        confirmed_facts.append(f"记录服务：{', '.join(asset.services[:20])}。")
    if asset.security_controls:
        enabled = [name for name, enabled in asset.security_controls.items() if enabled]
        missing = [name for name, enabled in asset.security_controls.items() if not enabled]
        if enabled:
            confirmed_facts.append(f"已记录接入防护：{', '.join(enabled)}。")
        if missing:
            confirmed_facts.append(f"未确认或未接入防护：{', '.join(missing)}。")

    evidence = []
    evidence.extend(f"漏洞证据：{item.cve_id or item.id} / {item.title} / {item.severity}" for item in high_vulns[:10])
    evidence.extend(f"告警证据：{item.source} / {item.title} / {item.severity}" for item in high_alerts[:10])
    evidence.extend(
        f"诱捕证据：{item.source_ip or 'unknown'} -> {item.target_ip or 'unknown'} / {item.event_type or item.threat_label or item.id}"
        for item in honeypot_events[:10]
    )
    if not evidence:
        evidence.append("当前未发现 high/critical 漏洞、告警或诱捕证据。")

    inferences = [
        f"综合风险评分为 {risk_score.score}（{risk_score.level}）。",
    ]
    if asset.exposure_level == "external" and high_vulns:
        inferences.append("公网资产叠加高危漏洞，优先级应高于普通内网资产修复。")
    if high_alerts and high_vulns:
        inferences.append("同一资产同时存在高危漏洞和高危告警，需要核查是否存在利用尝试。")
    if honeypot_events and alerts:
        inferences.append("诱捕信号与告警共现，建议进行同源 IP、时间线和载荷交叉验证。")

    uncertainties = []
    if not asset.open_ports and not asset.services:
        uncertainties.append("缺少开放端口和服务清单，暴露面判断可能不完整。")
    if not asset.security_controls:
        uncertainties.append("缺少 EDR/WAF/NDR/日志等防护接入信息。")
    if not alerts:
        uncertainties.append("缺少近期告警上下文，无法判断是否有攻击活跃度。")
    if not vulnerabilities:
        uncertainties.append("缺少漏洞扫描或漏洞管理数据，不代表资产无漏洞。")
    if not uncertainties:
        uncertainties.append("仍需结合最新终端、应用和网络日志确认是否存在成功入侵。")

    recommended_actions = list(dict.fromkeys([
        *risk_score.recommendations,
        "补充或核对资产开放端口、服务、业务负责人和防护接入状态。",
        "按风险评分优先处理 high/critical 漏洞和高危告警共现资产。",
    ]))

    normalized_data = {
        "asset_id": asset.id,
        "asset_name": asset.name,
        "asset_type": asset.asset_type,
        "ip": asset.ip,
        "hostname": asset.hostname,
        "domain": asset.domain,
        "business_system": asset.business_system,
        "business_owner": asset.business_owner,
        "importance": asset.importance,
        "exposure_level": asset.exposure_level,
        "environment": asset.environment,
        "open_ports": asset.open_ports,
        "services": asset.services,
        "protocols": asset.protocols,
        "security_controls": asset.security_controls,
        "risk_score": risk_score.model_dump(mode="json"),
        "counts": {
            "vulnerabilities": len(vulnerabilities),
            "high_vulnerabilities": len(high_vulns),
            "alerts": len(alerts),
            "high_alerts": len(high_alerts),
            "incidents": len(incidents),
            "open_incidents": len(open_incidents),
            "honeypot_events": len(honeypot_events),
        },
    }

    return AssetRiskProfile(
        asset=asset,
        vulnerabilities=vulnerabilities,
        alerts=alerts,
        incidents=incidents,
        honeypot_events=honeypot_events,
        risk_score=risk_score,
        confirmed_facts=confirmed_facts,
        evidence=evidence,
        inferences=inferences,
        uncertainties=uncertainties,
        recommended_actions=recommended_actions,
        normalized_data=normalized_data,
    )
