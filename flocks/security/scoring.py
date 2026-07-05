"""Deterministic lightweight risk scoring for security objects."""

from __future__ import annotations

from flocks.security.models import Alert, Asset, HoneypotEvent, RiskLevel, RiskScore, Vulnerability


IMPORTANCE_WEIGHT = {
    "low": 5,
    "medium": 10,
    "high": 18,
    "critical": 25,
}

VULNERABILITY_WEIGHT = {
    "info": 1,
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}

ALERT_WEIGHT = {
    "info": 1,
    "low": 3,
    "medium": 6,
    "high": 10,
    "critical": 15,
}


def risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 55:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def calculate_asset_risk(
    asset: Asset | None,
    vulnerabilities: list[Vulnerability] | None = None,
    alerts: list[Alert] | None = None,
    honeypot_events: list[HoneypotEvent] | None = None,
) -> RiskScore:
    """Calculate a capped 0-100 risk score with human-readable reasons."""
    vulnerabilities = vulnerabilities or []
    alerts = alerts or []
    honeypot_events = honeypot_events or []

    score = 0
    reasons: list[str] = []
    recommendations: list[str] = []

    if asset is not None:
        importance_weight = IMPORTANCE_WEIGHT.get(str(asset.importance), 10)
        score += importance_weight
        reasons.append(f"资产重要性为 {asset.importance}，基础风险加权 {importance_weight}。")
        if asset.exposure_level == "external":
            score += 15
            reasons.append("资产处于公网暴露面，攻击可达性较高。")
            recommendations.append("优先核查公网入口、访问控制、WAF/网关策略和暴露端口。")
        if asset.environment == "production":
            score += 5
            reasons.append("资产属于生产环境，业务影响面更高。")

    high_risk_vulns = []
    for vuln in vulnerabilities:
        vuln_weight = VULNERABILITY_WEIGHT.get(str(vuln.severity), 5)
        score += vuln_weight
        if vuln.severity in {"high", "critical"}:
            high_risk_vulns.append(vuln)
            reasons.append(f"存在 {vuln.severity} 漏洞：{vuln.title}。")
        if vuln.kev:
            score += 10
            reasons.append(f"漏洞 {vuln.cve_id or vuln.id} 命中 KEV 或等价高优先级目录。")
        if vuln.exploit_available:
            score += 8
            reasons.append(f"漏洞 {vuln.cve_id or vuln.id} 存在可用利用条件或利用代码。")
        if vuln.epss_score is not None:
            epss_weight = max(0, min(10, round(float(vuln.epss_score) * 10)))
            score += epss_weight
            if epss_weight >= 7:
                reasons.append(f"漏洞 {vuln.cve_id or vuln.id} EPSS 较高：{vuln.epss_score}。")

    if high_risk_vulns:
        recommendations.append("优先验证高危/严重漏洞暴露范围，并制定修复或缓解窗口。")

    high_risk_alerts = []
    for alert in alerts:
        alert_weight = ALERT_WEIGHT.get(str(alert.severity), 3)
        score += alert_weight
        if alert.severity in {"high", "critical"}:
            high_risk_alerts.append(alert)
            reasons.append(f"存在 {alert.severity} 告警：{alert.title}。")
    if high_risk_alerts:
        recommendations.append("对高危告警进行主机、网络、应用日志交叉验证，确认是否存在成功利用迹象。")

    if honeypot_events:
        honeypot_weight = min(len(honeypot_events) * 5, 15)
        score += honeypot_weight
        reasons.append(f"发现 {len(honeypot_events)} 条关联诱捕信号，风险提升 {honeypot_weight}。")
        recommendations.append("结合诱捕源 IP、目标资产和载荷特征，排查是否为同一攻击活动。")

    if not recommendations:
        recommendations.append("保持监控，补充资产暴露面、漏洞和告警数据后重新评估。")
    if not reasons:
        reasons.append("当前证据较少，评分基于有限上下文生成。")

    capped = max(0, min(100, int(score)))
    return RiskScore(
        score=capped,
        level=risk_level(capped),
        reasons=reasons,
        recommendations=recommendations,
    )


def calculate_vulnerability_priority(
    vulnerability: Vulnerability,
    asset: Asset | None = None,
    alerts: list[Alert] | None = None,
    honeypot_events: list[HoneypotEvent] | None = None,
) -> RiskScore:
    """Prioritize a vulnerability using technical severity plus asset and activity context."""
    alerts = alerts or []
    honeypot_events = honeypot_events or []

    severity = str(vulnerability.severity)
    status = str(vulnerability.status)
    score = VULNERABILITY_WEIGHT.get(severity, 5) * 2
    reasons = [f"漏洞严重等级为 {severity}。"]
    recommendations: list[str] = []

    if vulnerability.cvss_score is not None:
        cvss_weight = max(0, min(25, round(float(vulnerability.cvss_score) * 2.5)))
        score += cvss_weight
        if vulnerability.cvss_score >= 9:
            reasons.append(f"CVSS {vulnerability.cvss_score} 属于严重风险区间。")
    if vulnerability.epss_score is not None:
        epss_weight = max(0, min(20, round(float(vulnerability.epss_score) * 20)))
        score += epss_weight
        if vulnerability.epss_score >= 0.7:
            reasons.append(f"EPSS {vulnerability.epss_score} 较高，优先级上调。")
    if vulnerability.kev:
        score += 15
        reasons.append(f"{vulnerability.cve_id or vulnerability.id} 命中 KEV 或等价已利用信号。")
    if vulnerability.exploit_available:
        score += 12
        reasons.append("存在公开 Exploit、PoC 或等价可利用条件。")

    if asset is not None:
        importance_weight = IMPORTANCE_WEIGHT.get(str(asset.importance), 10)
        score += importance_weight
        reasons.append(f"关联资产重要性为 {asset.importance}。")
        if asset.exposure_level == "external":
            score += 15
            reasons.append("关联资产公网暴露，攻击可达性高。")
        if asset.environment == "production":
            score += 5
            reasons.append("关联资产处于生产环境。")

    high_alerts = [alert for alert in alerts if str(alert.severity) in {"high", "critical"}]
    if high_alerts:
        alert_weight = min(20, len(high_alerts) * 10)
        score += alert_weight
        reasons.append(f"关联 {len(high_alerts)} 条 high/critical 告警。")
    if honeypot_events:
        honeypot_weight = min(15, len(honeypot_events) * 5)
        score += honeypot_weight
        reasons.append(f"发现 {len(honeypot_events)} 条关联诱捕探测或攻击信号。")

    if status in {"fixed", "mitigated"}:
        score -= 35
        reasons.append(f"漏洞状态为 {status}，处置优先级下调，但仍需验证闭环。")
    elif status == "accepted":
        score -= 20
        reasons.append("漏洞已接受风险，建议定期复核接受依据。")
    elif status == "false_positive":
        score -= 60
        reasons.append("漏洞标记为误报，除非有新证据否则不建议进入修复队列。")

    if severity in {"critical", "high"} or vulnerability.kev or vulnerability.exploit_available:
        recommendations.append("优先验证漏洞是否真实存在且可从当前暴露面触达。")
    if asset and asset.exposure_level == "external":
        recommendations.append("对公网入口实施补丁、配置加固或临时访问控制/WAF 虚拟补丁。")
    if high_alerts:
        recommendations.append("核查关联告警时间线，判断是否存在利用尝试或成功利用迹象。")
    if honeypot_events:
        recommendations.append("将诱捕源 IP、载荷和漏洞组件进行交叉比对。")
    if not recommendations:
        recommendations.append("补充资产暴露面、修复状态和告警上下文后重新排序。")

    capped = max(0, min(100, int(score)))
    return RiskScore(
        score=capped,
        level=risk_level(capped),
        reasons=reasons,
        recommendations=recommendations,
    )
