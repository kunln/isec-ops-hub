from flocks.security.models import Alert, Asset, HoneypotEvent, Vulnerability
from flocks.security.scoring import calculate_asset_risk, calculate_vulnerability_priority


def test_calculate_asset_risk_weights_exposure_vulns_alerts_and_honeypot():
    asset = Asset(
        id="ast_1",
        name="Portal",
        importance="critical",
        exposure_level="external",
        environment="production",
    )
    vuln = Vulnerability(
        id="vul_1",
        asset_id=asset.id,
        title="Critical demo vuln",
        severity="critical",
        epss_score=0.85,
        kev=True,
        exploit_available=True,
    )
    alert = Alert(
        id="alr_1",
        asset_id=asset.id,
        title="Suspicious command execution",
        severity="high",
    )
    honeypot = HoneypotEvent(id="hpt_1", source_ip="198.51.100.23", target_ip="203.0.113.10")

    result = calculate_asset_risk(asset, [vuln], [alert], [honeypot])

    assert result.score >= 80
    assert result.level == "critical"
    assert any("公网" in reason for reason in result.reasons)
    assert result.recommendations


def test_calculate_vulnerability_priority_uses_asset_and_activity_context():
    asset = Asset(
        id="ast_1",
        name="Portal",
        importance="critical",
        exposure_level="external",
        environment="production",
    )
    vuln = Vulnerability(
        id="vul_1",
        asset_id=asset.id,
        title="Remote execution",
        severity="critical",
        cvss_score=9.8,
        epss_score=0.9,
        kev=True,
        exploit_available=True,
    )
    alert = Alert(
        id="alr_1",
        asset_id=asset.id,
        title="Exploit attempt",
        severity="high",
    )
    honeypot = HoneypotEvent(id="hpt_1", source_ip="198.51.100.23", target_ip="203.0.113.10")

    result = calculate_vulnerability_priority(vuln, asset, [alert], [honeypot])

    assert result.score >= 80
    assert result.level == "critical"
    assert any("KEV" in reason for reason in result.reasons)
    assert any("公网" in reason for reason in result.reasons)
