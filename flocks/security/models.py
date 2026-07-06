"""Security Extension domain models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _SecurityBaseModel(BaseModel):
    model_config = ConfigDict(use_enum_values=True)


class AssetImportance(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExposureLevel(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class AssetType(str, Enum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    NETWORK_DEVICE = "network_device"
    SECURITY_DEVICE = "security_device"
    WEB_APP = "web_app"
    API = "api"
    DATABASE = "database"
    CLOUD_RESOURCE = "cloud_resource"
    OTHER = "other"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    TESTING = "testing"
    DEVELOPMENT = "development"
    UNKNOWN = "unknown"


class SecuritySeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    MITIGATED = "mitigated"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class AlertSource(str, Enum):
    XDR = "xdr"
    EDR = "edr"
    NDR = "ndr"
    WAF = "waf"
    SIEM = "siem"
    HONEYPOT = "honeypot"
    SCANNER = "scanner"
    MANUAL = "manual"
    OTHER = "other"


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCIDENT_CREATED = "incident_created"
    CLOSED = "closed"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Asset(_SecurityBaseModel):
    id: str = ""
    name: str
    asset_type: AssetType = AssetType.OTHER
    ip: str | None = None
    hostname: str | None = None
    domain: str | None = None
    business_system: str | None = None
    business_owner: str | None = None
    importance: AssetImportance = AssetImportance.MEDIUM
    exposure_level: ExposureLevel = ExposureLevel.UNKNOWN
    environment: Environment = Environment.UNKNOWN
    open_ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    security_controls: dict[str, bool] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    description: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class Vulnerability(_SecurityBaseModel):
    id: str = ""
    asset_id: str
    cve_id: str | None = None
    title: str
    severity: SecuritySeverity = SecuritySeverity.MEDIUM
    cvss_score: float | None = None
    epss_score: float | None = None
    kev: bool = False
    exploit_available: bool = False
    description: str | None = None
    affected_component: str | None = None
    remediation: str | None = None
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    discovered_at: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class Alert(_SecurityBaseModel):
    id: str = ""
    asset_id: str | None = None
    source: AlertSource = AlertSource.OTHER
    title: str
    severity: SecuritySeverity = SecuritySeverity.MEDIUM
    alert_type: str | None = None
    description: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    ioc: list[str] = Field(default_factory=list)
    mitre_technique: str | None = None
    status: AlertStatus = AlertStatus.NEW
    occurred_at: str | None = None
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class Incident(_SecurityBaseModel):
    id: str = ""
    title: str
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    summary: str = ""
    analysis: str = ""
    recommendation: str = ""
    asset_ids: list[str] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    honeypot_event_ids: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    owner: str | None = None
    sla: str | None = None
    close_reason: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    created_by: str = "security_extension"
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class HoneypotEvent(_SecurityBaseModel):
    id: str = ""
    sensor_id: str | None = None
    source_ip: str | None = None
    target_ip: str | None = None
    protocol: str | None = None
    service: str | None = None
    event_type: str | None = None
    payload: str | None = None
    geo: dict[str, Any] = Field(default_factory=dict)
    threat_label: str | None = None
    occurred_at: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class FactStrength(str, Enum):
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    CRITICAL = "critical"


class AnalysisCaseStatus(str, Enum):
    NEW = "new"
    COLLECTING_EVIDENCE = "collecting_evidence"
    ANALYZING = "analyzing"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    MERGED = "merged"
    REOPENED = "reopened"


class AnalysisDisposition(str, Enum):
    OPEN = "open"
    CLOSED_BLOCKED_ATTEMPT = "closed_blocked_attempt"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"
    CLOSED_BENIGN = "closed_benign"
    CLOSED_INSUFFICIENT_EVIDENCE = "closed_insufficient_evidence"
    CLOSED_DUPLICATE = "closed_duplicate"
    MERGED_INTO_CASE = "merged_into_case"
    MERGED_INTO_INCIDENT = "merged_into_incident"
    ESCALATED_TO_INCIDENT = "escalated_to_incident"
    MONITORING = "monitoring"


class AnalysisFact(_SecurityBaseModel):
    id: str = ""
    fact_type: str
    statement: str
    strength: FactStrength = FactStrength.MEDIUM
    source_references: list[dict[str, Any]] = Field(default_factory=list)
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class AnalysisCase(_SecurityBaseModel):
    id: str = ""
    title: str
    status: AnalysisCaseStatus = AnalysisCaseStatus.NEW
    disposition: AnalysisDisposition = AnalysisDisposition.OPEN
    alert_ids: list[str] = Field(default_factory=list)
    incident_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    facts: list[AnalysisFact] = Field(default_factory=list)
    summary: str = ""
    owner: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class RiskScore(_SecurityBaseModel):
    score: int
    level: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AlertCorrelation(_SecurityBaseModel):
    alert: Alert
    asset: Asset | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    related_alerts: list[Alert] = Field(default_factory=list)
    honeypot_events: list[HoneypotEvent] = Field(default_factory=list)
    risk_score: RiskScore
    triage_summary: str
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM


class AlertTriageResult(_SecurityBaseModel):
    alert_id: str
    should_create_incident: bool
    severity: IncidentSeverity
    confidence: Confidence
    summary: str
    analysis: str
    evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    linked_asset_ids: list[str] = Field(default_factory=list)
    linked_vulnerability_ids: list[str] = Field(default_factory=list)
    linked_alert_ids: list[str] = Field(default_factory=list)
    incident_id: str | None = None


class AssetRiskProfile(_SecurityBaseModel):
    asset: Asset
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
    honeypot_events: list[HoneypotEvent] = Field(default_factory=list)
    risk_score: RiskScore
    confirmed_facts: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    normalized_data: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityPriority(_SecurityBaseModel):
    vulnerability: Vulnerability
    asset: Asset | None = None
    related_alerts: list[Alert] = Field(default_factory=list)
    honeypot_events: list[HoneypotEvent] = Field(default_factory=list)
    risk_score: RiskScore
    priority: RiskLevel
    factors: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
