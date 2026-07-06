"""Request schemas for the Security Extension API and store."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from flocks.security.models import (
    AlertSource,
    AlertStatus,
    AnalysisCaseStatus,
    AnalysisDisposition,
    AnalysisFact,
    AssetImportance,
    AssetType,
    Confidence,
    Environment,
    ExposureLevel,
    IncidentSeverity,
    IncidentStatus,
    SecuritySeverity,
    VulnerabilityStatus,
)


class SecurityListFilters(BaseModel):
    asset_id: str | None = None
    severity: str | None = None
    status: str | None = None
    source: str | None = None
    keyword: str | None = None
    ip: str | None = None
    domain: str | None = None
    hostname: str | None = None
    importance: str | None = None
    exposure_level: str | None = None
    cve_id: str | None = None
    ioc: str | None = None
    mitre_technique: str | None = None
    limit: int = Field(100, ge=1, le=500)


class AssetCreate(BaseModel):
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


class AssetUpdate(BaseModel):
    name: str | None = None
    asset_type: AssetType | None = None
    ip: str | None = None
    hostname: str | None = None
    domain: str | None = None
    business_system: str | None = None
    business_owner: str | None = None
    importance: AssetImportance | None = None
    exposure_level: ExposureLevel | None = None
    environment: Environment | None = None
    open_ports: list[int] | None = None
    services: list[str] | None = None
    protocols: list[str] | None = None
    security_controls: dict[str, bool] | None = None
    tags: list[str] | None = None
    description: str | None = None
    raw_data: dict[str, Any] | None = None
    normalized_data: dict[str, Any] | None = None


class VulnerabilityCreate(BaseModel):
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


class VulnerabilityUpdate(BaseModel):
    asset_id: str | None = None
    cve_id: str | None = None
    title: str | None = None
    severity: SecuritySeverity | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    kev: bool | None = None
    exploit_available: bool | None = None
    description: str | None = None
    affected_component: str | None = None
    remediation: str | None = None
    status: VulnerabilityStatus | None = None
    discovered_at: str | None = None
    raw_data: dict[str, Any] | None = None
    normalized_data: dict[str, Any] | None = None


class AlertCreate(BaseModel):
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


class AlertUpdate(BaseModel):
    asset_id: str | None = None
    source: AlertSource | None = None
    title: str | None = None
    severity: SecuritySeverity | None = None
    alert_type: str | None = None
    description: str | None = None
    raw_event: dict[str, Any] | None = None
    raw_data: dict[str, Any] | None = None
    ioc: list[str] | None = None
    mitre_technique: str | None = None
    status: AlertStatus | None = None
    occurred_at: str | None = None
    normalized_data: dict[str, Any] | None = None


class IncidentCreate(BaseModel):
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


class IncidentUpdate(BaseModel):
    title: str | None = None
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    summary: str | None = None
    analysis: str | None = None
    recommendation: str | None = None
    asset_ids: list[str] | None = None
    vulnerability_ids: list[str] | None = None
    alert_ids: list[str] | None = None
    honeypot_event_ids: list[str] | None = None
    evidence: list[str] | None = None
    timeline: list[dict[str, Any]] | None = None
    owner: str | None = None
    sla: str | None = None
    close_reason: str | None = None
    confidence: Confidence | None = None
    created_by: str | None = None
    raw_data: dict[str, Any] | None = None
    normalized_data: dict[str, Any] | None = None


class HoneypotEventCreate(BaseModel):
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


class HoneypotEventUpdate(BaseModel):
    sensor_id: str | None = None
    source_ip: str | None = None
    target_ip: str | None = None
    protocol: str | None = None
    service: str | None = None
    event_type: str | None = None
    payload: str | None = None
    geo: dict[str, Any] | None = None
    threat_label: str | None = None
    occurred_at: str | None = None
    raw_data: dict[str, Any] | None = None
    normalized_data: dict[str, Any] | None = None


class AnalysisCaseCreate(BaseModel):
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


class AnalysisCaseUpdate(BaseModel):
    title: str | None = None
    status: AnalysisCaseStatus | None = None
    disposition: AnalysisDisposition | None = None
    alert_ids: list[str] | None = None
    incident_ids: list[str] | None = None
    asset_ids: list[str] | None = None
    facts: list[AnalysisFact] | None = None
    summary: str | None = None
    owner: str | None = None
    raw_data: dict[str, Any] | None = None
    normalized_data: dict[str, Any] | None = None
