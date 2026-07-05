"""Models for standardized Security Extension connectors."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _ConnectorBaseModel(BaseModel):
    model_config = ConfigDict(use_enum_values=True)


class ConnectorRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConnectorCapability(str, Enum):
    ASSET_SEARCH = "asset.search"
    ASSET_GET = "asset.get"
    ASSET_SYNC = "asset.sync"
    VULNERABILITY_SEARCH = "vulnerability.search"
    VULNERABILITY_GET = "vulnerability.get"
    VULNERABILITY_SYNC = "vulnerability.sync"
    ALERT_SEARCH = "alert.search"
    ALERT_GET = "alert.get"
    ALERT_TRIAGE_CONTEXT = "alert.triage_context"
    EVENT_SEARCH = "event.search"
    EVENT_TIMELINE = "event.timeline"
    ENDPOINT_QUERY = "endpoint.query"
    ENDPOINT_PROCESS_TREE = "endpoint.process_tree"
    TRAFFIC_QUERY = "traffic.query"
    FLOW_QUERY = "flow.query"
    THREAT_INTEL_LOOKUP = "threat_intel.lookup"
    HONEYPOT_EVENT_SEARCH = "honeypot.event.search"
    CASE_CREATE = "case.create"
    CASE_UPDATE = "case.update"
    NOTIFICATION_SEND = "notification.send"
    REPORT_GENERATE = "report.generate"


class ConnectorHealthCheckResult(_ConnectorBaseModel):
    status: str
    message: str
    checked_at: str
    latency_ms: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ConnectorManifest(_ConnectorBaseModel):
    id: str
    name: str
    vendor: str
    product: str
    product_version: str | None = None
    deployment: str = "unknown"
    auth_methods: list[str] = Field(default_factory=list)
    capabilities: list[ConnectorCapability] = Field(default_factory=list)
    field_mapping: dict[str, dict[str, str]] = Field(default_factory=dict)
    severity_mapping: dict[str, str] = Field(default_factory=dict)
    status_mapping: dict[str, str] = Field(default_factory=dict)
    mapping_contracts: dict[str, Any] = Field(default_factory=dict)
    adapter_contracts: dict[str, Any] = Field(default_factory=dict)
    pagination: dict[str, Any] = Field(default_factory=dict)
    rate_limit: dict[str, Any] = Field(default_factory=dict)
    permissions: list[str] = Field(default_factory=list)
    risk_level: ConnectorRiskLevel = ConnectorRiskLevel.LOW
    description: str = ""
    enabled: bool = True
    raw_response: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    health_check: ConnectorHealthCheckResult | None = None


class ConnectorTestResult(_ConnectorBaseModel):
    connector_id: str
    success: bool
    status: str
    message: str
    health_check: ConnectorHealthCheckResult
    capabilities: list[ConnectorCapability] = Field(default_factory=list)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class ConnectorValidateResult(_ConnectorBaseModel):
    connector_id: str
    success: bool
    status: str
    message: str
    capabilities: list[ConnectorCapability] = Field(default_factory=list)
    adapter_contracts: dict[str, Any] = Field(default_factory=dict)
    mapping_contracts: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ConnectorPreviewResult(_ConnectorBaseModel):
    connector_id: str
    capability: ConnectorCapability
    success: bool
    source: str = "fixture"
    raw_response: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    mapping_result: dict[str, Any] = Field(default_factory=dict)
    adapter_contract: dict[str, Any] = Field(default_factory=dict)
    adapter_request: dict[str, Any] = Field(default_factory=dict)
    mapping_contract: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    missing_required_fields: list[str] = Field(default_factory=list)
    unmapped_fields: list[str] = Field(default_factory=list)
    transform_warnings: list[str] = Field(default_factory=list)
    missing_capabilities: list[ConnectorCapability] = Field(default_factory=list)
