"""Commercial local-admin domain models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _CommercialBaseModel(BaseModel):
    model_config = ConfigDict(use_enum_values=True)


class _CommercialPatchModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class TelemetryMode(str, Enum):
    OFF = "off"
    BASIC = "basic"
    SUPPORT = "support"


class PackageType(str, Enum):
    AGENT = "agent"
    TOOL = "tool"
    SKILL = "skill"
    WORKFLOW = "workflow"
    RUNTIME = "runtime"


class PackageRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILED = "failed"


class CommercialBranding(_CommercialBaseModel):
    product_name: str = Field(default="Flocks", min_length=1, max_length=80)
    company_name: str = Field(default="Flocks Team", min_length=1, max_length=120)
    logo_light: str | None = None
    logo_dark: str | None = None
    favicon: str | None = None
    support_url: str | None = None
    copyright: str = "Copyright Flocks Team"
    login_title: str | None = None
    login_subtitle: str | None = None


class CommercialBrandingUpdate(_CommercialPatchModel):
    product_name: str | None = Field(default=None, min_length=1, max_length=80)
    company_name: str | None = Field(default=None, min_length=1, max_length=120)
    logo_light: str | None = None
    logo_dark: str | None = None
    favicon: str | None = None
    support_url: str | None = None
    copyright: str | None = None
    login_title: str | None = None
    login_subtitle: str | None = None


class LicenseInfo(_CommercialBaseModel):
    status: str = "unlicensed"
    edition: str = "community"
    licensed_to: str | None = None
    license_id: str | None = None
    expires_at: str | None = None
    features: list[str] = Field(default_factory=list)
    imported_at: str | None = None
    source: str = "local"
    license_key_hash: str | None = None
    license_key_tail: str | None = None
    message: str | None = None

    @field_validator("features", mode="before")
    @classmethod
    def normalize_features(cls, value):
        if value is None or value == "":
            return []
        if isinstance(value, dict):
            value = [key for key, enabled in value.items() if enabled]
        elif isinstance(value, str):
            value = [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]
        normalized = []
        seen = set()
        for item in value:
            feature = str(item).strip().lower().replace("-", "_")
            if not feature or feature in seen:
                continue
            normalized.append(feature)
            seen.add(feature)
        return sorted(normalized)


class LicenseImportRequest(_CommercialPatchModel):
    license_key: str | None = None
    manifest: dict[str, Any] | None = None


class CommercialFeatureFlag(_CommercialBaseModel):
    id: str
    label: str
    enabled: bool = False
    source: str = "license"
    required_features: list[str] = Field(default_factory=list)
    message: str | None = None


class CommercialFeatureState(_CommercialBaseModel):
    license_status: str = "unlicensed"
    edition: str = "community"
    licensed_features: list[str] = Field(default_factory=list)
    flags: dict[str, CommercialFeatureFlag] = Field(default_factory=dict)


class NotificationPolicy(_CommercialBaseModel):
    local_notifications_enabled: bool = True
    built_in_notifications_enabled: bool = False
    benefit_notifications_enabled: bool = False
    whats_new_notifications_enabled: bool = False
    vendor_notifications_enabled: bool = False
    announcement_notifications_enabled: bool = True


class NotificationPolicyUpdate(_CommercialPatchModel):
    local_notifications_enabled: bool | None = None
    built_in_notifications_enabled: bool | None = None
    benefit_notifications_enabled: bool | None = None
    whats_new_notifications_enabled: bool | None = None
    vendor_notifications_enabled: bool | None = None
    announcement_notifications_enabled: bool | None = None


class UpdatePolicy(_CommercialBaseModel):
    update_check_enabled: bool = False
    update_apply_enabled: bool = False
    legacy_flocks_update_sources_enabled: bool = False
    update_channel: str = "stable"
    require_manual_approval: bool = True
    signature_required: bool = True

    # Backward-compatible fields used by the existing commercial console and
    # package-install policy. Keep them synchronized with the explicit fields
    # above while callers migrate to the new names.
    update_server_url: str | None = None
    channel: str = "stable"
    auto_check: bool = False
    auto_install: bool = False
    manual_approval: bool = True
    offline_package_import: bool = True
    rollback_enabled: bool = True
    last_checked_at: str | None = None

    @model_validator(mode="before")
    @classmethod
    def sync_legacy_fields(cls, value):
        if not isinstance(value, dict):
            return value
        data = dict(value)
        pairs = (
            ("auto_check", "update_check_enabled"),
            ("auto_install", "update_apply_enabled"),
            ("manual_approval", "require_manual_approval"),
            ("channel", "update_channel"),
        )
        for legacy_name, explicit_name in pairs:
            if explicit_name not in data and legacy_name in data:
                data[explicit_name] = data[legacy_name]
            if legacy_name not in data and explicit_name in data:
                data[legacy_name] = data[explicit_name]
        return data


class UpdatePolicyUpdate(_CommercialPatchModel):
    update_check_enabled: bool | None = None
    update_apply_enabled: bool | None = None
    legacy_flocks_update_sources_enabled: bool | None = None
    update_channel: str | None = None
    require_manual_approval: bool | None = None
    signature_required: bool | None = None
    update_server_url: str | None = None
    channel: str | None = None
    auto_check: bool | None = None
    auto_install: bool | None = None
    manual_approval: bool | None = None
    offline_package_import: bool | None = None
    rollback_enabled: bool | None = None
    last_checked_at: str | None = None


class ConnectivityConfig(_CommercialBaseModel):
    outbound_enabled: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)
    proxy_url: str | None = None
    tls_verify: bool = True
    update_server_url: str | None = None
    telemetry_server_url: str | None = None
    license_server_url: str | None = None


class ConnectivityUpdate(_CommercialPatchModel):
    outbound_enabled: bool | None = None
    allowed_hosts: list[str] | None = None
    proxy_url: str | None = None
    tls_verify: bool | None = None
    update_server_url: str | None = None
    telemetry_server_url: str | None = None
    license_server_url: str | None = None


class TelemetryConfig(_CommercialBaseModel):
    enabled: bool = False
    mode: TelemetryMode = TelemetryMode.OFF
    include_logs: bool = False
    include_metrics: bool = False
    include_security_data: bool = False
    redaction_enabled: bool = True
    last_upload_at: str | None = None


class TelemetryUpdate(_CommercialPatchModel):
    enabled: bool | None = None
    mode: TelemetryMode | None = None
    include_logs: bool | None = None
    include_metrics: bool | None = None
    include_security_data: bool | None = None
    redaction_enabled: bool | None = None
    last_upload_at: str | None = None


class PackagePermissionDeclaration(_CommercialBaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$", min_length=1, max_length=120)
    label: str | None = Field(default=None, max_length=160)
    description: str | None = None
    scope: str | None = Field(default=None, max_length=160)
    reason: str | None = None
    risk: PackageRiskLevel = PackageRiskLevel.LOW


class CommercialPackageManifest(_CommercialBaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$", min_length=1, max_length=120)
    type: PackageType
    name: str = Field(min_length=1, max_length=160)
    version: str = Field(min_length=1, max_length=80)
    description: str | None = None
    publisher: str | None = None
    compatible_runtime: str | None = None
    permissions: list[PackagePermissionDeclaration] = Field(default_factory=list)
    risk_level: PackageRiskLevel = PackageRiskLevel.LOW
    risk_summary: str | None = None
    hash: str | None = None
    signature: str | None = None
    installed_at: str | None = None
    enabled: bool = True
    source: str = "local"
    rollback_version: str | None = None

    @field_validator("permissions", mode="before")
    @classmethod
    def normalize_permissions(cls, value):
        if value is None or value == "":
            return []
        if isinstance(value, str):
            value = [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]
        normalized = []
        for item in value:
            if isinstance(item, str):
                normalized.append(
                    {
                        "id": item,
                        "label": item,
                        "risk": PackageRiskLevel.MEDIUM,
                    }
                )
            else:
                normalized.append(item)
        return normalized


class PackageInstallRequest(_CommercialPatchModel):
    manifest: CommercialPackageManifest
    permissions_acknowledged: bool = False
    risk_acknowledged: bool = False
    signature_policy_acknowledged: bool = False


class PackageRollbackRequest(_CommercialPatchModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$", min_length=1, max_length=120)


class Diagnostics(_CommercialBaseModel):
    generated_at: str
    storage_prefixes: list[str] = Field(default_factory=list)
    outbound_enabled: bool
    allowed_hosts: list[str] = Field(default_factory=list)
    telemetry_enabled: bool
    telemetry_mode: TelemetryMode
    include_security_data: bool
    package_count: int
    license_status: str
    update_channel: str
    warnings: list[str] = Field(default_factory=list)


class DiagnosticsExportResponse(_CommercialBaseModel):
    filename: str
    format: str = "json"
    content: dict[str, Any]


class CommercialAuditEvent(_CommercialBaseModel):
    id: str = ""
    action: str
    target: str
    status: AuditStatus = AuditStatus.SUCCESS
    actor_id: str | None = None
    actor_username: str | None = None
    actor_role: str | None = None
    request_ip: str | None = None
    user_agent: str | None = None
    summary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
