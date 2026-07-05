"""Commercial feature flags derived from the local license."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request, status

from flocks.commercial import audit
from flocks.commercial.models import (
    AuditStatus,
    CommercialFeatureFlag,
    CommercialFeatureState,
    ConnectivityUpdate,
    LicenseInfo,
    TelemetryMode,
    TelemetryUpdate,
    UpdatePolicyUpdate,
)
from flocks.commercial.store import default_store
from flocks.server.auth import get_optional_user


FEATURE_LICENSE = "license"
FEATURE_BRANDING = "branding"
FEATURE_UPDATES = "updates"
FEATURE_CONNECTIVITY = "connectivity"
FEATURE_TELEMETRY = "telemetry"
FEATURE_TELEMETRY_SECURITY_DATA = "telemetry.security_data"
FEATURE_PACKAGES = "packages"
FEATURE_DIAGNOSTICS = "diagnostics"
FEATURE_AUDIT = "audit"

_DISABLED_LICENSE_STATUSES = {"", "unlicensed", "expired", "revoked", "suspended", "inactive", "disabled"}
_ALL_FEATURES = {"*", "all", "commercial.all", "enterprise"}
_FULL_BUNDLE_EDITIONS = {"commercial", "pro", "business", "enterprise"}


@dataclass(frozen=True)
class FeatureDefinition:
    id: str
    label: str
    required_features: tuple[str, ...] = ()
    baseline_enabled: bool = False


FEATURE_DEFINITIONS: dict[str, FeatureDefinition] = {
    FEATURE_LICENSE: FeatureDefinition(
        id=FEATURE_LICENSE,
        label="License import and status",
        baseline_enabled=True,
    ),
    FEATURE_BRANDING: FeatureDefinition(
        id=FEATURE_BRANDING,
        label="Branding controls",
        required_features=(FEATURE_BRANDING,),
    ),
    FEATURE_UPDATES: FeatureDefinition(
        id=FEATURE_UPDATES,
        label="Commercial update policy",
        required_features=(FEATURE_UPDATES,),
    ),
    FEATURE_CONNECTIVITY: FeatureDefinition(
        id=FEATURE_CONNECTIVITY,
        label="Outbound commercial connectivity",
        required_features=(FEATURE_CONNECTIVITY,),
    ),
    FEATURE_TELEMETRY: FeatureDefinition(
        id=FEATURE_TELEMETRY,
        label="Commercial telemetry",
        required_features=(FEATURE_TELEMETRY,),
    ),
    FEATURE_TELEMETRY_SECURITY_DATA: FeatureDefinition(
        id=FEATURE_TELEMETRY_SECURITY_DATA,
        label="Security data telemetry",
        required_features=(FEATURE_TELEMETRY_SECURITY_DATA,),
    ),
    FEATURE_PACKAGES: FeatureDefinition(
        id=FEATURE_PACKAGES,
        label="Commercial package installation",
        required_features=(FEATURE_PACKAGES,),
    ),
    FEATURE_DIAGNOSTICS: FeatureDefinition(
        id=FEATURE_DIAGNOSTICS,
        label="Commercial diagnostics export",
        required_features=(FEATURE_DIAGNOSTICS,),
    ),
    FEATURE_AUDIT: FeatureDefinition(
        id=FEATURE_AUDIT,
        label="Commercial audit log",
        baseline_enabled=True,
    ),
}

FEATURE_ALIASES: dict[str, str] = {
    "*": "*",
    "all": "*",
    "commercial.all": "*",
    "commercial_all": "*",
    "enterprise": "*",
    "white_label": FEATURE_BRANDING,
    "whitelabel": FEATURE_BRANDING,
    "commercial.branding": FEATURE_BRANDING,
    "commercial_branding": FEATURE_BRANDING,
    "update": FEATURE_UPDATES,
    "updates": FEATURE_UPDATES,
    "auto_update": FEATURE_UPDATES,
    "commercial.update": FEATURE_UPDATES,
    "commercial_updates": FEATURE_UPDATES,
    "outbound": FEATURE_CONNECTIVITY,
    "outbound_connectivity": FEATURE_CONNECTIVITY,
    "commercial.connectivity": FEATURE_CONNECTIVITY,
    "commercial_connectivity": FEATURE_CONNECTIVITY,
    "telemetry": FEATURE_TELEMETRY,
    "commercial.telemetry": FEATURE_TELEMETRY,
    "commercial_telemetry": FEATURE_TELEMETRY,
    "telemetry_security_data": FEATURE_TELEMETRY_SECURITY_DATA,
    "telemetry.security_data": FEATURE_TELEMETRY_SECURITY_DATA,
    "security_data_telemetry": FEATURE_TELEMETRY_SECURITY_DATA,
    "commercial.telemetry_security_data": FEATURE_TELEMETRY_SECURITY_DATA,
    "package": FEATURE_PACKAGES,
    "packages": FEATURE_PACKAGES,
    "commercial.package": FEATURE_PACKAGES,
    "commercial.packages": FEATURE_PACKAGES,
    "commercial_packages": FEATURE_PACKAGES,
    "diagnostics": FEATURE_DIAGNOSTICS,
    "diagnostics_export": FEATURE_DIAGNOSTICS,
    "commercial.diagnostics": FEATURE_DIAGNOSTICS,
    "commercial_diagnostics": FEATURE_DIAGNOSTICS,
    "audit": FEATURE_AUDIT,
    "commercial.audit": FEATURE_AUDIT,
    "commercial_audit": FEATURE_AUDIT,
}


def canonical_feature_id(value: Any) -> str:
    normalized = str(value).strip().lower().replace("-", "_")
    return FEATURE_ALIASES.get(normalized, normalized)


def normalize_license_features(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, dict):
        value = [key for key, enabled in value.items() if enabled]
    elif isinstance(value, str):
        value = [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        feature = canonical_feature_id(item)
        if not feature or feature in seen:
            continue
        normalized.append(feature)
        seen.add(feature)
    return sorted(normalized)


def _parse_expiry(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def license_is_active(license_info: LicenseInfo) -> bool:
    status_value = (license_info.status or "").strip().lower()
    if status_value in _DISABLED_LICENSE_STATUSES:
        return False
    expires_at = _parse_expiry(license_info.expires_at)
    if expires_at is not None and expires_at <= datetime.now(UTC):
        return False
    return True


def _licensed_feature_set(license_info: LicenseInfo) -> set[str]:
    features = set(normalize_license_features(license_info.features))
    if features:
        return features
    edition = (license_info.edition or "").strip().lower().replace("-", "_")
    if edition in _FULL_BUNDLE_EDITIONS:
        return {"*"}
    return set()


def feature_state_from_license(license_info: LicenseInfo) -> CommercialFeatureState:
    active = license_is_active(license_info)
    licensed_features = _licensed_feature_set(license_info)
    wildcard_enabled = bool(licensed_features.intersection(_ALL_FEATURES))
    flags: dict[str, CommercialFeatureFlag] = {}

    for feature_id, definition in FEATURE_DEFINITIONS.items():
        enabled = definition.baseline_enabled or (
            active
            and (
                wildcard_enabled
                or any(required in licensed_features for required in definition.required_features)
            )
        )
        if definition.baseline_enabled:
            source = "baseline"
            message = "Available without a commercial license."
        elif enabled:
            source = "license"
            message = "Enabled by the current commercial license."
        elif not active:
            source = "license"
            message = "Disabled because the current license is inactive, expired, or missing."
        else:
            source = "license"
            message = "Disabled because the current license does not include this feature."

        flags[feature_id] = CommercialFeatureFlag(
            id=feature_id,
            label=definition.label,
            enabled=enabled,
            source=source,
            required_features=list(definition.required_features),
            message=message,
        )

    return CommercialFeatureState(
        license_status=license_info.status,
        edition=license_info.edition,
        licensed_features=sorted(licensed_features),
        flags=flags,
    )


async def get_feature_state() -> CommercialFeatureState:
    return feature_state_from_license(await default_store.get_license())


async def is_feature_enabled(feature_id: str) -> bool:
    canonical = canonical_feature_id(feature_id)
    state = await get_feature_state()
    flag = state.flags.get(canonical)
    return bool(flag and flag.enabled)


async def _record_feature_denied(
    request: Request,
    *,
    action: str,
    target: str,
    feature_id: str,
) -> None:
    await audit.record_audit_event(
        action=action,
        target=target,
        status=AuditStatus.DENIED,
        actor=get_optional_user(request),
        request=request,
        summary=f"License feature disabled: {feature_id}",
        metadata={"feature": feature_id},
    )


async def require_feature_for_request(
    request: Request,
    feature_id: str,
    *,
    action: str | None = None,
    target: str | None = None,
) -> None:
    canonical = canonical_feature_id(feature_id)
    if await is_feature_enabled(canonical):
        return
    audit_action = action or "commercial.feature.denied"
    audit_target = target or request.url.path
    await _record_feature_denied(
        request,
        action=audit_action,
        target=audit_target,
        feature_id=canonical,
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"License feature disabled: {canonical}",
    )


async def reconcile_configs_for_license(license_info: LicenseInfo) -> None:
    state = feature_state_from_license(license_info)
    flag = state.flags

    if not flag[FEATURE_TELEMETRY].enabled:
        await default_store.update_telemetry(
            TelemetryUpdate(
                enabled=False,
                mode=TelemetryMode.OFF,
                include_logs=False,
                include_metrics=False,
                include_security_data=False,
            )
        )
    elif not flag[FEATURE_TELEMETRY_SECURITY_DATA].enabled:
        await default_store.update_telemetry(TelemetryUpdate(include_security_data=False))

    if not flag[FEATURE_CONNECTIVITY].enabled:
        await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))

    if not flag[FEATURE_UPDATES].enabled:
        await default_store.update_update_policy(
            UpdatePolicyUpdate(
                update_check_enabled=False,
                update_apply_enabled=False,
                auto_check=False,
                auto_install=False,
            )
        )
