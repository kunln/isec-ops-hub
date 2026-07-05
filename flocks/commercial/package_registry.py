"""Local commercial package registry.

The first commercial phase is local and manifest-driven only. Package
installation records manifests; it does not download or execute code.
"""

from __future__ import annotations

from flocks.commercial import features
from flocks.commercial.models import (
    CommercialPackageManifest,
    PackageInstallRequest,
    PackageRiskLevel,
    PackageType,
)
from flocks.commercial.store import default_store


RISK_SCORE = {
    PackageRiskLevel.LOW.value: 0,
    PackageRiskLevel.MEDIUM.value: 1,
    PackageRiskLevel.HIGH.value: 2,
    PackageRiskLevel.CRITICAL.value: 3,
}
HIGH_RISK_TYPES = {PackageType.TOOL.value, PackageType.RUNTIME.value}
LOCAL_SOURCES = {"local", "offline", "file"}


class PackagePreflightError(PermissionError):
    def __init__(
        self,
        message: str,
        *,
        manifest: CommercialPackageManifest,
        warnings: list[str],
        denials: list[str],
    ) -> None:
        super().__init__(message)
        self.manifest = manifest
        self.warnings = warnings
        self.denials = denials


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _risk_score(level) -> int:
    return RISK_SCORE.get(_enum_value(level), 0)


def _max_risk(*levels) -> str:
    return max((_enum_value(level) for level in levels), key=lambda item: RISK_SCORE.get(item, 0))


def _permission_label(permission) -> str:
    return permission.label or permission.id


def _type_risk(package_type) -> str:
    package_type_value = _enum_value(package_type)
    if package_type_value in HIGH_RISK_TYPES:
        return PackageRiskLevel.HIGH.value
    if package_type_value in {PackageType.AGENT.value, PackageType.WORKFLOW.value}:
        return PackageRiskLevel.MEDIUM.value
    return PackageRiskLevel.LOW.value


def _assess_manifest(manifest: CommercialPackageManifest) -> tuple[CommercialPackageManifest, list[str]]:
    package_type_value = _enum_value(manifest.type)
    permission_risks = [_enum_value(permission.risk) for permission in manifest.permissions]
    risk_level = _max_risk(manifest.risk_level, _type_risk(manifest.type), *permission_risks)
    warnings: list[str] = []

    if package_type_value == PackageType.TOOL.value:
        warnings.append("tool packages can request operational permissions and are high risk")
    elif package_type_value == PackageType.RUNTIME.value:
        warnings.append("runtime packages can alter local execution behavior and are high risk")

    elevated_permissions = [
        _permission_label(permission)
        for permission in manifest.permissions
        if _risk_score(permission.risk) >= _risk_score(PackageRiskLevel.HIGH)
    ]
    if elevated_permissions:
        warnings.append(f"high-risk permissions declared: {', '.join(elevated_permissions)}")

    if not manifest.permissions and package_type_value == PackageType.TOOL.value:
        warnings.append("tool package declares no explicit permissions")

    summary = "; ".join(warnings) if warnings else "local package manifest preflight passed"
    data = manifest.model_dump(mode="json")
    data["risk_level"] = risk_level
    data["risk_summary"] = summary
    assessed = CommercialPackageManifest.model_validate(data)
    return assessed, warnings


def _is_high_risk(manifest: CommercialPackageManifest) -> bool:
    return _risk_score(manifest.risk_level) >= _risk_score(PackageRiskLevel.HIGH)


def _source_is_local(source: str | None) -> bool:
    return (source or "local").lower() in LOCAL_SOURCES


async def list_packages() -> list[CommercialPackageManifest]:
    return await default_store.list_packages()


async def install_package(request: PackageInstallRequest) -> CommercialPackageManifest:
    manifest, warnings = _assess_manifest(request.manifest)
    policy = await default_store.get_update_policy()
    denials: list[str] = []
    package_type_value = _enum_value(manifest.type)
    high_risk = _is_high_risk(manifest)

    if not await features.is_feature_enabled(features.FEATURE_PACKAGES):
        denials.append("license feature packages is disabled")

    if _source_is_local(manifest.source) and not policy.offline_package_import:
        denials.append("offline package import is disabled by update policy")

    requires_permission_ack = package_type_value == PackageType.TOOL.value or bool(manifest.permissions)
    if requires_permission_ack and not request.permissions_acknowledged:
        denials.append("package permissions must be acknowledged before installation")

    if high_risk:
        if not request.risk_acknowledged:
            denials.append("high-risk package assessment must be acknowledged before installation")
        if not manifest.hash:
            denials.append("high-risk package requires a hash before installation")
        if policy.signature_required and not manifest.signature:
            denials.append("high-risk package requires a signature because signature_required is enabled")
        if not policy.signature_required and not manifest.signature and not request.signature_policy_acknowledged:
            denials.append("unsigned high-risk package requires explicit non-signature policy acknowledgement")

    if denials:
        raise PackagePreflightError(
            "; ".join(denials),
            manifest=manifest,
            warnings=warnings,
            denials=denials,
        )
    return await default_store.install_package(manifest)


async def rollback_package(package_id: str) -> CommercialPackageManifest | None:
    return await default_store.rollback_package(package_id)
