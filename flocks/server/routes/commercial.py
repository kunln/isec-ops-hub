"""Commercial local-admin HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status

from flocks.commercial import (
    access_control,
    audit,
    branding,
    connectivity,
    diagnostics,
    features,
    license,
    package_registry,
    policy,
    telemetry,
    update_policy,
)
from flocks.commercial.models import (
    AuditStatus,
    CommercialBranding,
    CommercialBrandingUpdate,
    CommercialAuditEvent,
    CommercialPackageManifest,
    ConnectivityConfig,
    ConnectivityUpdate,
    Diagnostics,
    DiagnosticsExportResponse,
    CommercialFeatureState,
    LicenseImportRequest,
    LicenseInfo,
    NotificationPolicy,
    NotificationPolicyUpdate,
    PackageInstallRequest,
    PackageRollbackRequest,
    TelemetryConfig,
    TelemetryUpdate,
    UpdatePolicy,
    UpdatePolicyUpdate,
)
from flocks.server.auth import require_user


router = APIRouter()


async def _require_write_admin(request: Request, action: str, target: str):
    return await access_control.require_capability_for_request(
        request,
        "commercial.admin",
        action=action,
        target=target,
    )


async def _audit_success(
    request: Request,
    actor,
    *,
    action: str,
    target: str,
    summary: str,
    metadata: dict | None = None,
) -> None:
    await audit.record_audit_event(
        action=action,
        target=target,
        status=AuditStatus.SUCCESS,
        actor=actor,
        request=request,
        summary=summary,
        metadata=metadata or {},
    )


def _changed_fields(payload) -> list[str]:
    return sorted(payload.model_dump(mode="json", exclude_unset=True).keys())


def _package_permissions_for_audit(manifest: CommercialPackageManifest) -> list:
    permissions = []
    for permission in manifest.permissions:
        if hasattr(permission, "model_dump"):
            permissions.append(permission.model_dump(mode="json"))
        else:
            permissions.append(permission)
    return permissions


def _package_install_metadata(
    manifest: CommercialPackageManifest,
    payload: PackageInstallRequest,
    *,
    warnings: list[str] | None = None,
    denials: list[str] | None = None,
) -> dict:
    metadata = {
        "package_id": manifest.id,
        "package_type": manifest.type,
        "version": manifest.version,
        "risk_level": manifest.risk_level,
        "risk_summary": manifest.risk_summary,
        "permissions": _package_permissions_for_audit(manifest),
        "permissions_acknowledged": payload.permissions_acknowledged,
        "risk_acknowledged": payload.risk_acknowledged,
        "signature_policy_acknowledged": payload.signature_policy_acknowledged,
        "has_hash": bool(manifest.hash),
        "has_signature": bool(manifest.signature),
        "source": manifest.source,
    }
    if warnings:
        metadata["preflight_warnings"] = warnings
    if denials:
        metadata["denials"] = denials
    return metadata


async def _require_update_policy_features(payload: UpdatePolicyUpdate, request: Request) -> None:
    updates = payload.model_dump(mode="json", exclude_unset=True)
    commercial_update_fields = {
        "update_check_enabled",
        "update_apply_enabled",
        "legacy_flocks_update_sources_enabled",
        "update_server_url",
        "auto_check",
        "auto_install",
        "last_checked_at",
    }
    if any(field in updates and updates[field] not in (None, False, "") for field in commercial_update_fields):
        await features.require_feature_for_request(
            request,
            features.FEATURE_UPDATES,
            action="commercial.update_policy.update",
            target="update-policy",
        )


async def _require_connectivity_features(payload: ConnectivityUpdate, request: Request) -> None:
    updates = payload.model_dump(mode="json", exclude_unset=True)
    commercial_connectivity_fields = {
        "outbound_enabled",
        "proxy_url",
        "update_server_url",
        "telemetry_server_url",
        "license_server_url",
    }
    if any(field in updates and updates[field] not in (None, False, "") for field in commercial_connectivity_fields):
        await features.require_feature_for_request(
            request,
            features.FEATURE_CONNECTIVITY,
            action="commercial.connectivity.update",
            target="connectivity",
        )


async def _require_telemetry_features(payload: TelemetryUpdate, request: Request) -> None:
    updates = payload.model_dump(mode="json", exclude_unset=True)
    telemetry_fields = {"enabled", "mode", "include_logs", "include_metrics", "last_upload_at"}
    if any(field in updates and updates[field] not in (None, False, "", "off") for field in telemetry_fields):
        await features.require_feature_for_request(
            request,
            features.FEATURE_TELEMETRY,
            action="commercial.telemetry.update",
            target="telemetry",
        )
    if updates.get("include_security_data") is True:
        await features.require_feature_for_request(
            request,
            features.FEATURE_TELEMETRY_SECURITY_DATA,
            action="commercial.telemetry.update",
            target="telemetry",
        )


@router.get("/branding", response_model=CommercialBranding)
async def get_branding():
    return await branding.get_branding()


@router.get("/access-control")
async def get_access_control(request: Request):
    user = require_user(request)
    return {
        "role": user.role,
        "capabilities": sorted(access_control.capabilities_for_role(user.role)),
        "matrix": access_control.capability_matrix(),
        "routes": access_control.ui_route_capabilities(),
        "feature_flags": await features.get_feature_state(),
    }


@router.patch("/branding", response_model=CommercialBranding)
async def patch_branding(payload: CommercialBrandingUpdate, request: Request):
    actor = await _require_write_admin(request, "commercial.branding.update", "branding")
    await features.require_feature_for_request(
        request,
        features.FEATURE_BRANDING,
        action="commercial.branding.update",
        target="branding",
    )
    result = await branding.update_branding(payload)
    await _audit_success(
        request,
        actor,
        action="commercial.branding.update",
        target="branding",
        summary="Updated commercial branding",
        metadata={"changed_fields": _changed_fields(payload)},
    )
    return result


@router.get("/license", response_model=LicenseInfo)
async def get_license(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="license")
    return await license.get_license()


@router.get("/feature-flags", response_model=CommercialFeatureState)
async def get_feature_flags(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="feature-flags")
    return await features.get_feature_state()


@router.post("/license/import", response_model=LicenseInfo)
async def import_license(payload: LicenseImportRequest, request: Request):
    actor = await _require_write_admin(request, "commercial.license.import", "license")
    try:
        result = await license.import_license(payload)
    except ValueError as exc:
        await audit.record_audit_event(
            action="commercial.license.import",
            target="license",
            status=AuditStatus.FAILED,
            actor=actor,
            request=request,
            summary=str(exc),
            metadata={
                "has_license_key": bool(payload.license_key),
                "manifest_keys": sorted((payload.manifest or {}).keys()),
            },
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await _audit_success(
        request,
        actor,
        action="commercial.license.import",
        target="license",
        summary="Imported local commercial license",
        metadata={
            "license_id": result.license_id,
            "edition": result.edition,
            "has_license_key": bool(payload.license_key),
            "manifest_keys": sorted((payload.manifest or {}).keys()),
        },
    )
    return result


@router.get("/update-policy", response_model=UpdatePolicy)
async def get_update_policy(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="update-policy")
    return await update_policy.get_update_policy()


@router.patch("/update-policy", response_model=UpdatePolicy)
async def patch_update_policy(payload: UpdatePolicyUpdate, request: Request):
    actor = await _require_write_admin(request, "commercial.update_policy.update", "update-policy")
    await _require_update_policy_features(payload, request)
    result = await update_policy.update_update_policy(payload)
    await _audit_success(
        request,
        actor,
        action="commercial.update_policy.update",
        target="update-policy",
        summary="Updated commercial update policy",
        metadata={"changed_fields": _changed_fields(payload)},
    )
    return result


@router.get("/notification-policy", response_model=NotificationPolicy)
async def get_notification_policy(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="notification-policy")
    return await policy.get_notification_policy()


@router.patch("/notification-policy", response_model=NotificationPolicy)
async def patch_notification_policy(payload: NotificationPolicyUpdate, request: Request):
    actor = await _require_write_admin(request, "commercial.notification_policy.update", "notification-policy")
    result = await policy.update_notification_policy(payload)
    await _audit_success(
        request,
        actor,
        action="commercial.notification_policy.update",
        target="notification-policy",
        summary="Updated commercial notification policy",
        metadata={"changed_fields": _changed_fields(payload)},
    )
    return result


@router.get("/connectivity", response_model=ConnectivityConfig)
async def get_connectivity(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="connectivity")
    return await connectivity.get_connectivity()


@router.patch("/connectivity", response_model=ConnectivityConfig)
async def patch_connectivity(payload: ConnectivityUpdate, request: Request):
    actor = await _require_write_admin(request, "commercial.connectivity.update", "connectivity")
    await _require_connectivity_features(payload, request)
    result = await connectivity.update_connectivity(payload)
    await _audit_success(
        request,
        actor,
        action="commercial.connectivity.update",
        target="connectivity",
        summary="Updated outbound connectivity policy",
        metadata={"changed_fields": _changed_fields(payload)},
    )
    return result


@router.get("/telemetry", response_model=TelemetryConfig)
async def get_telemetry(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="telemetry")
    return await telemetry.get_telemetry()


@router.patch("/telemetry", response_model=TelemetryConfig)
async def patch_telemetry(payload: TelemetryUpdate, request: Request):
    actor = await _require_write_admin(request, "commercial.telemetry.update", "telemetry")
    await _require_telemetry_features(payload, request)
    result = await telemetry.update_telemetry(payload)
    await _audit_success(
        request,
        actor,
        action="commercial.telemetry.update",
        target="telemetry",
        summary="Updated commercial telemetry policy",
        metadata={"changed_fields": _changed_fields(payload)},
    )
    return result


@router.get("/packages", response_model=list[CommercialPackageManifest])
async def list_packages(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="packages")
    return await package_registry.list_packages()


@router.post("/packages/install", response_model=CommercialPackageManifest)
async def install_package(payload: PackageInstallRequest, request: Request):
    actor = await _require_write_admin(request, "commercial.package.install", f"package:{payload.manifest.id}")
    await features.require_feature_for_request(
        request,
        features.FEATURE_PACKAGES,
        action="commercial.package.install",
        target=f"package:{payload.manifest.id}",
    )
    try:
        result = await package_registry.install_package(payload)
    except PermissionError as exc:
        manifest = getattr(exc, "manifest", payload.manifest)
        await audit.record_audit_event(
            action="commercial.package.install",
            target=f"package:{manifest.id}",
            status=AuditStatus.DENIED,
            actor=actor,
            request=request,
            summary=str(exc),
            metadata=_package_install_metadata(
                manifest,
                payload,
                warnings=getattr(exc, "warnings", None),
                denials=getattr(exc, "denials", None),
            ),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await _audit_success(
        request,
        actor,
        action="commercial.package.install",
        target=f"package:{result.id}",
        summary="Installed local commercial package manifest",
        metadata=_package_install_metadata(result, payload),
    )
    return result


@router.post("/packages/rollback", response_model=CommercialPackageManifest)
async def rollback_package(payload: PackageRollbackRequest, request: Request):
    actor = await _require_write_admin(request, "commercial.package.rollback", f"package:{payload.id}")
    result = await package_registry.rollback_package(payload.id)
    if result is None:
        await audit.record_audit_event(
            action="commercial.package.rollback",
            target=f"package:{payload.id}",
            status=AuditStatus.FAILED,
            actor=actor,
            request=request,
            summary="Package not found or rollback unavailable",
            metadata={"package_id": payload.id},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Package not found or rollback unavailable: {payload.id}",
        )
    await _audit_success(
        request,
        actor,
        action="commercial.package.rollback",
        target=f"package:{result.id}",
        summary="Rolled back local commercial package manifest",
        metadata={"package_id": result.id, "version": result.version, "rollback_version": result.rollback_version},
    )
    return result


@router.get("/diagnostics", response_model=Diagnostics)
async def get_diagnostics(request: Request):
    await access_control.require_capability_for_request(request, "commercial.admin", target="diagnostics")
    return await diagnostics.get_diagnostics()


@router.post("/diagnostics/export", response_model=DiagnosticsExportResponse)
async def export_diagnostics(request: Request):
    actor = await _require_write_admin(request, "commercial.diagnostics.export", "diagnostics")
    await features.require_feature_for_request(
        request,
        features.FEATURE_DIAGNOSTICS,
        action="commercial.diagnostics.export",
        target="diagnostics",
    )
    result = await diagnostics.export_diagnostics()
    await _audit_success(
        request,
        actor,
        action="commercial.diagnostics.export",
        target="diagnostics",
        summary="Exported commercial diagnostics",
        metadata={"filename": result.filename},
    )
    return result


@router.get("/audit", response_model=list[CommercialAuditEvent])
async def list_audit_events(request: Request, limit: int = Query(100, ge=1, le=500)):
    await access_control.require_capability_for_request(
        request,
        "commercial.audit.read",
        action="commercial.audit.read",
        target="audit",
    )
    return await audit.list_audit_events(limit=limit)
