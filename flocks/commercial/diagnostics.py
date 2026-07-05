"""Commercial diagnostics helpers."""

from __future__ import annotations

from flocks.commercial.models import Diagnostics, DiagnosticsExportResponse
from flocks.commercial.store import (
    AUDIT_PREFIX,
    BRANDING_KEY,
    CONNECTIVITY_KEY,
    LICENSE_KEY,
    NOTIFICATION_POLICY_KEY,
    PACKAGES_PREFIX,
    TELEMETRY_KEY,
    UPDATE_POLICY_KEY,
    default_store,
    utc_now,
)


async def get_diagnostics() -> Diagnostics:
    connectivity = await default_store.get_connectivity()
    telemetry = await default_store.get_telemetry()
    license_info = await default_store.get_license()
    update_policy = await default_store.get_update_policy()
    packages = await default_store.list_packages()

    warnings: list[str] = []
    if telemetry.enabled and telemetry.include_security_data:
        warnings.append("telemetry_security_data_enabled")
    if telemetry.enabled and not telemetry.redaction_enabled:
        warnings.append("telemetry_redaction_disabled")
    if connectivity.outbound_enabled and not connectivity.allowed_hosts:
        warnings.append("outbound_enabled_without_allowed_hosts")
    if not update_policy.signature_required:
        warnings.append("package_signature_not_required")
    if update_policy.update_apply_enabled or update_policy.auto_install:
        warnings.append("auto_install_enabled")

    return Diagnostics(
        generated_at=utc_now(),
        storage_prefixes=[
            BRANDING_KEY,
            LICENSE_KEY,
            UPDATE_POLICY_KEY,
            NOTIFICATION_POLICY_KEY,
            CONNECTIVITY_KEY,
            TELEMETRY_KEY,
            PACKAGES_PREFIX,
            AUDIT_PREFIX,
        ],
        outbound_enabled=connectivity.outbound_enabled,
        allowed_hosts=connectivity.allowed_hosts,
        telemetry_enabled=telemetry.enabled,
        telemetry_mode=telemetry.mode,
        include_security_data=telemetry.include_security_data,
        package_count=len(packages),
        license_status=license_info.status,
        update_channel=update_policy.update_channel,
        warnings=warnings,
    )


async def export_diagnostics() -> DiagnosticsExportResponse:
    diagnostics = await get_diagnostics()
    generated = diagnostics.generated_at.replace(":", "").replace("+", "Z")
    return DiagnosticsExportResponse(
        filename=f"commercial-diagnostics-{generated}.json",
        content=diagnostics.model_dump(mode="json"),
    )
