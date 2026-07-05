"""Storage-backed commercial local-admin configuration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypeVar

from pydantic import BaseModel

from flocks.commercial.models import (
    CommercialBranding,
    CommercialBrandingUpdate,
    CommercialAuditEvent,
    CommercialPackageManifest,
    ConnectivityConfig,
    ConnectivityUpdate,
    LicenseInfo,
    NotificationPolicy,
    NotificationPolicyUpdate,
    TelemetryConfig,
    TelemetryUpdate,
    UpdatePolicy,
    UpdatePolicyUpdate,
)
from flocks.storage.storage import Storage
from flocks.utils.id import Identifier


CommercialConfig = TypeVar(
    "CommercialConfig",
    CommercialBranding,
    ConnectivityConfig,
    LicenseInfo,
    NotificationPolicy,
    TelemetryConfig,
    UpdatePolicy,
)

BRANDING_KEY = "commercial/branding"
LICENSE_KEY = "commercial/license"
UPDATE_POLICY_KEY = "commercial/update-policy"
NOTIFICATION_POLICY_KEY = "commercial/notification-policy"
CONNECTIVITY_KEY = "commercial/connectivity"
TELEMETRY_KEY = "commercial/telemetry"
PACKAGES_PREFIX = "commercial/packages/"
AUDIT_PREFIX = "commercial/audit/"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _dump_patch(data: BaseModel | dict[str, Any]) -> dict[str, Any]:
    if isinstance(data, BaseModel):
        return data.model_dump(mode="json", exclude_unset=True)
    return dict(data)


def _normalize_update_policy_patch(updates: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(updates)
    pairs = (
        ("auto_check", "update_check_enabled"),
        ("auto_install", "update_apply_enabled"),
        ("manual_approval", "require_manual_approval"),
        ("channel", "update_channel"),
    )
    for legacy_name, explicit_name in pairs:
        if legacy_name in normalized:
            normalized[explicit_name] = normalized[legacy_name]
        if explicit_name in normalized:
            normalized[legacy_name] = normalized[explicit_name]
    return normalized


class CommercialStore:
    async def _get_config(self, key: str, model: type[CommercialConfig]) -> CommercialConfig:
        stored = await Storage.get(key, model)
        if stored is not None:
            return stored
        return model()

    async def _set_config(self, key: str, value: CommercialConfig) -> CommercialConfig:
        await Storage.set(key, value, "commercial.config")
        return value

    async def _patch_config(
        self,
        key: str,
        model: type[CommercialConfig],
        payload: BaseModel | dict[str, Any],
    ) -> CommercialConfig:
        current = await self._get_config(key, model)
        data = current.model_dump(mode="json")
        updates = _dump_patch(payload)
        for field_name, value in updates.items():
            if field_name not in model.model_fields:
                continue
            data[field_name] = value
        updated = model.model_validate(data)
        return await self._set_config(key, updated)

    async def get_branding(self) -> CommercialBranding:
        return await self._get_config(BRANDING_KEY, CommercialBranding)

    async def update_branding(self, payload: CommercialBrandingUpdate | dict[str, Any]) -> CommercialBranding:
        return await self._patch_config(BRANDING_KEY, CommercialBranding, payload)

    async def get_license(self) -> LicenseInfo:
        return await self._get_config(LICENSE_KEY, LicenseInfo)

    async def set_license(self, payload: LicenseInfo | dict[str, Any]) -> LicenseInfo:
        license_info = payload if isinstance(payload, LicenseInfo) else LicenseInfo.model_validate(payload)
        return await self._set_config(LICENSE_KEY, license_info)

    async def get_update_policy(self) -> UpdatePolicy:
        return await self._get_config(UPDATE_POLICY_KEY, UpdatePolicy)

    async def update_update_policy(self, payload: UpdatePolicyUpdate | dict[str, Any]) -> UpdatePolicy:
        return await self._patch_config(
            UPDATE_POLICY_KEY,
            UpdatePolicy,
            _normalize_update_policy_patch(_dump_patch(payload)),
        )

    async def get_notification_policy(self) -> NotificationPolicy:
        return await self._get_config(NOTIFICATION_POLICY_KEY, NotificationPolicy)

    async def update_notification_policy(self, payload: NotificationPolicyUpdate | dict[str, Any]) -> NotificationPolicy:
        return await self._patch_config(NOTIFICATION_POLICY_KEY, NotificationPolicy, payload)

    async def get_connectivity(self) -> ConnectivityConfig:
        return await self._get_config(CONNECTIVITY_KEY, ConnectivityConfig)

    async def update_connectivity(self, payload: ConnectivityUpdate | dict[str, Any]) -> ConnectivityConfig:
        return await self._patch_config(CONNECTIVITY_KEY, ConnectivityConfig, payload)

    async def get_telemetry(self) -> TelemetryConfig:
        return await self._get_config(TELEMETRY_KEY, TelemetryConfig)

    async def update_telemetry(self, payload: TelemetryUpdate | dict[str, Any]) -> TelemetryConfig:
        return await self._patch_config(TELEMETRY_KEY, TelemetryConfig, payload)

    def _package_key(self, package_id: str) -> str:
        return f"{PACKAGES_PREFIX}{package_id}"

    async def list_packages(self) -> list[CommercialPackageManifest]:
        entries = await Storage.list_entries(PACKAGES_PREFIX, CommercialPackageManifest)
        packages = [package for _, package in entries]
        packages.sort(key=lambda item: (item.type, item.name.lower(), item.version))
        return packages

    async def get_package(self, package_id: str) -> CommercialPackageManifest | None:
        return await Storage.get(self._package_key(package_id), CommercialPackageManifest)

    async def install_package(self, manifest: CommercialPackageManifest) -> CommercialPackageManifest:
        existing = await self.get_package(manifest.id)
        data = manifest.model_dump(mode="json")
        data["installed_at"] = data.get("installed_at") or utc_now()
        if existing and existing.version != manifest.version:
            data["rollback_version"] = existing.version
        elif existing and not data.get("rollback_version"):
            data["rollback_version"] = existing.rollback_version
        installed = CommercialPackageManifest.model_validate(data)
        await Storage.set(self._package_key(installed.id), installed, "commercial.package")
        return installed

    async def rollback_package(self, package_id: str) -> CommercialPackageManifest | None:
        current = await self.get_package(package_id)
        if current is None or not current.rollback_version:
            return None
        data = current.model_dump(mode="json")
        previous_version = current.version
        data["version"] = current.rollback_version
        data["rollback_version"] = previous_version
        data["installed_at"] = utc_now()
        rolled_back = CommercialPackageManifest.model_validate(data)
        await Storage.set(self._package_key(package_id), rolled_back, "commercial.package")
        return rolled_back

    def _audit_key(self, event_id: str) -> str:
        return f"{AUDIT_PREFIX}{event_id}"

    async def record_audit_event(self, payload: CommercialAuditEvent | dict[str, Any]) -> CommercialAuditEvent:
        data = payload.model_dump(mode="json") if isinstance(payload, CommercialAuditEvent) else dict(payload)
        if not data.get("id"):
            data["id"] = Identifier.create("event")
        data["created_at"] = data.get("created_at") or utc_now()
        event = CommercialAuditEvent.model_validate(data)
        await Storage.set(self._audit_key(event.id), event, "commercial.audit")
        return event

    async def list_audit_events(self, limit: int = 100) -> list[CommercialAuditEvent]:
        entries = await Storage.list_entries(AUDIT_PREFIX, CommercialAuditEvent)
        events = [event for _, event in entries]
        events.sort(key=lambda item: item.created_at, reverse=True)
        return events[:limit]


default_store = CommercialStore()
