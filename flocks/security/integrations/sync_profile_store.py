"""Storage-backed Sync Profile metadata store skeleton."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import SENSITIVE_PARAM_KEYWORDS
from flocks.security.integrations.sync_profiles import SyncProfile, SyncProfileCreate, SyncProfileUpdate
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

SYNC_PROFILE_PREFIX = "security/sync_profiles/"
SYNC_PROFILE_STORAGE_TYPE = "security.sync_profiles"
_SECRET_VALUE_HINTS = ("api_key=", "apikey=", "secret=", "token=", "password=", "authorization:", "bearer ", "cookie:")


class SyncProfileStore:
    """Persist Sync Profile metadata without executing sync behavior."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()

    async def create_profile(self, payload: SyncProfileCreate) -> SyncProfile:
        errors = validate_sync_profile_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        now = utc_now()
        profile = SyncProfile(
            sync_profile_id=f"syncprof_{uuid4().hex}",
            package_id=payload.package_id,
            capability=payload.capability,
            display_name=payload.display_name.strip(),
            instance_id=payload.instance_id,
            enabled=payload.enabled,
            schedule=dict(payload.schedule),
            default_params=dict(payload.default_params),
            cursor_ref=payload.cursor_ref,
            status="enabled" if payload.enabled else "draft",
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        await Storage.set(_profile_key(profile.sync_profile_id), profile, SYNC_PROFILE_STORAGE_TYPE)
        return profile

    async def get_profile(self, profile_id: str) -> SyncProfile | None:
        return await Storage.get(_profile_key(profile_id), SyncProfile)

    async def list_profiles(self, package_id: str | None = None, enabled: bool | None = None) -> list[SyncProfile]:
        entries = await Storage.list_entries(SYNC_PROFILE_PREFIX, SyncProfile)
        profiles = [value for _, value in entries]
        if package_id is not None:
            profiles = [profile for profile in profiles if profile.package_id == package_id]
        if enabled is not None:
            profiles = [profile for profile in profiles if profile.enabled is enabled]
        return sorted(profiles, key=lambda profile: profile.created_at)

    async def update_profile(self, profile_id: str, payload: SyncProfileUpdate) -> SyncProfile | None:
        current = await self.get_profile(profile_id)
        if current is None:
            return None
        errors = validate_sync_profile_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        data = current.model_dump(mode="json")
        updates = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        for key in {"package_id", "capability", "display_name", "instance_id", "enabled", "schedule", "default_params", "cursor_ref", "status", "metadata"}:
            if key in updates:
                data[key] = updates[key]
        if isinstance(data.get("display_name"), str):
            data["display_name"] = data["display_name"].strip()
        data["updated_at"] = utc_now()
        updated = SyncProfile(**data)
        await Storage.set(_profile_key(profile_id), updated, SYNC_PROFILE_STORAGE_TYPE)
        return updated

    async def delete_profile(self, profile_id: str) -> bool:
        return await Storage.delete(_profile_key(profile_id))


def validate_sync_profile_payload(payload: SyncProfileCreate | SyncProfileUpdate, registry: IntegrationRegistry | None = None) -> list[str]:
    registry = registry or create_default_integration_registry()
    errors: list[str] = []
    package_id = getattr(payload, "package_id", None)
    capability = getattr(payload, "capability", None)
    if package_id is not None:
        package = registry.get_package(package_id)
        if package is None:
            errors.append(f"Unknown integration package: {package_id}")
        elif capability is not None and capability not in package.capabilities:
            errors.append(f"Unknown integration capability for {package_id}: {capability}")
    display_name = getattr(payload, "display_name", None)
    if display_name is not None and not display_name.strip():
        errors.append("display_name is required")
    for attr in ("schedule", "default_params", "metadata"):
        value = getattr(payload, attr, None)
        if value is not None:
            errors.extend(_validate_safe_metadata(attr, value))
    return errors


def _validate_safe_metadata(label: str, metadata: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if any(keyword in lowered for keyword in SENSITIVE_PARAM_KEYWORDS):
                    errors.append(f"{label} contains secret-like key: {path}{key}")
                visit(item, f"{path}{key}.")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}{index}.")
        elif isinstance(value, str) and any(hint in value.lower() for hint in _SECRET_VALUE_HINTS):
            errors.append(f"{label} contains obvious secret-like value: {path.rstrip('.') or label}")

    visit(metadata, "")
    return errors


def _profile_key(profile_id: str) -> str:
    return f"{SYNC_PROFILE_PREFIX}{profile_id}"


default_sync_profile_store = SyncProfileStore()
