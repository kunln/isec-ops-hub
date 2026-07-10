"""Sync Profile metadata store.

The store persists synchronization metadata, parameters, cursor references, and
schedule strings only. It never executes sync, calls connectors, performs HTTP,
reads Credential Profiles or secret refs, dispatches evidence, or creates
Security objects.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.integrations.instance_store import default_integration_instance_store
from flocks.security.integrations.instances import IntegrationInstance
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import SECRET_LIKE_VALUE_HINTS, SENSITIVE_PARAM_KEYWORDS
from flocks.security.integrations.sync_profiles import SyncProfile, SyncProfileCreate, SyncProfileUpdate
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

SYNC_PROFILE_PREFIX = "security/sync_profiles/"
SYNC_PROFILE_STORAGE_TYPE = "security.sync_profiles"


class SyncProfileStore:
    """Storage-backed Sync Profile metadata store."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()

    async def create_profile(self, payload: SyncProfileCreate) -> SyncProfile:
        errors = await self.validate_profile_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        instance = await default_integration_instance_store.get_instance(payload.instance_id)
        if instance is None:  # Defensive: validation already checked this.
            raise ValueError(f"Unknown integration instance: {payload.instance_id}")
        now = utc_now()
        profile = SyncProfile(
            sync_profile_id=f"syncprof_{uuid4().hex}",
            display_name=payload.display_name.strip(),
            instance_id=payload.instance_id,
            package_id=instance.package_id,
            capability=payload.capability,
            mode=payload.mode,
            enabled=payload.enabled,
            schedule=payload.schedule,
            cursor=dict(payload.cursor),
            params=dict(payload.params),
            deduplicate=payload.deduplicate,
            create_analysis_cases=payload.create_analysis_cases,
            run_initial_analysis=payload.run_initial_analysis,
            last_status="never_run",
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        await Storage.set(_profile_key(profile.sync_profile_id), profile, SYNC_PROFILE_STORAGE_TYPE)
        return profile

    async def get_profile(self, sync_profile_id: str) -> SyncProfile | None:
        return await Storage.get(_profile_key(sync_profile_id), SyncProfile)

    async def list_profiles(
        self,
        instance_id: str | None = None,
        package_id: str | None = None,
        capability: str | None = None,
        enabled: bool | None = None,
    ) -> list[SyncProfile]:
        entries = await Storage.list_entries(SYNC_PROFILE_PREFIX, SyncProfile)
        return _filter_and_sort(
            [value for _, value in entries],
            instance_id=instance_id,
            package_id=package_id,
            capability=capability,
            enabled=enabled,
        )

    async def update_profile(self, sync_profile_id: str, payload: SyncProfileUpdate) -> SyncProfile | None:
        current = await self.get_profile(sync_profile_id)
        if current is None:
            return None
        errors = await self.validate_profile_payload(payload, current=current)
        if errors:
            raise ValueError("; ".join(errors))
        updated = _apply_update(current, payload)
        await Storage.set(_profile_key(sync_profile_id), updated, SYNC_PROFILE_STORAGE_TYPE)
        return updated


    async def update_profile_run_state(
        self,
        sync_profile_id: str,
        *,
        last_run_id: str,
        last_status: str,
        last_synced_at: str,
        cursor: dict[str, Any] | None = None,
    ) -> SyncProfile | None:
        current = await self.get_profile(sync_profile_id)
        if current is None:
            return None
        data = current.model_dump(mode="json")
        data["last_run_id"] = last_run_id
        data["last_status"] = last_status
        data["last_synced_at"] = last_synced_at
        if cursor is not None:
            data["cursor"] = dict(cursor)
        data["updated_at"] = utc_now()
        updated = SyncProfile(**data)
        await Storage.set(_profile_key(sync_profile_id), updated, SYNC_PROFILE_STORAGE_TYPE)
        return updated

    async def delete_profile(self, sync_profile_id: str) -> bool:
        return await Storage.delete(_profile_key(sync_profile_id))

    async def validate_profile_payload(
        self, payload: SyncProfileCreate | SyncProfileUpdate, current: SyncProfile | None = None
    ) -> list[str]:
        return await validate_profile_payload(payload, self.registry, current=current)


def _profile_key(sync_profile_id: str) -> str:
    return f"{SYNC_PROFILE_PREFIX}{sync_profile_id}"


def _filter_and_sort(
    profiles: list[SyncProfile],
    instance_id: str | None = None,
    package_id: str | None = None,
    capability: str | None = None,
    enabled: bool | None = None,
) -> list[SyncProfile]:
    if instance_id is not None:
        profiles = [profile for profile in profiles if profile.instance_id == instance_id]
    if package_id is not None:
        profiles = [profile for profile in profiles if profile.package_id == package_id]
    if capability is not None:
        profiles = [profile for profile in profiles if profile.capability == capability]
    if enabled is not None:
        profiles = [profile for profile in profiles if profile.enabled is enabled]
    return sorted(profiles, key=lambda profile: profile.created_at)


def _apply_update(current: SyncProfile, payload: SyncProfileUpdate) -> SyncProfile:
    data = current.model_dump(mode="json")
    updates = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    allowed_fields = {
        "display_name",
        "capability",
        "mode",
        "enabled",
        "schedule",
        "cursor",
        "params",
        "deduplicate",
        "create_analysis_cases",
        "run_initial_analysis",
        "last_run_id",
        "last_status",
        "last_synced_at",
        "metadata",
    }
    for key, value in updates.items():
        if key in allowed_fields:
            data[key] = value
    if isinstance(data.get("display_name"), str):
        data["display_name"] = data["display_name"].strip()
    data["updated_at"] = utc_now()
    return SyncProfile(**data)


async def validate_profile_payload(
    payload: SyncProfileCreate | SyncProfileUpdate,
    registry: IntegrationRegistry | None = None,
    current: SyncProfile | None = None,
) -> list[str]:
    registry = registry or create_default_integration_registry()
    errors: list[str] = []
    instance: IntegrationInstance | None = None
    instance_id = getattr(payload, "instance_id", None) or (current.instance_id if current else None)
    if isinstance(payload, SyncProfileCreate):
        # Pydantic ignores extra fields by default; reject explicit package_id for API safety.
        extra = getattr(payload, "model_extra", None) or {}
        if "package_id" in extra:
            errors.append("package_id is derived from instance_id and must not be provided")
    if instance_id is not None:
        instance = await default_integration_instance_store.get_instance(instance_id)
        if instance is None:
            errors.append(f"Unknown integration instance: {instance_id}")
    display_name = getattr(payload, "display_name", None)
    if display_name is not None and not display_name.strip():
        errors.append("display_name is required")
    if isinstance(payload, SyncProfileCreate) and not payload.display_name.strip():
        errors.append("display_name is required")
    capability = getattr(payload, "capability", None) or (current.capability if current else None)
    if instance is not None and capability is not None:
        package = registry.get_package(instance.package_id)
        if package is None:
            errors.append(f"Unknown integration package: {instance.package_id}")
        elif capability not in package.capabilities:
            errors.append(f"Unknown capability for package {instance.package_id}: {capability}")
    for attr in ("params", "cursor", "metadata"):
        value = getattr(payload, attr, None)
        if value is not None:
            errors.extend(_validate_no_secret_like_data(attr, value))
    return errors


def _validate_no_secret_like_data(attr: str, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if any(keyword in lowered for keyword in SENSITIVE_PARAM_KEYWORDS):
                    errors.append(f"{attr} contains secret-like key: {path}{key}")
                visit(item, f"{path}{key}.")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}{index}.")
        elif isinstance(value, str) and _looks_like_secret_value(value):
            errors.append(f"{attr} contains obvious secret-like value: {path.rstrip('.') or attr}")

    visit(data, "")
    return errors


def _looks_like_secret_value(value: str) -> bool:
    return any(hint in value.lower() for hint in SECRET_LIKE_VALUE_HINTS)


default_sync_profile_store = SyncProfileStore()
