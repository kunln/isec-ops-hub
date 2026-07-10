"""Credential Profile metadata store.

The store persists credential metadata, configured field names, and future
secret_ref pointers only. It never stores credential values, resolves secrets,
tests credentials, calls connectors, performs HTTP requests, syncs data, or
creates Security objects.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.integrations.credentials import CredentialProfile, CredentialProfileCreate, CredentialProfileUpdate
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import SENSITIVE_PARAM_KEYWORDS
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

CREDENTIAL_PROFILE_PREFIX = "security/credential_profiles/"
CREDENTIAL_PROFILE_STORAGE_TYPE = "security.credential_profiles"

_SECRET_VALUE_HINTS = (
    "api_key=",
    "apikey=",
    "secret=",
    "token=",
    "password=",
    "authorization:",
    "bearer ",
    "cookie:",
    "session=",
    "x-api-key",
    "x-flocks-api-token",
)
_FIELD_VALUE_HINTS = ("=", ":", "bearer ")


class CredentialProfileStore:
    """Storage-backed Credential Profile metadata store."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()

    async def create_profile(self, payload: CredentialProfileCreate) -> CredentialProfile:
        errors = validate_profile_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        now = utc_now()
        profile = CredentialProfile(
            credential_profile_id=f"credprof_{uuid4().hex}",
            display_name=payload.display_name.strip(),
            profile_type=payload.profile_type,
            package_id=payload.package_id,
            instance_id=payload.instance_id,
            secret_ref=payload.secret_ref,
            required_fields=list(payload.required_fields),
            configured_fields=list(payload.configured_fields),
            expires_at=payload.expires_at,
            status="unknown",
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        await Storage.set(_profile_key(profile.credential_profile_id), profile, CREDENTIAL_PROFILE_STORAGE_TYPE)
        return profile

    async def get_profile(self, profile_id: str) -> CredentialProfile | None:
        return await Storage.get(_profile_key(profile_id), CredentialProfile)

    async def list_profiles(
        self, package_id: str | None = None, instance_id: str | None = None, status: str | None = None
    ) -> list[CredentialProfile]:
        entries = await Storage.list_entries(CREDENTIAL_PROFILE_PREFIX, CredentialProfile)
        return _filter_and_sort([value for _, value in entries], package_id=package_id, instance_id=instance_id, status=status)

    async def update_profile(self, profile_id: str, payload: CredentialProfileUpdate) -> CredentialProfile | None:
        current = await self.get_profile(profile_id)
        if current is None:
            return None
        errors = validate_profile_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        updated = _apply_update(current, payload)
        await Storage.set(_profile_key(profile_id), updated, CREDENTIAL_PROFILE_STORAGE_TYPE)
        return updated

    async def delete_profile(self, profile_id: str) -> bool:
        return await Storage.delete(_profile_key(profile_id))

    def validate_profile_payload(self, payload: CredentialProfileCreate | CredentialProfileUpdate) -> list[str]:
        return validate_profile_payload(payload, self.registry)


async def resolve_credential_profile_ref(profile_id: str) -> CredentialProfile | None:
    """Resolve Credential Profile metadata by id without returning credential values."""

    return await default_credential_profile_store.get_profile(profile_id)


def _profile_key(profile_id: str) -> str:
    return f"{CREDENTIAL_PROFILE_PREFIX}{profile_id}"


def _filter_and_sort(
    profiles: list[CredentialProfile], package_id: str | None = None, instance_id: str | None = None, status: str | None = None
) -> list[CredentialProfile]:
    if package_id is not None:
        profiles = [profile for profile in profiles if profile.package_id == package_id]
    if instance_id is not None:
        profiles = [profile for profile in profiles if profile.instance_id == instance_id]
    if status is not None:
        profiles = [profile for profile in profiles if profile.status == status]
    return sorted(profiles, key=lambda profile: profile.created_at)


def _apply_update(current: CredentialProfile, payload: CredentialProfileUpdate) -> CredentialProfile:
    data = current.model_dump(mode="json")
    updates = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    allowed_fields = {
        "display_name",
        "profile_type",
        "package_id",
        "instance_id",
        "secret_ref",
        "required_fields",
        "configured_fields",
        "expires_at",
        "status",
        "metadata",
    }
    for key, value in updates.items():
        if key in allowed_fields:
            data[key] = value
    if isinstance(data.get("display_name"), str):
        data["display_name"] = data["display_name"].strip()
    data["updated_at"] = utc_now()
    return CredentialProfile(**data)


def validate_profile_payload(
    payload: CredentialProfileCreate | CredentialProfileUpdate, registry: IntegrationRegistry | None = None
) -> list[str]:
    registry = registry or create_default_integration_registry()
    errors: list[str] = []
    package_id = getattr(payload, "package_id", None)
    if package_id is not None and registry.get_package(package_id) is None:
        errors.append(f"Unknown integration package: {package_id}")
    display_name = getattr(payload, "display_name", None)
    if display_name is not None and not display_name.strip():
        errors.append("display_name is required")
    if isinstance(payload, CredentialProfileCreate) and not payload.display_name.strip():
        errors.append("display_name is required")
    for attr in ("required_fields", "configured_fields"):
        fields = getattr(payload, attr, None)
        if fields is not None:
            errors.extend(_validate_field_names(attr, fields))
    secret_ref = getattr(payload, "secret_ref", None)
    if secret_ref is not None and _looks_like_secret_value(secret_ref):
        errors.append("secret_ref must be a reference, not a credential value")
    metadata = getattr(payload, "metadata", None)
    if metadata is not None:
        errors.extend(_validate_safe_metadata(metadata))
    return errors


def _validate_field_names(attr: str, fields: list[str]) -> list[str]:
    errors: list[str] = []
    for field in fields:
        lowered = str(field).lower().strip()
        if not lowered:
            errors.append(f"{attr} contains an empty field name")
        if any(hint in lowered for hint in _FIELD_VALUE_HINTS):
            errors.append(f"{attr} must contain field names only: {field}")
        if _looks_like_secret_value(lowered):
            errors.append(f"{attr} must not contain credential values: {field}")
    return errors


def _looks_like_secret_value(value: str) -> bool:
    lowered = str(value).lower()
    return any(hint in lowered for hint in _SECRET_VALUE_HINTS)


def _validate_safe_metadata(metadata: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if any(keyword in lowered for keyword in SENSITIVE_PARAM_KEYWORDS):
                    errors.append(f"metadata contains secret-like key: {path}{key}")
                visit(item, f"{path}{key}.")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}{index}.")
        elif isinstance(value, str) and _looks_like_secret_value(value):
            errors.append(f"metadata contains obvious secret-like value: {path.rstrip('.') or 'metadata'}")

    visit(metadata, "")
    return errors


default_credential_profile_store = CredentialProfileStore()
