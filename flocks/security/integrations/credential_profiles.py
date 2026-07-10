"""Credential Profile metadata skeleton for Integration Runtime v2.

Credential Profiles are references to externally managed credentials. This
module stores metadata only and intentionally does not store credential values,
read secrets, call connectors, perform HTTP, run sync, create Security objects,
or perform remediation.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.runtime import SENSITIVE_PARAM_KEYWORDS
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

CREDENTIAL_PROFILE_PREFIX = "security/integration_credential_profiles/"
CREDENTIAL_PROFILE_STORAGE_TYPE = "security.integration_credential_profiles"

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


class _CredentialProfileBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class CredentialProfile(_CredentialProfileBase):
    """Safe credential profile metadata without credential values."""

    profile_id: str
    package_id: str | None = None
    display_name: str
    environment: str = "default"
    secret_ref: str | None = None
    status: str = "unknown"
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialProfileCreate(_CredentialProfileBase):
    """Create payload for credential profile metadata.

    `secret_ref` is only an opaque reference; credential values are intentionally
    not part of this model.
    """

    profile_id: str | None = None
    package_id: str | None = None
    display_name: str
    environment: str = "default"
    secret_ref: str | None = None
    status: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialProfileUpdate(_CredentialProfileBase):
    """Patch payload for credential profile metadata."""

    package_id: str | None = None
    display_name: str | None = None
    environment: str | None = None
    secret_ref: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None


class InMemoryCredentialProfileStore:
    """Test-only in-memory Credential Profile metadata store."""

    def __init__(self) -> None:
        self._profiles: dict[str, CredentialProfile] = {}

    def create_profile(self, payload: CredentialProfileCreate) -> CredentialProfile:
        errors = validate_credential_profile_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        now = utc_now()
        profile = CredentialProfile(
            profile_id=payload.profile_id or f"credprof_{uuid4().hex}",
            package_id=payload.package_id,
            display_name=payload.display_name.strip(),
            environment=payload.environment,
            secret_ref=payload.secret_ref,
            status=payload.status,
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        self._profiles[profile.profile_id] = profile
        return profile

    def get_profile(self, profile_id: str) -> CredentialProfile | None:
        return self._profiles.get(profile_id)

    def list_profiles(self, package_id: str | None = None) -> list[CredentialProfile]:
        profiles = list(self._profiles.values())
        if package_id is not None:
            profiles = [profile for profile in profiles if profile.package_id == package_id]
        return sorted(profiles, key=lambda profile: profile.created_at)

    def update_profile(self, profile_id: str, payload: CredentialProfileUpdate) -> CredentialProfile | None:
        current = self.get_profile(profile_id)
        if current is None:
            return None
        errors = validate_credential_profile_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        updated = _apply_update(current, payload)
        self._profiles[profile_id] = updated
        return updated

    def delete_profile(self, profile_id: str) -> bool:
        return self._profiles.pop(profile_id, None) is not None


# Backward-compatible export requested by PR #32.
CredentialProfileStore = InMemoryCredentialProfileStore


class PersistentCredentialProfileStore:
    """Storage-backed Credential Profile metadata store."""

    async def create_profile(self, payload: CredentialProfileCreate) -> CredentialProfile:
        errors = validate_credential_profile_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        now = utc_now()
        profile = CredentialProfile(
            profile_id=payload.profile_id or f"credprof_{uuid4().hex}",
            package_id=payload.package_id,
            display_name=payload.display_name.strip(),
            environment=payload.environment,
            secret_ref=payload.secret_ref,
            status=payload.status,
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        await Storage.set(_profile_key(profile.profile_id), profile, CREDENTIAL_PROFILE_STORAGE_TYPE)
        return profile

    async def get_profile(self, profile_id: str) -> CredentialProfile | None:
        return await Storage.get(_profile_key(profile_id), CredentialProfile)

    async def list_profiles(self, package_id: str | None = None) -> list[CredentialProfile]:
        entries = await Storage.list_entries(CREDENTIAL_PROFILE_PREFIX, CredentialProfile)
        profiles = [value for _, value in entries]
        if package_id is not None:
            profiles = [profile for profile in profiles if profile.package_id == package_id]
        return sorted(profiles, key=lambda profile: profile.created_at)

    async def update_profile(self, profile_id: str, payload: CredentialProfileUpdate) -> CredentialProfile | None:
        current = await self.get_profile(profile_id)
        if current is None:
            return None
        errors = validate_credential_profile_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        updated = _apply_update(current, payload)
        await Storage.set(_profile_key(profile_id), updated, CREDENTIAL_PROFILE_STORAGE_TYPE)
        return updated

    async def delete_profile(self, profile_id: str) -> bool:
        return await Storage.delete(_profile_key(profile_id))


async def resolve_credential_profile_ref(
    profile_id: str | None,
    *,
    store: PersistentCredentialProfileStore | None = None,
) -> CredentialProfile | None:
    """Resolve a credential profile metadata reference without reading secrets."""

    if not profile_id:
        return None
    active_store = store or default_credential_profile_store
    return await active_store.get_profile(profile_id)


def _profile_key(profile_id: str) -> str:
    return f"{CREDENTIAL_PROFILE_PREFIX}{profile_id}"


def _apply_update(current: CredentialProfile, payload: CredentialProfileUpdate) -> CredentialProfile:
    data = current.model_dump(mode="json")
    updates = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    for key, value in updates.items():
        if key in {"package_id", "display_name", "environment", "secret_ref", "status", "metadata"}:
            data[key] = value
    if isinstance(data.get("display_name"), str):
        data["display_name"] = data["display_name"].strip()
    data["updated_at"] = utc_now()
    return CredentialProfile(**data)


def validate_credential_profile_payload(payload: CredentialProfileCreate | CredentialProfileUpdate) -> list[str]:
    errors: list[str] = []
    display_name = getattr(payload, "display_name", None)
    if display_name is not None and not display_name.strip():
        errors.append("display_name is required")
    metadata = getattr(payload, "metadata", None)
    if metadata is not None:
        errors.extend(_validate_safe_metadata(metadata))
    return errors


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
        elif isinstance(value, str) and any(hint in value.lower() for hint in _SECRET_VALUE_HINTS):
            errors.append(f"metadata contains obvious secret-like value: {path.rstrip('.') or 'metadata'}")

    visit(metadata, "")
    return errors


default_credential_profile_store = PersistentCredentialProfileStore()
