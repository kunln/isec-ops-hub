"""Credential Profile metadata skeleton.

Credential Profiles store safe credential metadata and future vault references only.
They intentionally do not store credential values, return secrets, test
connections, call connectors, perform HTTP requests, sync, or create Security
objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _CredentialProfileBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class CredentialProfile(_CredentialProfileBaseModel):
    """Safe Credential Profile metadata and secret reference."""

    credential_profile_id: str
    display_name: str
    profile_type: str = "api_key"
    package_id: str | None = None
    instance_id: str | None = None
    secret_ref: str | None = None
    required_fields: list[str] = Field(default_factory=list)
    configured_fields: list[str] = Field(default_factory=list)
    expires_at: str | None = None
    status: str = "unknown"
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialProfileCreate(_CredentialProfileBaseModel):
    """Create payload for Credential Profile metadata.

    configured_fields contains field names only, and secret_ref is a future
    vault reference rather than a credential value.
    """

    display_name: str
    profile_type: str = "api_key"
    package_id: str | None = None
    instance_id: str | None = None
    secret_ref: str | None = None
    required_fields: list[str] = Field(default_factory=list)
    configured_fields: list[str] = Field(default_factory=list)
    expires_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialProfileUpdate(_CredentialProfileBaseModel):
    """Patch payload for Credential Profile metadata."""

    display_name: str | None = None
    profile_type: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    secret_ref: str | None = None
    required_fields: list[str] | None = None
    configured_fields: list[str] | None = None
    expires_at: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None
