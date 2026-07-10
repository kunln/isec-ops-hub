"""Lightweight models for Integration Runtime v2 package metadata."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _IntegrationBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class IntegrationPackageManifest(_IntegrationBaseModel):
    """Static Integration Package manifest metadata.

    This skeleton intentionally models package and capability metadata only. It
    does not hold credentials, raw API responses, raw logs, schedules, or any
    runtime connector behavior.
    """

    package_id: str
    name: str
    vendor: str
    product: str
    version: str
    category: str
    description: str | None = None
    auth_type: str
    capabilities: list[str] = Field(default_factory=list)
    sensitive_fields: list[str] = Field(default_factory=list)
    raw_response_policy: str
    raw_log_storage: str


class IntegrationCapability(_IntegrationBaseModel):
    """Static capability metadata for an Integration Package."""

    package_id: str
    capability: str
    display_name: str | None = None
    description: str | None = None
    method: str | None = None
    path: str | None = None
    pagination: dict[str, Any] | str | None = None
    mapping: dict[str, Any] | str | None = None


class IntegrationPackage(_IntegrationBaseModel):
    """Integration Package metadata plus its declared capabilities."""

    manifest: IntegrationPackageManifest
    capabilities: dict[str, IntegrationCapability] = Field(default_factory=dict)
