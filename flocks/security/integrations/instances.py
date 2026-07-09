"""Integration Instance metadata skeleton.

This module stores instance metadata only. It intentionally does not store
credential values, test connections, run sync, call v1 connectors, perform
HTTP requests, or create Security objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.runtime import IntegrationCapabilityRunRequest, SENSITIVE_PARAM_KEYWORDS

SECRET_LIKE_VALUE_HINTS = (
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


class _InstanceBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class IntegrationInstance(_InstanceBaseModel):
    """Configured Integration Package instance metadata."""

    instance_id: str
    package_id: str
    vendor: str | None = None
    product: str | None = None
    display_name: str
    environment: str = "default"
    base_url: str | None = None
    credential_profile_id: str | None = None
    verify_ssl: bool = False
    enabled: bool = True
    health_status: str = "unknown"
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstanceCreate(_InstanceBaseModel):
    """Create payload for instance metadata.

    credential_profile_id is only a reference; credential values are not part
    of this model.
    """

    package_id: str
    display_name: str
    environment: str = "default"
    base_url: str | None = None
    credential_profile_id: str | None = None
    verify_ssl: bool = False
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstanceUpdate(_InstanceBaseModel):
    """Patch payload for instance metadata."""

    display_name: str | None = None
    environment: str | None = None
    base_url: str | None = None
    credential_profile_id: str | None = None
    verify_ssl: bool | None = None
    enabled: bool | None = None
    health_status: str | None = None
    metadata: dict[str, Any] | None = None


def build_capability_run_request_from_instance(
    instance: IntegrationInstance,
    capability: str,
    params: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> IntegrationCapabilityRunRequest:
    """Build a dry-run capability request from safe instance metadata.

    The instance store rejects secret-like metadata keys, so only safe metadata
    is merged with caller-supplied params. Caller params win and are sanitized by
    the runtime summary path when planned or run.
    """

    merged_params = _drop_secret_like_params(instance.metadata)
    if params:
        merged_params.update(_drop_secret_like_params(params))
    return IntegrationCapabilityRunRequest(
        package_id=instance.package_id,
        capability=capability,
        params=merged_params,
        dry_run=dry_run,
    )


_DROP_VALUE = object()


def _drop_secret_like_params(params: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in params.items():
        if any(keyword in str(key).lower() for keyword in SENSITIVE_PARAM_KEYWORDS):
            continue
        sanitized = _drop_secret_like_value(value)
        if sanitized is _DROP_VALUE:
            continue
        safe[str(key)] = sanitized
    return safe


def _drop_secret_like_value(value: Any) -> Any:
    if isinstance(value, str) and _is_secret_like_value(value):
        return _DROP_VALUE
    if isinstance(value, dict):
        return _drop_secret_like_params(value)
    if isinstance(value, list):
        safe_items = []
        for item in value:
            sanitized = _drop_secret_like_value(item)
            if sanitized is not _DROP_VALUE:
                safe_items.append(sanitized)
        return safe_items
    return value


def _is_secret_like_value(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in SECRET_LIKE_VALUE_HINTS)
