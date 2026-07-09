"""Integration Instance skeleton for Integration Runtime v2.

This module models configured Integration instances and converts an instance
into a dry-run capability request. It does not resolve credentials, perform
HTTP requests, call v1 connectors, persist raw responses, or create Security
objects.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import IntegrationCapabilityRunRequest, sanitize_run_params


class _InstanceBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class IntegrationInstanceCreate(_InstanceBaseModel):
    """Request model for creating an Integration Instance."""

    package_id: str
    name: str
    instance_id: str | None = None
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str | None = None
    allowed_capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstanceUpdate(_InstanceBaseModel):
    """Request model for updating safe Integration Instance metadata."""

    name: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    credential_ref: str | None = None
    allowed_capabilities: list[str] | None = None
    metadata: dict[str, Any] | None = None


class IntegrationInstance(_InstanceBaseModel):
    """Stored Integration Instance metadata without credential values."""

    instance_id: str
    package_id: str
    name: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str | None = None
    allowed_capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str

    def safe_summary(self) -> dict[str, Any]:
        """Return a credential-safe summary for plans, APIs, and tests."""

        return {
            "instance_id": self.instance_id,
            "package_id": self.package_id,
            "name": self.name,
            "enabled": self.enabled,
            "config": sanitize_run_params(self.config),
            "credential_ref": self.credential_ref,
            "allowed_capabilities": list(self.allowed_capabilities),
            "metadata": sanitize_run_params(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class IntegrationInstanceStore:
    """In-memory Integration Instance store skeleton."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()
        self._instances: dict[str, IntegrationInstance] = {}

    def create_instance(self, request: IntegrationInstanceCreate) -> IntegrationInstance:
        self._validate_package_and_capabilities(request.package_id, request.allowed_capabilities)
        instance_id = request.instance_id or f"int-{uuid4().hex[:12]}"
        if instance_id in self._instances:
            raise ValueError(f"duplicate integration instance: {instance_id}")
        now = _utc_now()
        instance = IntegrationInstance(
            instance_id=instance_id,
            package_id=request.package_id,
            name=request.name,
            enabled=request.enabled,
            config=deepcopy(request.config),
            credential_ref=request.credential_ref,
            allowed_capabilities=list(request.allowed_capabilities),
            metadata=deepcopy(request.metadata),
            created_at=now,
            updated_at=now,
        )
        self._instances[instance_id] = instance
        return instance

    def get_instance(self, instance_id: str) -> IntegrationInstance | None:
        return self._instances.get(instance_id)

    def require_instance(self, instance_id: str) -> IntegrationInstance:
        instance = self.get_instance(instance_id)
        if instance is None:
            raise KeyError(f"Unknown integration instance: {instance_id}")
        return instance

    def list_instances(self, package_id: str | None = None) -> list[IntegrationInstance]:
        instances = self._instances.values()
        if package_id is not None:
            instances = [instance for instance in instances if instance.package_id == package_id]
        return sorted(instances, key=lambda item: item.instance_id)

    def update_instance(self, instance_id: str, request: IntegrationInstanceUpdate) -> IntegrationInstance:
        current = self.require_instance(instance_id)
        allowed_capabilities = current.allowed_capabilities if request.allowed_capabilities is None else request.allowed_capabilities
        self._validate_package_and_capabilities(current.package_id, allowed_capabilities)
        updated = current.model_copy(
            update={
                "name": current.name if request.name is None else request.name,
                "enabled": current.enabled if request.enabled is None else request.enabled,
                "config": deepcopy(current.config if request.config is None else request.config),
                "credential_ref": current.credential_ref if request.credential_ref is None else request.credential_ref,
                "allowed_capabilities": list(allowed_capabilities),
                "metadata": deepcopy(current.metadata if request.metadata is None else request.metadata),
                "updated_at": _utc_now(),
            }
        )
        self._instances[instance_id] = updated
        return updated

    def delete_instance(self, instance_id: str) -> bool:
        return self._instances.pop(instance_id, None) is not None

    def _validate_package_and_capabilities(self, package_id: str, capabilities: list[str]) -> None:
        package = self.registry.get_package(package_id)
        if package is None:
            raise ValueError(f"Unknown integration package: {package_id}")
        unknown = sorted(set(capabilities) - set(package.capabilities))
        if unknown:
            raise ValueError(f"Unknown capability for package {package_id}: {', '.join(unknown)}")


def build_capability_run_request_from_instance(
    instance: IntegrationInstance,
    capability: str,
    *,
    params: dict[str, Any] | None = None,
    mode: str = "manual",
    requested_by: str | None = None,
    dry_run: bool = True,
) -> IntegrationCapabilityRunRequest:
    """Build a dry-run capability request from safe Integration Instance metadata."""

    if not instance.enabled:
        raise ValueError(f"Integration instance is disabled: {instance.instance_id}")
    if instance.allowed_capabilities and capability not in instance.allowed_capabilities:
        raise ValueError(f"Capability is not enabled for instance {instance.instance_id}: {capability}")
    merged_params = deepcopy(instance.config)
    merged_params.update(params or {})
    merged_params["instance_id"] = instance.instance_id
    if instance.credential_ref:
        merged_params["credential_ref"] = instance.credential_ref
    return IntegrationCapabilityRunRequest(
        package_id=instance.package_id,
        capability=capability,
        mode=mode,
        params=merged_params,
        requested_by=requested_by,
        dry_run=dry_run,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


default_integration_instance_store = IntegrationInstanceStore()
