"""Integration Instance metadata stores.

Persistent storage keeps Integration Instance metadata only. It intentionally
stores credential_profile_id references rather than credential values and never
performs connector calls, HTTP requests, sync, test connections, remediation, or
Security object creation.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.integrations.instances import IntegrationInstance, IntegrationInstanceCreate, IntegrationInstanceUpdate
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import SENSITIVE_PARAM_KEYWORDS
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

INTEGRATION_INSTANCE_PREFIX = "security/integration_instances/"
INTEGRATION_INSTANCE_STORAGE_TYPE = "security.integration_instances"

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


class InMemoryIntegrationInstanceStore:
    """Test-only in-memory Integration Instance metadata store."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()
        self._instances: dict[str, IntegrationInstance] = {}

    def create_instance(self, payload: IntegrationInstanceCreate) -> IntegrationInstance:
        errors = validate_instance_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        package = self.registry.require_package(payload.package_id)
        now = utc_now()
        instance = IntegrationInstance(
            instance_id=f"intinst_{uuid4().hex}",
            package_id=payload.package_id,
            vendor=package.manifest.vendor,
            product=package.manifest.product,
            display_name=payload.display_name.strip(),
            environment=payload.environment,
            base_url=payload.base_url,
            credential_profile_id=payload.credential_profile_id,
            verify_ssl=payload.verify_ssl,
            enabled=payload.enabled,
            health_status="unknown",
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        self._instances[instance.instance_id] = instance
        return instance

    def get_instance(self, instance_id: str) -> IntegrationInstance | None:
        return self._instances.get(instance_id)

    def list_instances(self, package_id: str | None = None, enabled: bool | None = None) -> list[IntegrationInstance]:
        instances = list(self._instances.values())
        return _filter_and_sort(instances, package_id=package_id, enabled=enabled)

    def update_instance(self, instance_id: str, payload: IntegrationInstanceUpdate) -> IntegrationInstance | None:
        current = self.get_instance(instance_id)
        if current is None:
            return None
        errors = validate_instance_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        updated = _apply_update(current, payload)
        self._instances[instance_id] = updated
        return updated

    def delete_instance(self, instance_id: str) -> bool:
        return self._instances.pop(instance_id, None) is not None

    def validate_instance_payload(self, payload: IntegrationInstanceCreate | IntegrationInstanceUpdate) -> list[str]:
        return validate_instance_payload(payload, self.registry)


# Backward-compatible name for existing unit tests that need a synchronous store.
IntegrationInstanceStore = InMemoryIntegrationInstanceStore


class PersistentIntegrationInstanceStore:
    """Storage-backed Integration Instance metadata store."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()

    async def create_instance(self, payload: IntegrationInstanceCreate) -> IntegrationInstance:
        errors = validate_instance_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        package = self.registry.require_package(payload.package_id)
        now = utc_now()
        instance = IntegrationInstance(
            instance_id=f"intinst_{uuid4().hex}",
            package_id=payload.package_id,
            vendor=package.manifest.vendor,
            product=package.manifest.product,
            display_name=payload.display_name.strip(),
            environment=payload.environment,
            base_url=payload.base_url,
            credential_profile_id=payload.credential_profile_id,
            verify_ssl=payload.verify_ssl,
            enabled=payload.enabled,
            health_status="unknown",
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        await Storage.set(_instance_key(instance.instance_id), instance, INTEGRATION_INSTANCE_STORAGE_TYPE)
        return instance

    async def get_instance(self, instance_id: str) -> IntegrationInstance | None:
        return await Storage.get(_instance_key(instance_id), IntegrationInstance)

    async def list_instances(self, package_id: str | None = None, enabled: bool | None = None) -> list[IntegrationInstance]:
        entries = await Storage.list_entries(INTEGRATION_INSTANCE_PREFIX, IntegrationInstance)
        return _filter_and_sort([value for _, value in entries], package_id=package_id, enabled=enabled)

    async def update_instance(self, instance_id: str, payload: IntegrationInstanceUpdate) -> IntegrationInstance | None:
        current = await self.get_instance(instance_id)
        if current is None:
            return None
        errors = validate_instance_payload(payload, self.registry)
        if errors:
            raise ValueError("; ".join(errors))
        updated = _apply_update(current, payload)
        await Storage.set(_instance_key(instance_id), updated, INTEGRATION_INSTANCE_STORAGE_TYPE)
        return updated

    async def delete_instance(self, instance_id: str) -> bool:
        return await Storage.delete(_instance_key(instance_id))

    def validate_instance_payload(self, payload: IntegrationInstanceCreate | IntegrationInstanceUpdate) -> list[str]:
        return validate_instance_payload(payload, self.registry)


def _instance_key(instance_id: str) -> str:
    return f"{INTEGRATION_INSTANCE_PREFIX}{instance_id}"


def _filter_and_sort(
    instances: list[IntegrationInstance], package_id: str | None = None, enabled: bool | None = None
) -> list[IntegrationInstance]:
    if package_id is not None:
        instances = [instance for instance in instances if instance.package_id == package_id]
    if enabled is not None:
        instances = [instance for instance in instances if instance.enabled is enabled]
    return sorted(instances, key=lambda instance: instance.created_at)


def _apply_update(current: IntegrationInstance, payload: IntegrationInstanceUpdate) -> IntegrationInstance:
    data = current.model_dump(mode="json")
    updates = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    allowed_fields = {
        "display_name",
        "environment",
        "base_url",
        "credential_profile_id",
        "verify_ssl",
        "enabled",
        "health_status",
        "metadata",
    }
    for key, value in updates.items():
        if key in allowed_fields:
            data[key] = value
    if isinstance(data.get("display_name"), str):
        data["display_name"] = data["display_name"].strip()
    data["updated_at"] = utc_now()
    return IntegrationInstance(**data)


def validate_instance_payload(
    payload: IntegrationInstanceCreate | IntegrationInstanceUpdate, registry: IntegrationRegistry | None = None
) -> list[str]:
    registry = registry or create_default_integration_registry()
    errors: list[str] = []
    package_id = getattr(payload, "package_id", None)
    if package_id is not None and registry.get_package(package_id) is None:
        errors.append(f"Unknown integration package: {package_id}")
    display_name = getattr(payload, "display_name", None)
    if display_name is not None and not display_name.strip():
        errors.append("display_name is required")
    base_url = getattr(payload, "base_url", None)
    if base_url and not (base_url.startswith("http://") or base_url.startswith("https://")):
        errors.append("base_url must start with http:// or https://")
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


default_integration_instance_store = PersistentIntegrationInstanceStore()
