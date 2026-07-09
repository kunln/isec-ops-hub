"""In-memory Integration Instance metadata store skeleton."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.integrations.instances import IntegrationInstance, IntegrationInstanceCreate, IntegrationInstanceUpdate
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import SENSITIVE_PARAM_KEYWORDS
from flocks.security.store import utc_now

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


class IntegrationInstanceStore:
    """Lightweight in-memory store for Integration Instance metadata."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()
        self._instances: dict[str, IntegrationInstance] = {}

    def create_instance(self, payload: IntegrationInstanceCreate) -> IntegrationInstance:
        errors = self.validate_instance_payload(payload)
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
        if package_id is not None:
            instances = [instance for instance in instances if instance.package_id == package_id]
        if enabled is not None:
            instances = [instance for instance in instances if instance.enabled is enabled]
        return sorted(instances, key=lambda instance: instance.created_at)

    def update_instance(self, instance_id: str, payload: IntegrationInstanceUpdate) -> IntegrationInstance | None:
        current = self.get_instance(instance_id)
        if current is None:
            return None
        errors = self.validate_instance_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        data = current.model_dump(mode="json")
        data.update(payload.model_dump(mode="json", exclude_unset=True, exclude_none=True))
        if "display_name" in data and isinstance(data["display_name"], str):
            data["display_name"] = data["display_name"].strip()
        data["updated_at"] = utc_now()
        updated = IntegrationInstance(**data)
        self._instances[instance_id] = updated
        return updated

    def delete_instance(self, instance_id: str) -> bool:
        return self._instances.pop(instance_id, None) is not None

    def validate_instance_payload(self, payload: IntegrationInstanceCreate | IntegrationInstanceUpdate) -> list[str]:
        errors: list[str] = []
        package_id = getattr(payload, "package_id", None)
        if package_id is not None and self.registry.get_package(package_id) is None:
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


default_integration_instance_store = IntegrationInstanceStore()
