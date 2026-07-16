"""Adapter Registry skeleton for Integration Runtime v2.

This module maps ``package_id + capability`` to an ``IntegrationAdapter``
factory. It is metadata-only and resolver-only: resolving an adapter may
instantiate the registered factory, but it never runs adapter capabilities,
connectors, HTTP, credential resolution, mappings, evidence dispatch, Security
object creation, notification sending, or remediation.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from flocks.security.integrations.adapter import FakeIntegrationAdapter, IntegrationAdapter, sanitize_adapter_mapping

AdapterFactory = Callable[[], IntegrationAdapter]


class AdapterRegistryEntry(BaseModel):
    """Metadata-only registry entry for an adapter factory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_id: str
    capability: str
    adapter_id: str
    factory_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("package_id", "capability", "adapter_id")
    @classmethod
    def _require_explicit_string(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("adapter registry identifiers must be non-empty strings")
        return value

    @field_validator("metadata", mode="before")
    @classmethod
    def _sanitize_metadata(cls, value: Any) -> dict[str, Any]:
        sanitized = sanitize_adapter_mapping(value if isinstance(value, dict) else {})
        return sanitized if isinstance(sanitized, dict) else {}


class AdapterRegistry:
    """Resolver-only registry for IntegrationAdapter factories."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], AdapterRegistryEntry] = {}
        self._factories: dict[tuple[str, str], AdapterFactory] = {}

    @staticmethod
    def _key(package_id: str, capability: str) -> tuple[str, str]:
        if not isinstance(package_id, str) or not package_id.strip():
            raise ValueError("package_id must be a non-empty string")
        if not isinstance(capability, str) or not capability.strip():
            raise ValueError("capability must be a non-empty string")
        return package_id, capability

    def register_adapter_factory(
        self,
        package_id: str,
        capability: str,
        factory: AdapterFactory,
        *,
        adapter_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AdapterRegistryEntry:
        """Register a factory without storing credentials, raw data, or the callable in the entry."""

        if not callable(factory):
            raise ValueError("factory must be callable")
        key = self._key(package_id, capability)
        resolved_adapter_id = adapter_id or f"{package_id}.{capability}.adapter"
        entry = AdapterRegistryEntry(
            package_id=package_id,
            capability=capability,
            adapter_id=resolved_adapter_id,
            factory_name=getattr(factory, "__name__", None),
            metadata=metadata or {},
        )
        self._entries[key] = entry
        self._factories[key] = factory
        return entry

    def get_adapter(self, package_id: str, capability: str) -> IntegrationAdapter | None:
        """Instantiate the registered adapter factory without running any capability."""

        factory = self._factories.get(self._key(package_id, capability))
        if factory is None:
            return None
        return factory()

    def require_adapter(self, package_id: str, capability: str) -> IntegrationAdapter:
        """Return a registered adapter or raise a clear resolver error."""

        adapter = self.get_adapter(package_id, capability)
        if adapter is None:
            raise ValueError(f"No adapter registered for package_id={package_id!r} capability={capability!r}")
        return adapter

    def has_adapter(self, package_id: str, capability: str) -> bool:
        return self._key(package_id, capability) in self._factories

    def list_adapters(self, package_id: str | None = None) -> list[AdapterRegistryEntry]:
        if package_id is not None and (not isinstance(package_id, str) or not package_id.strip()):
            raise ValueError("package_id must be a non-empty string")
        entries = self._entries.values()
        if package_id is not None:
            entries = [entry for entry in entries if entry.package_id == package_id]
        return sorted(entries, key=lambda entry: (entry.package_id, entry.capability))

    def clear(self) -> None:
        self._entries.clear()
        self._factories.clear()


def create_default_adapter_registry(*, include_fake: bool = True) -> AdapterRegistry:
    """Create the Runtime v2 registry with real device adapters and an optional fake."""

    registry = AdapterRegistry()
    register_device_runtime_adapters(registry)
    if include_fake:
        registry.register_adapter_factory(
            "fake.integration",
            "alert.search",
            lambda: FakeIntegrationAdapter("fake.integration", {"alert.search"}),
            adapter_id="fake.integration.adapter",
            metadata={"test_only": True},
        )
    return registry


def register_device_runtime_adapters(registry: AdapterRegistry) -> AdapterRegistryEntry:
    """Register the bounded Device Integration-backed TDA alert adapter."""

    from flocks.security.integrations.device_runtime_adapter import DeviceIntegrationRuntimeAdapter

    return registry.register_adapter_factory(
        "asiainfo.tda",
        "alert.search",
        DeviceIntegrationRuntimeAdapter,
        adapter_id=DeviceIntegrationRuntimeAdapter.adapter_id,
        metadata={"source": "device_integration_bridge", "normalized_only": True},
    )


default_adapter_registry = create_default_adapter_registry(include_fake=False)
