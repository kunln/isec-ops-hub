"""In-process Integration Package Registry skeleton.

The current PR implements the built-in registry skeleton described by Phase 2
of docs/integration-runtime-v2.md. Full manifest.yaml / capabilities.yaml
loading is intentionally deferred to a later PR so this layer introduces no
runtime connector, credential, synchronization, or raw-log storage behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path

from flocks.security.integrations.models import IntegrationCapability, IntegrationPackage

_ALLOWED_RAW_RESPONSE_POLICIES = {"transient_only"}
_ALLOWED_RAW_LOG_STORAGE = {"forbidden"}
_CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_SECRET_VALUE_HINTS = ("secret=", "token=", "password=", "apikey=", "api_key=")


@dataclass
class IntegrationRegistry:
    """Registry for static Integration Package and capability metadata."""

    _packages: dict[str, IntegrationPackage] = field(default_factory=dict)

    def register_package(self, package: IntegrationPackage) -> None:
        errors = self.validate_package(package)
        package_id = package.manifest.package_id
        if package_id in self._packages:
            errors.append(f"duplicate package_id: {package_id}")
        if errors:
            raise ValueError("Invalid integration package: " + "; ".join(errors))
        self._packages[package_id] = package

    def get_package(self, package_id: str) -> IntegrationPackage | None:
        return self._packages.get(package_id)

    def require_package(self, package_id: str) -> IntegrationPackage:
        package = self.get_package(package_id)
        if package is None:
            raise KeyError(f"Unknown integration package: {package_id}")
        return package

    def list_packages(self) -> list[IntegrationPackage]:
        return sorted(self._packages.values(), key=lambda item: item.manifest.package_id)

    def list_capabilities(self, package_id: str | None = None) -> list[IntegrationCapability]:
        packages = [self.require_package(package_id)] if package_id is not None else self.list_packages()
        capabilities: list[IntegrationCapability] = []
        for package in packages:
            capabilities.extend(sorted(package.capabilities.values(), key=lambda item: item.capability))
        return capabilities

    def find_packages_by_capability(self, capability: str) -> list[IntegrationPackage]:
        return [package for package in self.list_packages() if capability in package.capabilities]

    def validate_package(self, package: IntegrationPackage) -> list[str]:
        errors: list[str] = []
        manifest = package.manifest
        if not manifest.package_id.strip():
            errors.append("package_id is required")
        for field_name in ("vendor", "product", "name", "version"):
            if not getattr(manifest, field_name).strip():
                errors.append(f"{field_name} is required")
        if not manifest.capabilities:
            errors.append("capabilities are required")
        if manifest.raw_response_policy not in _ALLOWED_RAW_RESPONSE_POLICIES:
            errors.append("raw_response_policy must be transient_only")
        if manifest.raw_log_storage not in _ALLOWED_RAW_LOG_STORAGE:
            errors.append("raw_log_storage must be forbidden")

        seen: set[str] = set()
        for capability_name in manifest.capabilities:
            if capability_name in seen:
                errors.append(f"duplicate capability in manifest: {capability_name}")
            seen.add(capability_name)
            if not _CAPABILITY_PATTERN.match(capability_name):
                errors.append(f"capability should use dot notation: {capability_name}")
            capability = package.capabilities.get(capability_name)
            if capability is None:
                errors.append(f"missing capability metadata: {capability_name}")
                continue
            if capability.package_id != manifest.package_id:
                errors.append(f"capability package_id mismatch: {capability_name}")
            if capability.capability != capability_name:
                errors.append(f"capability name mismatch: {capability_name}")

        extra_capabilities = set(package.capabilities) - set(manifest.capabilities)
        for capability_name in sorted(extra_capabilities):
            errors.append(f"capability metadata not declared in manifest: {capability_name}")

        for sensitive_field in manifest.sensitive_fields:
            if not sensitive_field.strip():
                errors.append("sensitive_fields must contain field names")
            lowered = sensitive_field.lower()
            if any(hint in lowered for hint in _SECRET_VALUE_HINTS):
                errors.append(f"sensitive_fields must not contain secret values: {sensitive_field}")
        return errors


def create_default_integration_registry() -> IntegrationRegistry:
    """Create a registry populated with built-in Integration Packages."""

    from flocks.security.integrations.builtin import get_builtin_integration_packages

    registry = IntegrationRegistry()
    for package in get_builtin_integration_packages():
        registry.register_package(package)
    return registry


def register_manifest_dict(registry: IntegrationRegistry, data: dict[str, object]) -> IntegrationPackage:
    """Load a manifest dictionary and register the resulting package."""

    from flocks.security.integrations.manifest_loader import load_package_from_manifest_dict

    package = load_package_from_manifest_dict(data)
    registry.register_package(package)
    return package


def register_manifest_file(registry: IntegrationRegistry, path: str | Path) -> IntegrationPackage:
    """Load a manifest file and register the resulting package."""

    from flocks.security.integrations.manifest_loader import load_package_from_manifest_file

    package = load_package_from_manifest_file(path)
    registry.register_package(package)
    return package
