"""Integration Runtime v2 package registry skeleton."""

from flocks.security.integrations.builtin import get_builtin_integration_packages
from flocks.security.integrations.models import (
    IntegrationCapability,
    IntegrationPackage,
    IntegrationPackageManifest,
)
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.runtime import (
    IntegrationCapabilityRunPlan,
    IntegrationCapabilityRunRequest,
    IntegrationCapabilityRunResult,
    IntegrationCapabilityRuntime,
    is_destructive_capability,
    sanitize_run_params,
)

__all__ = [
    "IntegrationCapability",
    "IntegrationPackage",
    "IntegrationPackageManifest",
    "IntegrationRegistry",
    "IntegrationCapabilityRunPlan",
    "IntegrationCapabilityRunRequest",
    "IntegrationCapabilityRunResult",
    "IntegrationCapabilityRuntime",
    "create_default_integration_registry",
    "get_builtin_integration_packages",
    "is_destructive_capability",
    "sanitize_run_params",
]
