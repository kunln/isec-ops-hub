"""Integration Runtime v2 package registry skeleton."""

from flocks.security.integrations.builtin import get_builtin_integration_packages
from flocks.security.integrations.instance_store import IntegrationInstanceStore, default_integration_instance_store
from flocks.security.integrations.instances import (
    IntegrationInstance,
    IntegrationInstanceCreate,
    IntegrationInstanceUpdate,
    build_capability_run_request_from_instance,
)
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
    "IntegrationInstance",
    "IntegrationInstanceCreate",
    "IntegrationInstanceUpdate",
    "IntegrationInstanceStore",
    "IntegrationCapability",
    "IntegrationPackage",
    "IntegrationPackageManifest",
    "IntegrationRegistry",
    "IntegrationCapabilityRunPlan",
    "IntegrationCapabilityRunRequest",
    "IntegrationCapabilityRunResult",
    "IntegrationCapabilityRuntime",
    "build_capability_run_request_from_instance",
    "create_default_integration_registry",
    "default_integration_instance_store",
    "get_builtin_integration_packages",
    "is_destructive_capability",
    "sanitize_run_params",
]
