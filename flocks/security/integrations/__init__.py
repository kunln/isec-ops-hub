"""Integration Runtime v2 package registry skeleton."""

from flocks.security.integrations.builtin import get_builtin_integration_packages
from flocks.security.integrations.builtin_mappings import MINGYU_RISK_MAPPING, TDA_ALERT_MAPPING
from flocks.security.integrations.mapping import (
    EvidenceEventMappingResult,
    MappingRule,
    apply_mapping,
    build_payload_hash,
    collect_values,
    drop_sensitive_fields,
    filter_key_fields,
    first_of,
    get_path,
    normalize_severity,
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
    "EvidenceEventMappingResult",
    "MappingRule",
    "MINGYU_RISK_MAPPING",
    "TDA_ALERT_MAPPING",
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
    "apply_mapping",
    "build_payload_hash",
    "collect_values",
    "drop_sensitive_fields",
    "filter_key_fields",
    "first_of",
    "get_path",
    "normalize_severity",
    "sanitize_run_params",
]
