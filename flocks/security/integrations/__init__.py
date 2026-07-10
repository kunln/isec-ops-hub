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
from flocks.security.integrations.evidence_dispatcher import (
    EvidenceDispatchRequest,
    EvidenceDispatchResult,
    dispatch_evidence_events,
    preview_evidence_events,
)
from flocks.security.integrations.credential_store import CredentialProfileStore, default_credential_profile_store, resolve_credential_profile_ref
from flocks.security.integrations.credentials import CredentialProfile, CredentialProfileCreate, CredentialProfileUpdate
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
    "EvidenceEventMappingResult",
    "MappingRule",
    "MINGYU_RISK_MAPPING",
    "TDA_ALERT_MAPPING",
    "apply_mapping",
    "build_payload_hash",
    "collect_values",
    "drop_sensitive_fields",
    "filter_key_fields",
    "first_of",
    "get_path",
    "normalize_severity",
    "EvidenceDispatchRequest",
    "EvidenceDispatchResult",
    "dispatch_evidence_events",
    "preview_evidence_events",
    "CredentialProfile",
    "CredentialProfileCreate",
    "CredentialProfileStore",
    "CredentialProfileUpdate",
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
    "default_credential_profile_store",
    "default_integration_instance_store",
    "get_builtin_integration_packages",
    "is_destructive_capability",
    "resolve_credential_profile_ref",
    "sanitize_run_params",
]
