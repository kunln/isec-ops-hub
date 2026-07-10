"""Capability Runtime v2 dry-run skeleton.

This module validates Integration Package capability requests and builds
sanitized dry-run plans only. It intentionally does not perform HTTP requests,
access credentials, call v1 connectors, persist raw responses/logs, or create
Security objects.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_PARAM_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "sign",
    "auth_timestamp",
    "authorization",
    "cookie",
)

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
DESTRUCTIVE_CAPABILITY_KEYWORDS = (
    "block",
    "unblock",
    "delete",
    "isolate",
    "quarantine",
    "disable",
    "enable_account",
    "kill",
    "remediate",
    "policy.update",
    "rule.update",
    "config.update",
)
MAX_SUMMARY_STRING_LENGTH = 256
MAX_SUMMARY_SEQUENCE_ITEMS = 20


class _RuntimeBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class IntegrationCapabilityRunRequest(_RuntimeBaseModel):
    """Request to plan or run a package capability."""

    package_id: str
    capability: str
    mode: str = "manual"
    params: dict[str, Any] = Field(default_factory=dict)
    requested_by: str | None = None
    dry_run: bool = True


class IntegrationCapabilityRunPlan(_RuntimeBaseModel):
    """Sanitized dry-run execution plan for a capability request."""

    package_id: str
    capability: str
    mode: str
    status: str
    request_summary: dict[str, Any]
    capability_summary: dict[str, Any]
    safety_summary: dict[str, Any]
    limitations: list[str]


class IntegrationCapabilityRunResult(_RuntimeBaseModel):
    """Skeleton runtime result for a capability request."""

    package_id: str
    capability: str
    mode: str
    status: str
    request_summary: dict[str, Any]
    result_summary: dict[str, Any]
    error_summary: dict[str, Any] | None
    limitations: list[str]


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SENSITIVE_PARAM_KEYWORDS)


def _is_secret_like_value(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in SECRET_LIKE_VALUE_HINTS)


def sanitize_run_params(params: dict[str, Any]) -> dict[str, Any]:
    """Return a sanitized parameter summary safe for request summaries."""

    def sanitize_value(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): (REDACTED_VALUE if _is_sensitive_key(str(key)) else sanitize_value(item)) for key, item in value.items()}
        if isinstance(value, list):
            summarized = [sanitize_value(item) for item in value[:MAX_SUMMARY_SEQUENCE_ITEMS]]
            if len(value) > MAX_SUMMARY_SEQUENCE_ITEMS:
                summarized.append({"type": "list_truncated", "length": len(value)})
            return summarized
        if isinstance(value, tuple):
            summarized = [sanitize_value(item) for item in value[:MAX_SUMMARY_SEQUENCE_ITEMS]]
            if len(value) > MAX_SUMMARY_SEQUENCE_ITEMS:
                summarized.append({"type": "tuple_truncated", "length": len(value)})
            return summarized
        if isinstance(value, bytes):
            length = len(value)
            if length > MAX_SUMMARY_STRING_LENGTH:
                return {"type": type(value).__name__, "length": length}
            return value
        if isinstance(value, str):
            if _is_secret_like_value(value):
                return REDACTED_VALUE
            length = len(value)
            if length > MAX_SUMMARY_STRING_LENGTH:
                return {"type": type(value).__name__, "length": length}
            return value
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return {"type": type(value).__name__, "length": len(value)}
        return value

    return sanitize_value(params)


def is_destructive_capability(capability: str) -> bool:
    """Return whether a capability name carries destructive semantics."""

    lowered = capability.lower()
    return any(keyword in lowered for keyword in DESTRUCTIVE_CAPABILITY_KEYWORDS)


class IntegrationCapabilityRuntime:
    """Dry-run only Capability Runtime skeleton."""

    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self.registry = registry or create_default_integration_registry()

    def validate_request(self, request: IntegrationCapabilityRunRequest) -> list[str]:
        errors: list[str] = []
        package = self.registry.get_package(request.package_id)
        if package is None:
            errors.append(f"Unknown integration package: {request.package_id}")
        elif request.capability not in package.capabilities:
            errors.append(f"Unknown capability for package {request.package_id}: {request.capability}")
        if is_destructive_capability(request.capability):
            errors.append(f"Destructive capability is rejected: {request.capability}")
        return errors

    def build_plan(self, request: IntegrationCapabilityRunRequest) -> IntegrationCapabilityRunPlan:
        errors = self.validate_request(request)
        package = self.registry.get_package(request.package_id)
        capability = package.capabilities.get(request.capability) if package else None
        status = "rejected" if is_destructive_capability(request.capability) else "validation_failed" if errors else "planned"
        return IntegrationCapabilityRunPlan(
            package_id=request.package_id,
            capability=request.capability,
            mode=request.mode,
            status=status,
            request_summary=self._request_summary(request),
            capability_summary={
                "package_id": request.package_id,
                "vendor": package.manifest.vendor if package else None,
                "product": package.manifest.product if package else None,
                "capability": request.capability,
                "display_name": capability.display_name if capability else None,
                "method": capability.method if capability else None,
                "path": capability.path if capability else None,
            },
            safety_summary=self._safety_summary(package is not None),
            limitations=self._limitations(errors),
        )

    def run(self, request: IntegrationCapabilityRunRequest) -> IntegrationCapabilityRunResult:
        plan = self.build_plan(request)
        if plan.status != "planned":
            return self._result_from_plan(plan, plan.status, {"errors": plan.limitations})
        if not request.dry_run:
            return self._result_from_plan(
                plan,
                "not_implemented",
                {"reason": "Capability execution is not implemented; this skeleton supports dry_run only."},
            )
        return self._result_from_plan(plan, "planned", None)

    def _request_summary(self, request: IntegrationCapabilityRunRequest) -> dict[str, Any]:
        return {
            "package_id": request.package_id,
            "capability": request.capability,
            "mode": request.mode,
            "requested_by": request.requested_by,
            "dry_run": request.dry_run,
            "params": sanitize_run_params(request.params),
        }

    def _safety_summary(self, package_known: bool) -> dict[str, Any]:
        return {
            "raw_response_policy": "transient_only",
            "raw_log_storage": "forbidden",
            "credential_access": "none",
            "http_requests": "disabled",
            "v1_connector_invocation": "disabled",
            "security_object_creation": "disabled",
            "package_known": package_known,
        }

    def _limitations(self, errors: list[str]) -> list[str]:
        limitations = [
            "dry-run planning only; no real HTTP requests are performed",
            "no credential access is performed",
            "no v1 connector calls are performed",
            "no Evidence, Alert, Analysis Case, Incident, or Notification is created",
            "raw API responses and raw logs are not persisted",
        ]
        return errors + limitations

    def _result_from_plan(
        self,
        plan: IntegrationCapabilityRunPlan,
        status: str,
        error_summary: dict[str, Any] | None,
    ) -> IntegrationCapabilityRunResult:
        return IntegrationCapabilityRunResult(
            package_id=plan.package_id,
            capability=plan.capability,
            mode=plan.mode,
            status=status,
            request_summary=plan.request_summary,
            result_summary={
                "planned": plan.status == "planned",
                "dry_run_only": True,
                "capability_summary": plan.capability_summary,
                "safety_summary": plan.safety_summary,
            },
            error_summary=error_summary,
            limitations=plan.limitations,
        )
