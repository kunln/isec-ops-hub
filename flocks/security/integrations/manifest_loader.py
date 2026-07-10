"""Declarative Integration Package manifest loader skeleton.

This module loads static Integration Package metadata only. It intentionally
avoids connector imports, HTTP, credential access, sync execution, security
object creation, mapping execution, and raw response persistence.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from flocks.security.integrations.models import (
    IntegrationCapability,
    IntegrationPackage,
    IntegrationPackageManifest,
)

_REQUIRED_MANIFEST_FIELDS = ("package_id", "name", "vendor", "product", "version", "category")
_REQUIRED_CAPABILITY_FIELDS = ("capability", "display_name", "method", "path")
_FORBIDDEN_RAW_LOG_STORAGE = {"enabled", "full_raw", "store_raw", "persist_raw"}
_FORBIDDEN_RAW_RESPONSE_POLICIES = {"persist_full_response", "store_raw"}
_JSON_SUFFIXES = {".json"}
_YAML_SUFFIXES = {".yaml", ".yml"}


def normalize_manifest_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Return a manifest copy with safe skeleton defaults applied."""

    normalized = dict(data)
    normalized.setdefault("raw_response_policy", "transient_only")
    normalized.setdefault("raw_log_storage", "forbidden")
    normalized.setdefault("sensitive_fields", [])
    normalized.setdefault("auth_type", "none")
    return normalized


def validate_manifest_dict(data: dict[str, Any]) -> list[str]:
    """Validate declarative manifest data without executing runtime behavior."""

    normalized = normalize_manifest_dict(data)
    errors: list[str] = []

    for field_name in _REQUIRED_MANIFEST_FIELDS:
        value = normalized.get(field_name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field_name} is required")

    capabilities = normalized.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        errors.append("capabilities must be a non-empty list")
        capabilities = []

    for index, capability in enumerate(capabilities):
        prefix = f"capabilities[{index}]"
        if not isinstance(capability, dict):
            errors.append(f"{prefix} must be an object")
            continue
        for field_name in _REQUIRED_CAPABILITY_FIELDS:
            value = capability.get(field_name)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{prefix}.{field_name} is required")

    raw_log_storage = normalized.get("raw_log_storage")
    if raw_log_storage in _FORBIDDEN_RAW_LOG_STORAGE:
        errors.append(f"raw_log_storage must not be {raw_log_storage}")
    elif raw_log_storage != "forbidden":
        errors.append("raw_log_storage must be forbidden")

    raw_response_policy = normalized.get("raw_response_policy")
    if raw_response_policy in _FORBIDDEN_RAW_RESPONSE_POLICIES:
        errors.append(f"raw_response_policy must not be {raw_response_policy}")
    elif raw_response_policy != "transient_only":
        errors.append("raw_response_policy must be transient_only")

    sensitive_fields = normalized.get("sensitive_fields")
    if not isinstance(sensitive_fields, list):
        errors.append("sensitive_fields must be a list")

    return errors


def load_manifest_dict(data: dict[str, Any]) -> IntegrationPackageManifest:
    """Load an IntegrationPackageManifest from declarative metadata."""

    normalized = normalize_manifest_dict(data)
    errors = validate_manifest_dict(normalized)
    if errors:
        raise ValueError("Invalid integration manifest: " + "; ".join(errors))

    return IntegrationPackageManifest(
        package_id=normalized["package_id"],
        name=normalized["name"],
        vendor=normalized["vendor"],
        product=normalized["product"],
        version=normalized["version"],
        category=normalized["category"],
        description=normalized.get("description"),
        auth_type=normalized["auth_type"],
        capabilities=[item["capability"] for item in normalized["capabilities"]],
        sensitive_fields=list(normalized["sensitive_fields"]),
        raw_response_policy=normalized["raw_response_policy"],
        raw_log_storage=normalized["raw_log_storage"],
    )


def load_package_from_manifest_dict(data: dict[str, Any]) -> IntegrationPackage:
    """Load static IntegrationPackage metadata from a declarative manifest."""

    normalized = normalize_manifest_dict(data)
    manifest = load_manifest_dict(normalized)
    capabilities = {
        item["capability"]: IntegrationCapability(
            package_id=manifest.package_id,
            capability=item["capability"],
            display_name=item.get("display_name"),
            description=item.get("description"),
            method=item.get("method"),
            path=item.get("path"),
            pagination=item.get("pagination"),
            mapping=item.get("mapping"),
        )
        for item in normalized["capabilities"]
    }
    return IntegrationPackage(manifest=manifest, capabilities=capabilities)


def load_manifest_file(path: str | Path) -> IntegrationPackageManifest:
    """Load an IntegrationPackageManifest from a JSON or YAML file."""

    return load_manifest_dict(_read_manifest_file(path))


def load_package_from_manifest_file(path: str | Path) -> IntegrationPackage:
    """Load an IntegrationPackage from a JSON or YAML file."""

    return load_package_from_manifest_dict(_read_manifest_file(path))


def _read_manifest_file(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    suffix = manifest_path.suffix.lower()
    text = manifest_path.read_text(encoding="utf-8")

    if suffix in _JSON_SUFFIXES:
        data = json.loads(text)
    elif suffix in _YAML_SUFFIXES:
        data = _load_yaml(text)
    else:
        raise ValueError(f"Unsupported manifest file type: {suffix or '<none>'}")

    if not isinstance(data, dict):
        raise ValueError("Integration manifest file must contain an object")
    return data


def _load_yaml(text: str) -> Any:
    if importlib.util.find_spec("yaml") is None:
        raise ValueError("YAML manifest loading requires the optional 'yaml' module")
    yaml = importlib.import_module("yaml")
    return yaml.safe_load(text)
