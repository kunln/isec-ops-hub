"""Declarative Integration Package manifest loader skeleton.

This module loads static Integration Package metadata only. It does not import
or call vendor connectors, perform HTTP requests, read credentials, execute
mappings, run sync, create security objects, or persist raw responses/logs.
"""

from __future__ import annotations

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


def normalize_manifest_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow-normalized manifest dict with safe defaults applied."""

    normalized = dict(data)
    normalized.setdefault("raw_response_policy", "transient_only")
    normalized.setdefault("raw_log_storage", "forbidden")
    normalized.setdefault("sensitive_fields", [])
    normalized.setdefault("auth_type", "none")
    return normalized


def validate_manifest_dict(data: dict[str, Any]) -> list[str]:
    """Validate declarative manifest metadata without executing runtime behavior."""

    normalized = normalize_manifest_dict(data)
    errors: list[str] = []
    for field_name in _REQUIRED_MANIFEST_FIELDS:
        value = normalized.get(field_name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field_name} is required")

    capabilities = normalized.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        errors.append("capabilities must be a non-empty list")
    else:
        for index, item in enumerate(capabilities):
            if not isinstance(item, dict):
                errors.append(f"capabilities[{index}] must be an object")
                continue
            for field_name in _REQUIRED_CAPABILITY_FIELDS:
                value = item.get(field_name)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"capabilities[{index}].{field_name} is required")

    sensitive_fields = normalized.get("sensitive_fields")
    if not isinstance(sensitive_fields, list):
        errors.append("sensitive_fields must be a list")

    raw_log_storage = normalized.get("raw_log_storage")
    if raw_log_storage in _FORBIDDEN_RAW_LOG_STORAGE:
        errors.append("raw_log_storage must not enable raw log persistence")
    if raw_log_storage != "forbidden":
        errors.append("raw_log_storage must be forbidden")

    raw_response_policy = normalized.get("raw_response_policy")
    if raw_response_policy in _FORBIDDEN_RAW_RESPONSE_POLICIES:
        errors.append("raw_response_policy must not persist full raw responses")
    if raw_response_policy != "transient_only":
        errors.append("raw_response_policy must be transient_only")

    return errors


def load_manifest_dict(data: dict[str, Any]) -> IntegrationPackageManifest:
    """Load and validate an IntegrationPackageManifest from a dictionary."""

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
        sensitive_fields=normalized["sensitive_fields"],
        raw_response_policy=normalized["raw_response_policy"],
        raw_log_storage=normalized["raw_log_storage"],
    )


def load_package_from_manifest_dict(data: dict[str, Any]) -> IntegrationPackage:
    """Load an IntegrationPackage from declarative manifest metadata."""

    normalized = normalize_manifest_dict(data)
    manifest = load_manifest_dict(normalized)
    return IntegrationPackage(
        manifest=manifest,
        capabilities={
            item["capability"]: IntegrationCapability(
                package_id=manifest.package_id,
                capability=item["capability"],
                display_name=item["display_name"],
                description=item.get("description"),
                method=item["method"],
                path=item["path"],
                pagination=item.get("pagination"),
                mapping=item.get("mapping"),
            )
            for item in normalized["capabilities"]
        },
    )


def _load_data_file(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    suffix = manifest_path.suffix.lower()
    if suffix == ".json":
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-untyped]
        except ModuleNotFoundError as exc:
            raise ValueError("YAML manifest loading requires the optional 'yaml' module") from exc
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"Unsupported manifest file type: {manifest_path.suffix}")
    if not isinstance(data, dict):
        raise ValueError("Integration manifest file must contain an object")
    return data


def load_manifest_file(path: str | Path) -> IntegrationPackageManifest:
    """Load and validate an IntegrationPackageManifest from JSON or optional YAML."""

    return load_manifest_dict(_load_data_file(path))


def load_package_from_manifest_file(path: str | Path) -> IntegrationPackage:
    """Load an IntegrationPackage from JSON or optional YAML manifest metadata."""

    return load_package_from_manifest_dict(_load_data_file(path))
