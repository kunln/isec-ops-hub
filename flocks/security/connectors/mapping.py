"""Config-driven raw-to-Flocks connector mapping engine."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any


MAPPING_CONTRACT_VERSION = "connector.mapping.v1"
_MISSING = object()


@dataclass
class MappingApplyResult:
    mapping_result: dict[str, Any]
    missing_required_fields: list[str] = field(default_factory=list)
    unmapped_fields: list[str] = field(default_factory=list)
    transform_warnings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_mapping_contract(path: Path) -> dict[str, Any]:
    contract = json.loads(path.read_text(encoding="utf-8"))
    validate_mapping_contract(contract, source=str(path))
    return contract


def validate_mapping_contract(contract: dict[str, Any], *, source: str = "mapping contract") -> None:
    version = contract.get("version")
    if version != MAPPING_CONTRACT_VERSION:
        raise ValueError(f"{source} uses unsupported mapping version: {version}")
    if not contract.get("capability"):
        raise ValueError(f"{source} is missing capability")
    if not contract.get("target"):
        raise ValueError(f"{source} is missing target")
    fields = contract.get("fields")
    if not isinstance(fields, list) or not fields:
        raise ValueError(f"{source} must define a non-empty fields list")
    for index, field_spec in enumerate(fields):
        if not isinstance(field_spec, dict):
            raise ValueError(f"{source} fields[{index}] must be an object")
        if "target" not in field_spec:
            raise ValueError(f"{source} fields[{index}] is missing target")
        if "raw" not in field_spec and "default" not in field_spec:
            raise ValueError(f"{source} fields[{index}] must define raw or default")


def build_field_mapping(contract: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for field_spec in contract.get("fields", []):
        raw_paths = _raw_paths(field_spec)
        if len(raw_paths) == 1 and raw_paths[0] != "$":
            mapping[raw_paths[0]] = str(field_spec["target"])
    return mapping


def mapping_contract_summary(contract: dict[str, Any], *, file: str | None = None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "version": contract["version"],
        "capability": contract["capability"],
        "target": contract["target"],
        "source": contract.get("source", {}),
        "required_fields": [
            field["target"]
            for field in contract.get("fields", [])
            if isinstance(field, dict) and field.get("required") is True
        ],
        "field_count": len(contract.get("fields", [])),
    }
    if file:
        summary["file"] = file
    return summary


def apply_mapping_contract(raw_response: dict[str, Any], contract: dict[str, Any], connector_id: str) -> MappingApplyResult:
    validate_mapping_contract(contract)
    target_collection = str(contract["target"])
    item_path = _item_path(contract)
    items = _items_at_path(raw_response, item_path)
    diagnostics = MappingApplyResult(mapping_result={target_collection: []})
    if items is _MISSING:
        marker = item_path or "$"
        diagnostics.warnings.append(f"Mapping item path not found: {marker}")
        return diagnostics
    if not isinstance(items, list):
        diagnostics.warnings.append(f"Mapping item path is not a list: {item_path or '$'}")
        return diagnostics

    normalized_items: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        item_marker = f"{item_path}[{index}]" if item_path else f"items[{index}]"
        if not isinstance(item, dict):
            diagnostics.transform_warnings.append(f"{item_marker}: item is not an object")
            diagnostics.warnings.append(f"Mapping skipped non-object item: {item_marker}")
            continue
        normalized, consumed = _map_item(item, contract, connector_id, item_marker, diagnostics)
        diagnostics.unmapped_fields.extend(_unmapped_fields(item, consumed, item_marker))
        normalized_items.append(normalized)

    diagnostics.mapping_result[target_collection] = normalized_items
    diagnostics.warnings.extend(diagnostics.transform_warnings)
    return diagnostics


def _item_path(contract: dict[str, Any]) -> str:
    source = contract.get("source")
    if isinstance(source, dict):
        value = source.get("items_path")
        if isinstance(value, str):
            return value
    value = contract.get("item_path")
    return value if isinstance(value, str) else "items"


def _items_at_path(raw_response: dict[str, Any], path: str) -> Any:
    if path in ("", "$"):
        return raw_response
    return _get_path(raw_response, path)


def _map_item(
    item: dict[str, Any],
    contract: dict[str, Any],
    connector_id: str,
    item_marker: str,
    diagnostics: MappingApplyResult,
) -> tuple[dict[str, Any], set[str]]:
    normalized: dict[str, Any] = {}
    consumed_paths: set[str] = set()
    for field_spec in contract.get("fields", []):
        target = str(field_spec["target"])
        value, source_path = _extract_value(item, field_spec)
        if source_path and source_path != "$":
            consumed_paths.add(source_path)

        missing = value is _MISSING or value in (None, "", [], {})
        if missing and field_spec.get("required") is True:
            marker = f"{item_marker}.{source_path or target}"
            diagnostics.missing_required_fields.append(marker)
            diagnostics.warnings.append(f"Mapping required field missing: {marker}")
        if missing:
            if "default" not in field_spec:
                continue
            value = deepcopy(field_spec["default"])

        value = _apply_transforms(value, field_spec, item_marker, target, diagnostics)
        value = _apply_enum(value, field_spec, item_marker, target, diagnostics)
        if value is not _MISSING:
            normalized[target] = value

    if contract.get("include_raw_data", True):
        normalized["raw_data"] = {"connector_id": connector_id, "response": item}
    if contract.get("include_normalized_data", True):
        excluded = {"raw_data", "raw_event", "normalized_data"}
        normalized["normalized_data"] = {
            key: value
            for key, value in normalized.items()
            if key not in excluded and value not in (None, "", [], {})
        }
    return normalized, consumed_paths


def _extract_value(item: dict[str, Any], field_spec: dict[str, Any]) -> tuple[Any, str | None]:
    for raw_path in _raw_paths(field_spec):
        value = item if raw_path == "$" else _get_path(item, raw_path)
        if value is not _MISSING and value not in (None, "", [], {}):
            return value, raw_path
    raw_paths = _raw_paths(field_spec)
    return _MISSING, raw_paths[0] if raw_paths else None


def _raw_paths(field_spec: dict[str, Any]) -> list[str]:
    raw = field_spec.get("raw")
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if raw is None:
        return []
    return [str(raw)]


def _get_path(root: Any, path: str) -> Any:
    current = root
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return _MISSING
            current = current[index]
            continue
        return _MISSING
    return current


def _apply_transforms(
    value: Any,
    field_spec: dict[str, Any],
    item_marker: str,
    target: str,
    diagnostics: MappingApplyResult,
) -> Any:
    transforms = field_spec.get("transforms", field_spec.get("transform", []))
    if isinstance(transforms, str):
        transforms = [transforms]
    if not isinstance(transforms, list):
        diagnostics.transform_warnings.append(f"{item_marker}.{target}: invalid transform declaration")
        return value
    transformed = value
    for transform in transforms:
        name = str(transform)
        try:
            transformed = _apply_transform(transformed, name)
        except (TypeError, ValueError) as exc:
            diagnostics.transform_warnings.append(f"{item_marker}.{target}: transform {name} failed: {exc}")
            return deepcopy(field_spec["default"]) if "default" in field_spec else _MISSING
    return transformed


def _apply_transform(value: Any, transform: str) -> Any:
    if transform in {"copy", "identity"}:
        return value
    if transform == "string":
        return None if value is None else str(value)
    if transform == "strip":
        return value.strip() if isinstance(value, str) else value
    if transform == "lower":
        return value.lower() if isinstance(value, str) else value
    if transform == "list":
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (tuple, set)):
            return list(value)
        return [value]
    if transform == "dict":
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        raise TypeError(f"expected object, got {type(value).__name__}")
    if transform == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return bool(value)
    if transform == "int":
        return int(value)
    if transform == "float":
        return float(value)
    raise ValueError(f"unknown transform: {transform}")


def _apply_enum(
    value: Any,
    field_spec: dict[str, Any],
    item_marker: str,
    target: str,
    diagnostics: MappingApplyResult,
) -> Any:
    enum_mapping = field_spec.get("enum")
    if not isinstance(enum_mapping, dict):
        return value
    key = str(value).strip().lower()
    normalized_mapping = {str(raw).strip().lower(): mapped for raw, mapped in enum_mapping.items()}
    if key in normalized_mapping:
        return normalized_mapping[key]
    if "enum_default" in field_spec:
        fallback = field_spec["enum_default"]
        diagnostics.transform_warnings.append(f"{item_marker}.{target}: unmapped enum value {value!r}, using {fallback!r}")
        return fallback
    diagnostics.transform_warnings.append(f"{item_marker}.{target}: unmapped enum value {value!r}")
    return value


def _unmapped_fields(item: dict[str, Any], consumed_paths: set[str], item_marker: str) -> list[str]:
    unmapped = []
    for path in _flatten_item_paths(item):
        if not _is_consumed(path, consumed_paths):
            unmapped.append(f"{item_marker}.{path}")
    return unmapped


def _flatten_item_paths(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        paths: list[str] = []
        for key, nested in value.items():
            nested_prefix = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(nested, dict):
                paths.extend(_flatten_item_paths(nested, nested_prefix))
            else:
                paths.append(nested_prefix)
        return paths
    return [prefix] if prefix else []


def _is_consumed(path: str, consumed_paths: set[str]) -> bool:
    for consumed in consumed_paths:
        if path == consumed or path.startswith(f"{consumed}."):
            return True
    return False
