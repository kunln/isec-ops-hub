"""Connector package discovery and registration helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from time import perf_counter
from typing import Any, Awaitable, Callable

from flocks.security.connectors.adapter import (
    ADAPTER_CONTRACT_VERSION,
    adapter_contract_summary,
    load_adapter_contract,
    preview_adapter_contract,
    resolve_mapping_path,
    _resolve_dynamic,
)
from flocks.security.connectors.mapping import (
    MAPPING_CONTRACT_VERSION,
    build_field_mapping,
    load_mapping_contract,
    mapping_contract_summary,
)
from flocks.security.connectors.installed_registry import (
    compute_connector_package_hash,
    copy_connector_package_to_managed_store,
    get_installed_connector_package,
    installed_registry_summary,
    list_installed_connector_packages,
    rollback_installed_connector_package,
    set_installed_connector_package_enabled,
    uninstall_installed_connector_package,
    upsert_installed_connector_package,
)
from flocks.security.connectors.models import (
    ConnectorCapability,
    ConnectorHealthCheckResult,
    ConnectorManifest,
    ConnectorPreviewResult,
    ConnectorTestResult,
    ConnectorValidateResult,
)


PACKAGE_CONTRACT_VERSION = "connector.package.v1"
BUILTIN_CONNECTOR_PACKAGE_ROOT = Path(__file__).resolve().parent / "fixtures"
CURRENT_FLOCKS_VERSION = "unknown"

try:
    from flocks import __version__ as CURRENT_FLOCKS_VERSION
except Exception:
    pass


@dataclass(frozen=True)
class ConnectorPackage:
    root: Path
    manifest_path: Path
    manifest_data: dict[str, Any]
    adapter_paths: dict[ConnectorCapability, Path] = field(default_factory=dict)
    adapter_contracts: dict[ConnectorCapability, dict[str, Any]] = field(default_factory=dict)
    mapping_paths: dict[ConnectorCapability, Path] = field(default_factory=dict)
    mapping_contracts: dict[ConnectorCapability, dict[str, Any]] = field(default_factory=dict)
    source: str = "package"

    @property
    def connector_id(self) -> str:
        return str(self.manifest_data["id"])


PackageTestFn = Callable[[], Awaitable[ConnectorTestResult]]
PackagePreviewFn = Callable[[ConnectorCapability], Awaitable[ConnectorPreviewResult]]
PackageValidateFn = Callable[[], Awaitable[ConnectorValidateResult]]
CredentialEnvProvider = Callable[[str], dict[str, str]]


def default_connector_package_roots(workspace_root: Path | None = None) -> list[Path]:
    roots = [BUILTIN_CONNECTOR_PACKAGE_ROOT]
    roots.append(Path.home() / ".flocks" / "connectors")
    if workspace_root is not None:
        roots.append(workspace_root / ".flocks" / "connectors")
    return roots


def discover_connector_packages(
    roots: list[Path] | None = None,
    *,
    workspace_root: Path | None = None,
) -> list[ConnectorPackage]:
    package_roots = roots if roots is not None else default_connector_package_roots(workspace_root)
    packages: dict[str, ConnectorPackage] = {}
    for root in package_roots:
        if not root.is_dir():
            continue
        for manifest_path in sorted(root.glob("*/manifest.json")):
            try:
                package = load_connector_package(manifest_path.parent, source=_package_source(root, workspace_root))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            packages[package.connector_id] = package
    return sorted(packages.values(), key=lambda package: package.connector_id)


def discover_enabled_connector_packages(
    *,
    registry_path: Path | None = None,
) -> list[ConnectorPackage]:
    packages: dict[str, ConnectorPackage] = {}
    for record in list_installed_connector_packages(registry_path):
        if not bool(record.get("enabled")):
            continue
        root_value = record.get("root")
        if not root_value:
            continue
        try:
            root = Path(str(root_value)).expanduser().resolve()
            if compute_connector_package_hash(root) != record.get("hash"):
                continue
            package = load_connector_package(root, source=str(record.get("source") or "installed"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if package.connector_id == str(record.get("id")):
            packages[package.connector_id] = package
    return sorted(packages.values(), key=lambda package: package.connector_id)


async def build_connector_package_diagnostics(
    roots: list[Path] | None = None,
    *,
    workspace_root: Path | None = None,
    registry_path: Path | None = None,
    include_installed_registry: bool = True,
) -> dict[str, Any]:
    package_roots = roots if roots is not None else default_connector_package_roots(workspace_root)
    root_entries: list[dict[str, Any]] = []
    package_entries: list[dict[str, Any]] = []
    discovery_active_keys_by_id: dict[str, tuple[str, str]] = {}
    installed_records = list_installed_connector_packages(registry_path) if include_installed_registry else []
    installed_by_id = {str(record.get("id")): record for record in installed_records if record.get("id")}
    installed_seen: set[tuple[str, str]] = set()

    for root in package_roots:
        source = _package_source(root, workspace_root)
        root_path = root.expanduser()
        exists = root_path.is_dir()
        manifest_paths = sorted(root_path.glob("*/manifest.json")) if exists else []
        root_entries.append(
            {
                "source": source,
                "root": str(root_path.resolve() if exists else root_path),
                "exists": exists,
                "manifest_count": len(manifest_paths),
            }
        )
        for manifest_path in manifest_paths:
            entry = await _diagnose_connector_package(manifest_path, source=source)
            package_entries.append(entry)
            if entry["valid"] and entry.get("id"):
                discovery_active_keys_by_id[str(entry["id"])] = (str(entry["root"]), str(entry["manifest"]))

    for entry in package_entries:
        package_id = entry.get("id")
        if not package_id or not entry["valid"]:
            entry["discovery_active"] = False
        else:
            entry_key = (str(entry["root"]), str(entry["manifest"]))
            entry["discovery_active"] = discovery_active_keys_by_id.get(str(package_id)) == entry_key
        if package_id and not entry.get("discovery_active") and entry["valid"]:
            entry["warnings"].append(f"Package {package_id} is shadowed by a later package with the same id.")
            _finish_diagnostic_entry(entry)
        record = installed_by_id.get(str(package_id)) if package_id else None
        _apply_installed_state(entry, record)
        if record is not None and entry.get("installed_source_match"):
            installed_seen.add(_installed_source_key(record))

    for record in installed_records:
        key = _installed_source_key(record)
        if key not in installed_seen:
            package_entries.append(_installed_missing_entry(record))

    error_count = sum(len(entry["errors"]) for entry in package_entries)
    warning_count = sum(len(entry["warnings"]) for entry in package_entries)
    valid_count = sum(1 for entry in package_entries if entry["valid"])
    installed_count = len(installed_records)
    enabled_count = sum(1 for record in installed_records if bool(record.get("enabled")))
    active_count = sum(1 for entry in package_entries if entry.get("active"))
    return {
        "checked_at": _utc_now(),
        "version": PACKAGE_CONTRACT_VERSION,
        "installed_registry": installed_registry_summary(registry_path) if include_installed_registry else None,
        "summary": {
            "roots": len(root_entries),
            "packages": len(package_entries),
            "active_packages": active_count,
            "installed_packages": installed_count,
            "enabled_packages": enabled_count,
            "valid_packages": valid_count,
            "invalid_packages": len(package_entries) - valid_count,
            "errors": error_count,
            "warnings": warning_count,
        },
        "roots": root_entries,
        "packages": package_entries,
    }


async def install_connector_package(
    package_root: Path | str,
    *,
    enabled: bool = False,
    source: str | None = None,
    registry_path: Path | None = None,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(package_root).expanduser().resolve()
    package_source = source or _package_source(root.parent, Path.cwd())
    source_package = load_connector_package(root, source=package_source)
    source_validation = await validate_connector_package(source_package)
    if not source_validation.success:
        raise ValueError("; ".join(source_validation.errors) or source_validation.message)
    source_hash = compute_connector_package_hash(source_package.root)
    managed_root = copy_connector_package_to_managed_store(
        source_package.root,
        package_id=source_package.connector_id,
        version=_manifest_package_version(source_package.manifest_data),
        package_hash=source_hash,
        registry_path=registry_path,
    )
    package = load_connector_package(managed_root, source=package_source)
    validation = await validate_connector_package(package)
    if not validation.success:
        raise ValueError("; ".join(validation.errors) or validation.message)
    record = build_installed_connector_package_record(
        package,
        validation,
        enabled=enabled,
        source_root=source_package.root,
        source_manifest_path=source_package.manifest_path,
        source_hash=source_hash,
        source_metadata=source_metadata,
    )
    return upsert_installed_connector_package(record, registry_path=registry_path)


async def enable_connector_package(
    package_id: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    record = get_installed_connector_package(package_id, registry_path)
    if record is None:
        raise ValueError(f"Connector package is not installed: {package_id}")
    root = Path(str(record.get("root"))).expanduser().resolve()
    current_hash = compute_connector_package_hash(root)
    if current_hash != record.get("hash"):
        raise ValueError(f"Connector package hash changed since install: {package_id}")
    package = load_connector_package(root, source=str(record.get("source") or "installed"))
    if package.connector_id != package_id:
        raise ValueError(f"Installed package id changed from {package_id} to {package.connector_id}")
    validation = await validate_connector_package(package)
    if not validation.success:
        raise ValueError("; ".join(validation.errors) or validation.message)
    return set_installed_connector_package_enabled(
        package_id,
        True,
        registry_path=registry_path,
        validation_result=validation,
    )


def disable_connector_package(
    package_id: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    return set_installed_connector_package_enabled(package_id, False, registry_path=registry_path)


def uninstall_connector_package(
    package_id: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    return uninstall_installed_connector_package(package_id, registry_path=registry_path)


async def rollback_connector_package(
    package_id: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    rollback_installed_connector_package(package_id, registry_path=registry_path, enabled=False)
    return await enable_connector_package(package_id, registry_path=registry_path)


def load_connector_package(package_root: Path, *, source: str = "package") -> ConnectorPackage:
    root = package_root.resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"Connector package manifest not found: {manifest_path}")
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_package_manifest(manifest_data, source=str(manifest_path))

    capabilities = _manifest_capabilities(manifest_data)
    adapter_declarations = _adapter_declarations(manifest_data)
    adapter_paths: dict[ConnectorCapability, Path] = {}
    adapter_contracts: dict[ConnectorCapability, dict[str, Any]] = {}
    mapping_paths: dict[ConnectorCapability, Path] = {}
    mapping_contracts: dict[ConnectorCapability, dict[str, Any]] = {}
    for capability in capabilities:
        adapter_ref = adapter_declarations.get(capability.value)
        if not adapter_ref:
            raise ValueError(f"Connector package {manifest_data['id']} missing adapter for {capability.value}")
        adapter_path = _resolve_package_path(root, str(adapter_ref))
        adapter_contract = load_adapter_contract(adapter_path)
        if str(adapter_contract.get("capability")) != capability.value:
            raise ValueError(
                f"Adapter {adapter_path} capability {adapter_contract.get('capability')} "
                f"does not match manifest capability {capability.value}"
            )
        mapping_path = resolve_mapping_path(adapter_contract, adapter_path.parent)
        mapping_contract = load_mapping_contract(mapping_path)
        if str(mapping_contract.get("capability")) != capability.value:
            raise ValueError(
                f"Mapping {mapping_path} capability {mapping_contract.get('capability')} "
                f"does not match manifest capability {capability.value}"
            )
        adapter_paths[capability] = adapter_path
        adapter_contracts[capability] = adapter_contract
        mapping_paths[capability] = mapping_path
        mapping_contracts[capability] = mapping_contract

    return ConnectorPackage(
        root=root,
        manifest_path=manifest_path,
        manifest_data=manifest_data,
        adapter_paths=adapter_paths,
        adapter_contracts=adapter_contracts,
        mapping_paths=mapping_paths,
        mapping_contracts=mapping_contracts,
        source=source,
    )


def validate_package_manifest(manifest: dict[str, Any], *, source: str = "connector package manifest") -> None:
    version = manifest.get("version")
    if version != PACKAGE_CONTRACT_VERSION:
        raise ValueError(f"{source} uses unsupported package version: {version}")
    for field_name in ("id", "name", "vendor", "product"):
        if not manifest.get(field_name):
            raise ValueError(f"{source} is missing {field_name}")
    if not _manifest_capabilities(manifest):
        raise ValueError(f"{source} must declare at least one capability")
    if not isinstance(manifest.get("adapters"), dict):
        raise ValueError(f"{source} must define adapters")
    compatibility = manifest.get("compatibility", {})
    if compatibility is not None and not isinstance(compatibility, dict):
        raise ValueError(f"{source} compatibility must be an object")
    min_flocks_version = (compatibility or {}).get("min_flocks_version")
    if min_flocks_version and not _version_at_least(CURRENT_FLOCKS_VERSION, str(min_flocks_version)):
        raise ValueError(
            f"{source} requires Flocks >= {min_flocks_version}; current version is {CURRENT_FLOCKS_VERSION}"
        )
    max_flocks_version = (compatibility or {}).get("max_flocks_version")
    if max_flocks_version and CURRENT_FLOCKS_VERSION != "unknown" and not _version_at_least(
        str(max_flocks_version),
        CURRENT_FLOCKS_VERSION,
    ):
        raise ValueError(
            f"{source} requires Flocks <= {max_flocks_version}; current version is {CURRENT_FLOCKS_VERSION}"
        )
    release = manifest.get("release", {})
    if release is not None and not isinstance(release, dict):
        raise ValueError(f"{source} release must be an object")


def build_package_registration(
    package: ConnectorPackage,
    *,
    credential_env_provider: CredentialEnvProvider | None = None,
) -> tuple[ConnectorManifest, PackageTestFn, PackagePreviewFn, PackageValidateFn]:
    manifest = build_package_manifest(package)

    def credential_env() -> dict[str, str]:
        return credential_env_provider(package.connector_id) if credential_env_provider is not None else {}

    async def test_connection() -> ConnectorTestResult:
        return await test_connector_package(package, env=credential_env())

    async def preview(capability: ConnectorCapability) -> ConnectorPreviewResult:
        return await preview_connector_package(package, capability, env=credential_env())

    async def validate() -> ConnectorValidateResult:
        return await validate_connector_package(package)

    return manifest, test_connection, preview, validate


def build_installed_connector_package_record(
    package: ConnectorPackage,
    validation: ConnectorValidateResult,
    *,
    enabled: bool,
    source_root: Path | None = None,
    source_manifest_path: Path | None = None,
    source_hash: str | None = None,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest_data = package.manifest_data
    now = _utc_now()
    record = {
        "id": package.connector_id,
        "name": str(manifest_data["name"]),
        "vendor": str(manifest_data["vendor"]),
        "product": str(manifest_data["product"]),
        "version": _manifest_package_version(manifest_data),
        "product_version": manifest_data.get("product_version"),
        "manifest_version": manifest_data.get("version"),
        "package_contract_version": PACKAGE_CONTRACT_VERSION,
        "hash": compute_connector_package_hash(package.root),
        "root": str(package.root),
        "installed_root": str(package.root),
        "manifest_path": str(package.manifest_path),
        "manifest": manifest_data,
        "source": package.source,
        "source_root": str(source_root) if source_root is not None else str(package.root),
        "source_manifest_path": str(source_manifest_path) if source_manifest_path is not None else str(package.manifest_path),
        "source_hash": source_hash or compute_connector_package_hash(package.root),
        "enabled": bool(enabled),
        "installed_at": now,
        "updated_at": now,
        "last_validation_result": validation.model_dump(mode="json"),
        "last_validation_at": now,
        "release": _manifest_release(manifest_data, package),
        "compatibility": _manifest_compatibility(manifest_data),
    }
    if source_metadata:
        record["source_metadata"] = dict(source_metadata)
        for key, value in source_metadata.items():
            if key not in record:
                record[key] = value
    return record


def build_package_manifest(package: ConnectorPackage) -> ConnectorManifest:
    manifest_data = package.manifest_data
    capabilities = list(package.adapter_paths.keys())
    adapter_contracts = {
        capability.value: adapter_contract_summary(
            package.adapter_contracts[capability],
            file=str(package.adapter_paths[capability]),
        )
        for capability in capabilities
    }
    mapping_contracts = {
        capability.value: mapping_contract_summary(
            package.mapping_contracts[capability],
            file=str(package.mapping_paths[capability]),
        )
        for capability in capabilities
    }
    field_mapping = {
        capability.value: build_field_mapping(package.mapping_contracts[capability])
        for capability in capabilities
    }
    return ConnectorManifest(
        id=package.connector_id,
        name=str(manifest_data["name"]),
        vendor=str(manifest_data["vendor"]),
        product=str(manifest_data["product"]),
        product_version=manifest_data.get("product_version"),
        deployment=str(manifest_data.get("deployment", "package")),
        auth_methods=list(manifest_data.get("auth_methods", [])),
        capabilities=capabilities,
        field_mapping=field_mapping,
        severity_mapping=dict(manifest_data.get("severity_mapping", {})),
        status_mapping=dict(manifest_data.get("status_mapping", {})),
        adapter_contracts=adapter_contracts,
        mapping_contracts=mapping_contracts,
        pagination=dict(manifest_data.get("pagination", {})),
        rate_limit=dict(manifest_data.get("rate_limit", {})),
        permissions=list(manifest_data.get("permissions", [])),
        risk_level=str(manifest_data.get("risk_level", "low")),
        description=str(manifest_data.get("description", "")),
        enabled=bool(manifest_data.get("enabled", True)),
        raw_response={
            "package_root": str(package.root),
            "manifest": str(package.manifest_path),
            "source": package.source,
            "adapters": {capability.value: str(path) for capability, path in package.adapter_paths.items()},
            "mappings": {capability.value: str(path) for capability, path in package.mapping_paths.items()},
            "release": _manifest_release(manifest_data, package),
        },
        normalized_data={
            "available_capabilities": [capability.value for capability in capabilities],
            "package_contract_version": PACKAGE_CONTRACT_VERSION,
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
            "mapping_contract_version": MAPPING_CONTRACT_VERSION,
            "compatibility": _manifest_compatibility(manifest_data),
        },
        health_check=ConnectorHealthCheckResult(
            status="ok",
            message="Connector package loaded.",
            checked_at=_utc_now(),
            latency_ms=0,
            details={"package_root": str(package.root), "source": package.source},
        ),
    )


async def preview_connector_package(
    package: ConnectorPackage,
    capability: ConnectorCapability,
    *,
    env: dict[str, str] | None = None,
    http_client: Any | None = None,
) -> ConnectorPreviewResult:
    adapter_path = package.adapter_paths.get(capability)
    if adapter_path is None:
        raise ValueError(f"Connector package {package.connector_id} missing adapter for {capability.value}")
    return await preview_adapter_contract(
        package.connector_id,
        package.adapter_contracts[capability],
        base_dir=adapter_path.parent,
        contract_file=adapter_path,
        http_client=http_client,
        env=env,
    )


async def test_connector_package(package: ConnectorPackage, *, env: dict[str, str] | None = None) -> ConnectorTestResult:
    health_tool_result = await _test_connector_package_health_tool(package, env=env)
    if health_tool_result is not None:
        return health_tool_result

    started = perf_counter()
    previews: dict[str, Any] = {}
    warnings: list[str] = []
    for capability in package.adapter_paths:
        preview = await preview_connector_package(package, capability, env=env)
        target, count = _preview_item_count(preview.mapping_result)
        previews[capability.value] = {
            "source": preview.source,
            "transport": preview.adapter_contract.get("transport"),
            "target": target,
            "items": count,
            "warnings": len(preview.warnings),
        }
        warnings.extend(preview.warnings)
    latency_ms = max(0, round((perf_counter() - started) * 1000))
    health = ConnectorHealthCheckResult(
        status="ok",
        message="Connector package test succeeded.",
        checked_at=_utc_now(),
        latency_ms=latency_ms,
        details={"package_root": str(package.root), "previews": previews},
    )
    return ConnectorTestResult(
        connector_id=package.connector_id,
        success=True,
        status="ok",
        message=health.message,
        health_check=health,
        capabilities=list(package.adapter_paths.keys()),
        raw_response={"package_root": str(package.root), "manifest": str(package.manifest_path)},
        normalized_data={"previews": previews},
        warnings=warnings,
    )


async def _test_connector_package_health_tool(
    package: ConnectorPackage,
    *,
    env: dict[str, str] | None = None,
) -> ConnectorTestResult | None:
    health_tool = package.manifest_data.get("health_tool")
    if not isinstance(health_tool, dict):
        return None

    name = str(health_tool.get("name") or "").strip()
    if not name:
        return None
    env_values = env or {}
    params = _resolve_dynamic(health_tool.get("params", {}), env_values)
    if not isinstance(params, dict):
        raise ValueError(f"Connector package {package.connector_id} health_tool params must resolve to an object")

    started = perf_counter()
    from flocks.tool import ToolContext, ToolRegistry

    ToolRegistry.init()
    result = await ToolRegistry.execute(
        name,
        ctx=ToolContext(session_id="connector-test", message_id=f"connector:{package.connector_id}:health"),
        **params,
    )
    if not result.success:
        raise ValueError(result.error or f"Connector package health tool failed: {name}")

    latency_ms = max(0, round((perf_counter() - started) * 1000))
    health = ConnectorHealthCheckResult(
        status="ok",
        message="Connector package health tool succeeded.",
        checked_at=_utc_now(),
        latency_ms=latency_ms,
        details={
            "package_root": str(package.root),
            "health_tool": {
                "name": name,
                "param_keys": sorted(params.keys()),
            },
        },
    )
    return ConnectorTestResult(
        connector_id=package.connector_id,
        success=True,
        status="ok",
        message=health.message,
        health_check=health,
        capabilities=list(package.adapter_paths.keys()),
        raw_response={"package_root": str(package.root), "manifest": str(package.manifest_path)},
        normalized_data={"health_tool": name, "output": result.output},
        warnings=[],
    )


async def validate_connector_package(package: ConnectorPackage) -> ConnectorValidateResult:
    warnings: list[str] = []
    errors: list[str] = []
    adapter_contracts: dict[str, Any] = {}
    mapping_contracts: dict[str, Any] = {}
    for capability in package.adapter_paths:
        try:
            adapter_contracts[capability.value] = adapter_contract_summary(
                package.adapter_contracts[capability],
                file=str(package.adapter_paths[capability]),
            )
            mapping_contracts[capability.value] = mapping_contract_summary(
                package.mapping_contracts[capability],
                file=str(package.mapping_paths[capability]),
            )
            if package.adapter_contracts[capability].get("transport") == "fixture":
                preview = await preview_connector_package(package, capability)
                warnings.extend(preview.warnings)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{capability.value}: {exc}")
    success = not errors
    return ConnectorValidateResult(
        connector_id=package.connector_id,
        success=success,
        status="ok" if success else "error",
        message="Connector package validated." if success else "Connector package validation failed.",
        capabilities=list(package.adapter_paths.keys()),
        adapter_contracts=adapter_contracts,
        mapping_contracts=mapping_contracts,
        warnings=warnings,
        errors=errors,
    )


async def _diagnose_connector_package(manifest_path: Path, *, source: str) -> dict[str, Any]:
    root = manifest_path.parent.resolve()
    entry: dict[str, Any] = {
        "id": root.name,
        "name": None,
        "vendor": None,
        "product": None,
        "version": None,
        "package_version": None,
        "source": source,
        "root": str(root),
        "manifest": str(manifest_path.resolve()),
        "active": False,
        "discovery_active": False,
        "valid": False,
        "status": "error",
        "enabled": False,
        "manifest_enabled": None,
        "installed": False,
        "installed_version": None,
        "installed_hash": None,
        "installed_at": None,
        "package_hash": None,
        "runtime_status": "not_installed",
        "last_validation_result": None,
        "last_validation_at": None,
        "capabilities": [],
        "adapter_count": 0,
        "mapping_count": 0,
        "adapters": {},
        "mappings": {},
        "runtime_validation": {},
        "release": {},
        "compatibility": {},
        "warnings": [],
        "errors": [],
    }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        entry["errors"].append(f"Manifest load failed: {exc}")
        return _finish_diagnostic_entry(entry)

    if not isinstance(manifest, dict):
        entry["errors"].append("Manifest JSON must be an object.")
        return _finish_diagnostic_entry(entry)

    entry.update(
        {
            "id": str(manifest.get("id") or root.name),
            "name": manifest.get("name"),
            "vendor": manifest.get("vendor"),
            "product": manifest.get("product"),
            "version": manifest.get("version"),
            "package_version": _manifest_package_version(manifest),
            "manifest_enabled": manifest.get("enabled", True),
            "capabilities": _raw_capability_values(manifest),
            "release": _manifest_release_from_manifest(manifest),
            "compatibility": _manifest_compatibility(manifest),
        }
    )
    try:
        entry["package_hash"] = compute_connector_package_hash(root)
    except (OSError, ValueError) as exc:
        entry["warnings"].append(f"Package hash failed: {exc}")
    try:
        validate_package_manifest(manifest, source=str(manifest_path))
    except ValueError as exc:
        entry["errors"].append(str(exc))

    valid_capabilities = _valid_capabilities_for_diagnostics(manifest, entry)
    adapter_declarations = _adapter_declarations(manifest)
    for capability in valid_capabilities:
        _diagnose_adapter_and_mapping(entry, root, capability, adapter_declarations)

    if not entry["errors"]:
        try:
            package = load_connector_package(root, source=source)
            validation = await validate_connector_package(package)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            entry["errors"].append(f"Runtime validation failed: {exc}")
        else:
            entry["runtime_validation"] = validation.model_dump(mode="json")
            entry["warnings"].extend(validation.warnings)
            entry["errors"].extend(validation.errors)

    return _finish_diagnostic_entry(entry)


def _finish_diagnostic_entry(entry: dict[str, Any]) -> dict[str, Any]:
    entry["adapter_count"] = sum(
        1 for adapter in entry.get("adapters", {}).values() if isinstance(adapter, dict) and adapter.get("exists")
    )
    entry["mapping_count"] = sum(
        1 for mapping in entry.get("mappings", {}).values() if isinstance(mapping, dict) and mapping.get("exists")
    )
    entry["valid"] = not entry["errors"]
    entry["status"] = "error" if entry["errors"] else "warning" if entry["warnings"] else "ok"
    return entry


def _apply_installed_state(entry: dict[str, Any], record: dict[str, Any] | None) -> None:
    if record is None:
        entry["installed"] = False
        entry["enabled"] = False
        entry["active"] = False
        entry["runtime_status"] = "invalid" if not entry.get("valid") else "not_installed"
        return

    entry["installed"] = True
    entry["installed_version"] = record.get("version")
    entry["installed_hash"] = record.get("hash")
    entry["installed_at"] = record.get("installed_at")
    entry["enabled"] = bool(record.get("enabled"))
    entry["last_validation_result"] = record.get("last_validation_result")
    entry["last_validation_at"] = record.get("last_validation_at")
    same_source = _same_path(record.get("source_root") or record.get("root"), entry.get("root"))
    entry["installed_source_match"] = same_source
    same_source_hash = bool(entry.get("package_hash")) and entry.get("package_hash") == (
        record.get("source_hash") or record.get("hash")
    )
    managed_hash_ok = _record_package_hash_ok(record)
    entry["active"] = bool(entry["enabled"] and entry.get("valid") and same_source and managed_hash_ok)
    entry["rollback_available"] = bool(record.get("rollback_available"))
    if not same_source:
        entry["runtime_status"] = "installed_elsewhere"
    elif not entry.get("valid"):
        entry["runtime_status"] = "invalid"
    elif not managed_hash_ok:
        entry["runtime_status"] = "installed_missing"
    elif not same_source_hash:
        entry["runtime_status"] = "stale_source"
    elif entry["enabled"]:
        entry["runtime_status"] = "enabled"
    else:
        entry["runtime_status"] = "disabled"


def _installed_missing_entry(record: dict[str, Any]) -> dict[str, Any]:
    package_id = str(record.get("id") or "unknown")
    root = str(record.get("source_root") or record.get("root") or "")
    manifest = record.get("manifest") if isinstance(record.get("manifest"), dict) else {}
    managed_ok = _record_package_hash_ok(record)
    enabled = bool(record.get("enabled"))
    entry: dict[str, Any] = {
        "id": package_id,
        "name": record.get("name"),
        "vendor": record.get("vendor"),
        "product": record.get("product"),
        "version": record.get("manifest_version"),
        "package_version": record.get("version"),
        "source": record.get("source") or "installed",
        "root": root,
        "manifest": str(record.get("source_manifest_path") or record.get("manifest_path") or (Path(root) / "manifest.json" if root else "")),
        "active": bool(enabled and managed_ok),
        "discovery_active": False,
        "valid": managed_ok,
        "status": "warning" if managed_ok else "error",
        "enabled": enabled,
        "manifest_enabled": None,
        "installed": True,
        "installed_source_match": False,
        "installed_version": record.get("version"),
        "installed_hash": record.get("hash"),
        "installed_at": record.get("installed_at"),
        "package_hash": None,
        "runtime_status": "enabled" if enabled and managed_ok else "disabled" if managed_ok else "installed_missing",
        "rollback_available": bool(record.get("rollback_available")),
        "last_validation_result": record.get("last_validation_result"),
        "last_validation_at": record.get("last_validation_at"),
        "capabilities": list(manifest.get("capabilities", [])) if isinstance(manifest.get("capabilities"), list) else [],
        "adapter_count": 0,
        "mapping_count": 0,
        "adapters": {},
        "mappings": {},
        "runtime_validation": {},
        "release": record.get("release") or _manifest_release_from_manifest(manifest),
        "compatibility": record.get("compatibility") or _manifest_compatibility(manifest),
        "warnings": ["Source connector package manifest is no longer discoverable; runtime uses the managed installed copy."]
        if managed_ok
        else [],
        "errors": [] if managed_ok else ["Managed connector package copy is no longer available."],
    }
    return _finish_diagnostic_entry(entry)


def _installed_source_key(record: dict[str, Any]) -> tuple[str, str]:
    return (str(record.get("id")), str(Path(str(record.get("source_root") or record.get("root") or "")).expanduser()))


def _record_package_hash_ok(record: dict[str, Any]) -> bool:
    root_value = record.get("root")
    if not root_value:
        return False
    try:
        return compute_connector_package_hash(Path(str(root_value)).expanduser()) == record.get("hash")
    except (OSError, ValueError):
        return False


def _raw_capability_values(manifest: dict[str, Any]) -> list[str]:
    capabilities = manifest.get("capabilities", [])
    return [str(item) for item in capabilities] if isinstance(capabilities, list) else []


def _valid_capabilities_for_diagnostics(
    manifest: dict[str, Any],
    entry: dict[str, Any],
) -> list[ConnectorCapability]:
    capabilities: list[ConnectorCapability] = []
    for item in _raw_capability_values(manifest):
        try:
            capabilities.append(ConnectorCapability(item))
        except ValueError:
            entry["errors"].append(f"Unknown connector capability in manifest {entry.get('id')}: {item}")
    return capabilities


def _diagnose_adapter_and_mapping(
    entry: dict[str, Any],
    root: Path,
    capability: ConnectorCapability,
    adapter_declarations: dict[str, str],
) -> None:
    adapter_diag: dict[str, Any] = {"status": "error", "file": None, "exists": False, "summary": {}, "errors": []}
    mapping_diag: dict[str, Any] = {"status": "error", "file": None, "exists": False, "summary": {}, "errors": []}
    entry["adapters"][capability.value] = adapter_diag
    entry["mappings"][capability.value] = mapping_diag

    adapter_ref = adapter_declarations.get(capability.value)
    if not adapter_ref:
        message = f"Connector package {entry.get('id')} missing adapter for {capability.value}"
        adapter_diag["errors"].append(message)
        adapter_diag["status"] = "error"
        entry["errors"].append(message)
        return

    adapter_path = _resolve_package_path(root, adapter_ref)
    adapter_diag["file"] = str(adapter_path)
    adapter_diag["exists"] = adapter_path.is_file()
    try:
        adapter_contract = load_adapter_contract(adapter_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        message = f"{capability.value} adapter load failed: {exc}"
        adapter_diag["errors"].append(message)
        entry["errors"].append(message)
        return

    adapter_diag["summary"] = adapter_contract_summary(adapter_contract, file=str(adapter_path))
    adapter_diag["status"] = "ok"
    if str(adapter_contract.get("capability")) != capability.value:
        message = (
            f"Adapter {adapter_path} capability {adapter_contract.get('capability')} "
            f"does not match manifest capability {capability.value}"
        )
        adapter_diag["errors"].append(message)
        entry["errors"].append(message)

    mapping_ref = adapter_contract.get("mapping")
    if mapping_ref:
        mapping_path = Path(str(mapping_ref))
        if not mapping_path.is_absolute():
            mapping_path = adapter_path.parent / mapping_path
        mapping_diag["file"] = str(mapping_path)
        mapping_diag["exists"] = mapping_path.is_file()

    try:
        resolved_mapping_path = resolve_mapping_path(adapter_contract, adapter_path.parent)
        mapping_contract = load_mapping_contract(resolved_mapping_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        message = f"{capability.value} mapping load failed: {exc}"
        mapping_diag["errors"].append(message)
        mapping_diag["status"] = "error"
        entry["errors"].append(message)
        return

    mapping_diag["file"] = str(resolved_mapping_path)
    mapping_diag["exists"] = resolved_mapping_path.is_file()
    mapping_diag["summary"] = mapping_contract_summary(mapping_contract, file=str(resolved_mapping_path))
    mapping_diag["status"] = "ok"
    if str(mapping_contract.get("capability")) != capability.value:
        message = (
            f"Mapping {resolved_mapping_path} capability {mapping_contract.get('capability')} "
            f"does not match manifest capability {capability.value}"
        )
        mapping_diag["errors"].append(message)
        entry["errors"].append(message)


def _adapter_declarations(manifest: dict[str, Any]) -> dict[str, str]:
    adapters = manifest.get("adapters", {})
    return {str(capability): str(path) for capability, path in adapters.items()} if isinstance(adapters, dict) else {}


def _manifest_capabilities(manifest: dict[str, Any]) -> list[ConnectorCapability]:
    capabilities: list[ConnectorCapability] = []
    for item in manifest.get("capabilities", []):
        try:
            capabilities.append(ConnectorCapability(str(item)))
        except ValueError as exc:
            raise ValueError(f"Unknown connector capability in manifest {manifest.get('id')}: {item}") from exc
    return capabilities


def _manifest_package_version(manifest: dict[str, Any]) -> str:
    return str(manifest.get("package_version") or manifest.get("product_version") or manifest.get("version") or "")


def _manifest_compatibility(manifest: dict[str, Any]) -> dict[str, Any]:
    compatibility = manifest.get("compatibility") if isinstance(manifest.get("compatibility"), dict) else {}
    return {
        "min_flocks_version": compatibility.get("min_flocks_version"),
        "max_flocks_version": compatibility.get("max_flocks_version"),
        "connector_package_contract": PACKAGE_CONTRACT_VERSION,
        "adapter_contract": ADAPTER_CONTRACT_VERSION,
        "mapping_contract": MAPPING_CONTRACT_VERSION,
        "current_flocks_version": CURRENT_FLOCKS_VERSION,
    }


def _manifest_release_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    release = manifest.get("release") if isinstance(manifest.get("release"), dict) else {}
    changelog = release.get("changelog") if isinstance(release.get("changelog"), list) else []
    notes = release.get("notes")
    if not notes:
        capabilities = ", ".join(_raw_capability_values(manifest)) or "no capabilities"
        notes = (
            f"{manifest.get('name') or manifest.get('id')} "
            f"{_manifest_package_version(manifest)} provides {capabilities}."
        )
    return {
        "channel": release.get("channel", "stable"),
        "notes": str(notes),
        "changelog": [str(item) for item in changelog],
        "published_at": release.get("published_at"),
        "compatibility": _manifest_compatibility(manifest),
    }


def _manifest_release(manifest: dict[str, Any], package: ConnectorPackage) -> dict[str, Any]:
    release = _manifest_release_from_manifest(manifest)
    transports = sorted(
        {
            str(contract.get("transport"))
            for contract in package.adapter_contracts.values()
            if isinstance(contract, dict) and contract.get("transport")
        }
    )
    release["generated_summary"] = {
        "package_id": str(manifest.get("id") or package.connector_id),
        "package_version": _manifest_package_version(manifest),
        "product_version": manifest.get("product_version"),
        "capabilities": [capability.value for capability in package.adapter_paths],
        "adapter_transports": transports,
        "mapping_targets": sorted(
            {
                str(contract.get("target"))
                for contract in package.mapping_contracts.values()
                if isinstance(contract, dict) and contract.get("target")
            }
        ),
    }
    return release


def _version_at_least(current: str, minimum: str) -> bool:
    if not current or current == "unknown":
        return True
    return _version_tuple(current) >= _version_tuple(minimum)


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", str(value))]
    return tuple(parts or [0])


def _same_path(left: Any, right: Any) -> bool:
    if not left or not right:
        return False
    try:
        return Path(str(left)).expanduser().resolve() == Path(str(right)).expanduser().resolve()
    except (OSError, RuntimeError):
        return str(left) == str(right)


def _resolve_package_path(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path


def _preview_item_count(mapping_result: dict[str, Any]) -> tuple[str | None, int]:
    for key, value in mapping_result.items():
        if isinstance(value, list):
            return key, len(value)
    return None, 0


def _package_source(root: Path, workspace_root: Path | None) -> str:
    resolved_root = root.resolve()
    if resolved_root == BUILTIN_CONNECTOR_PACKAGE_ROOT.resolve():
        return "builtin"
    if workspace_root is not None and resolved_root == (workspace_root / ".flocks" / "connectors").resolve():
        return "workspace"
    if resolved_root == (Path.home() / ".flocks" / "connectors").resolve():
        return "user"
    return "package"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
