"""Persistent installed connector package registry."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any
from uuid import uuid4

from flocks.config.config import Config


INSTALLED_REGISTRY_VERSION = "connector.package.installed.v1"
INSTALLED_REGISTRY_RELATIVE_PATH = Path("security") / "connector-packages.json"
MANAGED_PACKAGE_STORE_RELATIVE_PATH = Path("security") / "connectors" / "installed"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_installed_connector_package_registry_path() -> Path:
    return Config.get_data_path() / INSTALLED_REGISTRY_RELATIVE_PATH


def default_managed_connector_package_store_path() -> Path:
    return Config.get_data_path() / MANAGED_PACKAGE_STORE_RELATIVE_PATH


def registry_path_or_default(registry_path: Path | None = None) -> Path:
    return (registry_path or default_installed_connector_package_registry_path()).expanduser()


def managed_store_path_or_default(
    registry_path: Path | None = None,
    store_path: Path | None = None,
) -> Path:
    if store_path is not None:
        return store_path.expanduser()
    if registry_path is not None:
        return registry_path_or_default(registry_path).parent / "connectors" / "installed"
    return default_managed_connector_package_store_path()


def empty_installed_connector_package_registry() -> dict[str, Any]:
    return {
        "version": INSTALLED_REGISTRY_VERSION,
        "updated_at": None,
        "packages": {},
        "history": {},
        "audit": [],
    }


def load_installed_connector_package_registry(registry_path: Path | None = None) -> dict[str, Any]:
    path = registry_path_or_default(registry_path)
    if not path.is_file():
        return empty_installed_connector_package_registry()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Installed connector package registry must be an object: {path}")
    registry = empty_installed_connector_package_registry()
    registry.update(data)
    registry["version"] = str(registry.get("version") or INSTALLED_REGISTRY_VERSION)
    registry["packages"] = registry.get("packages") if isinstance(registry.get("packages"), dict) else {}
    registry["history"] = registry.get("history") if isinstance(registry.get("history"), dict) else {}
    registry["audit"] = registry.get("audit") if isinstance(registry.get("audit"), list) else []
    return registry


def save_installed_connector_package_registry(
    registry: dict[str, Any],
    registry_path: Path | None = None,
) -> dict[str, Any]:
    path = registry_path_or_default(registry_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    registry["version"] = INSTALLED_REGISTRY_VERSION
    registry["updated_at"] = utc_now()
    payload = json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write(payload)
    os.replace(tmp_path, path)
    return registry


def compute_connector_package_hash(package_root: Path) -> str:
    root = package_root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Connector package directory not found: {package_root}")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        if path.is_dir() and not path.is_symlink():
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8"))
            digest.update(b"\0")
            continue
        if not path.is_file():
            continue
        digest.update(b"file\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def copy_connector_package_to_managed_store(
    package_root: Path,
    *,
    package_id: str,
    version: str,
    package_hash: str,
    registry_path: Path | None = None,
    store_path: Path | None = None,
) -> Path:
    root = package_root.expanduser().resolve()
    _validate_copyable_package_tree(root)
    store = managed_store_path_or_default(registry_path, store_path)
    target = store / _safe_path_segment(package_id) / _install_key(version, package_hash)
    if target.is_dir():
        if compute_connector_package_hash(target) != package_hash:
            raise ValueError(f"Managed connector package hash mismatch: {target}")
        return target.resolve()

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.parent / f".{target.name}.{uuid4().hex}.tmp"
    try:
        shutil.copytree(root, tmp_path, symlinks=False)
        copied_hash = compute_connector_package_hash(tmp_path)
        if copied_hash != package_hash:
            raise ValueError(f"Managed connector package copy hash mismatch: {package_id}")
        tmp_path.rename(target)
    except FileExistsError:
        if target.is_dir() and compute_connector_package_hash(target) == package_hash:
            return target.resolve()
        raise
    except Exception:
        if tmp_path.exists():
            shutil.rmtree(tmp_path, ignore_errors=True)
        raise
    return target.resolve()


def list_installed_connector_packages(registry_path: Path | None = None) -> list[dict[str, Any]]:
    registry = load_installed_connector_package_registry(registry_path)
    packages = [
        _with_rollback_metadata(registry, dict(record))
        for record in registry["packages"].values()
        if isinstance(record, dict)
    ]
    packages.sort(key=lambda item: (str(item.get("id", "")), str(item.get("version", ""))))
    return packages


def get_installed_connector_package(
    package_id: str,
    registry_path: Path | None = None,
) -> dict[str, Any] | None:
    registry = load_installed_connector_package_registry(registry_path)
    record = registry["packages"].get(package_id)
    return _with_rollback_metadata(registry, dict(record)) if isinstance(record, dict) else None


def upsert_installed_connector_package(
    record: dict[str, Any],
    *,
    registry_path: Path | None = None,
    action: str = "install",
) -> dict[str, Any]:
    package_id = str(record.get("id") or "")
    if not package_id:
        raise ValueError("Installed connector package record is missing id")
    registry = load_installed_connector_package_registry(registry_path)
    existing = registry["packages"].get(package_id)
    now = utc_now()
    installed = dict(record)
    installed["id"] = package_id
    installed["installed_at"] = installed.get("installed_at") or now
    installed["updated_at"] = now
    if isinstance(existing, dict):
        snapshot = dict(existing)
        snapshot["superseded_at"] = now
        registry["history"].setdefault(package_id, []).append(snapshot)
    registry["packages"][package_id] = installed
    _append_audit(registry, action, package_id, status="success", metadata=_audit_metadata(installed))
    save_installed_connector_package_registry(registry, registry_path)
    return _with_rollback_metadata(registry, dict(installed))


def set_installed_connector_package_enabled(
    package_id: str,
    enabled: bool,
    *,
    registry_path: Path | None = None,
    validation_result: Any | None = None,
) -> dict[str, Any]:
    registry = load_installed_connector_package_registry(registry_path)
    record = registry["packages"].get(package_id)
    if not isinstance(record, dict):
        raise ValueError(f"Connector package is not installed: {package_id}")
    now = utc_now()
    updated = dict(record)
    updated["enabled"] = bool(enabled)
    updated["updated_at"] = now
    if enabled:
        updated["last_enabled_at"] = now
    else:
        updated["last_disabled_at"] = now
    if validation_result is not None:
        updated["last_validation_result"] = _dump_validation_result(validation_result)
        updated["last_validation_at"] = now
    registry["packages"][package_id] = updated
    _append_audit(
        registry,
        "enable" if enabled else "disable",
        package_id,
        status="success",
        metadata=_audit_metadata(updated),
    )
    save_installed_connector_package_registry(registry, registry_path)
    return _with_rollback_metadata(registry, dict(updated))


def uninstall_installed_connector_package(
    package_id: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    registry = load_installed_connector_package_registry(registry_path)
    record = registry["packages"].pop(package_id, None)
    if not isinstance(record, dict):
        raise ValueError(f"Connector package is not installed: {package_id}")
    now = utc_now()
    snapshot = dict(record)
    snapshot["enabled"] = False
    snapshot["uninstalled_at"] = now
    snapshot["updated_at"] = now
    registry["history"].setdefault(package_id, []).append(snapshot)
    _append_audit(registry, "uninstall", package_id, status="success", metadata=_audit_metadata(snapshot))
    save_installed_connector_package_registry(registry, registry_path)
    return snapshot


def rollback_installed_connector_package(
    package_id: str,
    *,
    registry_path: Path | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    registry = load_installed_connector_package_registry(registry_path)
    current = registry["packages"].get(package_id)
    candidate = _latest_restorable_history_record(registry, package_id, current if isinstance(current, dict) else None)
    if candidate is None:
        raise ValueError(f"Connector package rollback is not available: {package_id}")

    now = utc_now()
    if isinstance(current, dict):
        snapshot = dict(current)
        snapshot["superseded_at"] = now
        snapshot["superseded_by_rollback"] = True
        registry["history"].setdefault(package_id, []).append(snapshot)

    rolled_back = dict(candidate)
    rolled_back["enabled"] = bool(enabled)
    rolled_back["updated_at"] = now
    rolled_back["rolled_back_at"] = now
    if enabled:
        rolled_back["last_enabled_at"] = now
    for transient_key in ("superseded_at", "uninstalled_at", "superseded_by_rollback"):
        rolled_back.pop(transient_key, None)
    registry["packages"][package_id] = rolled_back
    _append_audit(registry, "rollback", package_id, status="success", metadata=_audit_metadata(rolled_back))
    save_installed_connector_package_registry(registry, registry_path)
    return _with_rollback_metadata(registry, dict(rolled_back))


def installed_registry_summary(registry_path: Path | None = None) -> dict[str, Any]:
    registry = load_installed_connector_package_registry(registry_path)
    packages = [record for record in registry["packages"].values() if isinstance(record, dict)]
    history = registry["history"] if isinstance(registry.get("history"), dict) else {}
    return {
        "path": str(registry_path_or_default(registry_path)),
        "managed_store": str(managed_store_path_or_default(registry_path)),
        "version": registry.get("version"),
        "installed_packages": len(packages),
        "enabled_packages": sum(1 for record in packages if bool(record.get("enabled"))),
        "history_entries": sum(len(items) for items in history.values() if isinstance(items, list)),
        "audit_events": len(registry.get("audit") or []),
    }


def _append_audit(
    registry: dict[str, Any],
    action: str,
    package_id: str,
    *,
    status: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    registry.setdefault("audit", []).append(
        {
            "id": f"connector-package-event-{uuid4().hex}",
            "action": f"connector_package.{action}",
            "package_id": package_id,
            "status": status,
            "created_at": utc_now(),
            "metadata": metadata or {},
        }
    )


def _audit_metadata(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "version": record.get("version"),
        "hash": record.get("hash"),
        "root": record.get("root"),
        "enabled": record.get("enabled"),
        "source": record.get("source"),
    }


def _dump_validation_result(validation_result: Any) -> dict[str, Any]:
    if hasattr(validation_result, "model_dump"):
        return validation_result.model_dump(mode="json")
    if isinstance(validation_result, dict):
        return dict(validation_result)
    return {"value": validation_result}


def _with_rollback_metadata(registry: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    package_id = str(record.get("id") or "")
    record["rollback_available"] = _latest_restorable_history_record(registry, package_id, record) is not None
    return record


def _latest_restorable_history_record(
    registry: dict[str, Any],
    package_id: str,
    current: dict[str, Any] | None,
) -> dict[str, Any] | None:
    history = registry.get("history") if isinstance(registry.get("history"), dict) else {}
    records = history.get(package_id) if isinstance(history.get(package_id), list) else []
    current_hash = current.get("hash") if current else None
    for record in reversed(records):
        if not isinstance(record, dict):
            continue
        if current_hash and record.get("hash") == current_hash:
            continue
        root_value = record.get("root")
        if not root_value:
            continue
        root = Path(str(root_value)).expanduser()
        if not root.is_dir():
            continue
        try:
            if compute_connector_package_hash(root) != record.get("hash"):
                continue
        except (OSError, ValueError):
            continue
        return dict(record)
    return None


def _validate_copyable_package_tree(root: Path) -> None:
    if not root.is_dir():
        raise ValueError(f"Connector package directory not found: {root}")
    for path in root.rglob("*"):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Connector package path escapes package root: {path}") from exc
        if path.is_symlink():
            raise ValueError(f"Connector package contains symlink, which cannot be installed: {path}")
        if not path.is_dir() and not path.is_file():
            raise ValueError(f"Connector package contains unsupported filesystem entry: {path}")


def _install_key(version: str, package_hash: str) -> str:
    digest = package_hash.split(":", 1)[-1][:12]
    return f"{_safe_path_segment(version or 'unknown')}-{digest}"


def _safe_path_segment(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in str(value))
    cleaned = cleaned.strip(".-")
    return cleaned or "unknown"
