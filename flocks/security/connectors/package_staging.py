"""Staging store for uploaded connector package artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile
from typing import Any
from uuid import uuid4
import zipfile

from flocks.config.config import Config
from flocks.security.connectors.installed_registry import compute_connector_package_hash
from flocks.security.connectors.package_loader import (
    build_package_manifest,
    install_connector_package,
    load_connector_package,
    validate_connector_package,
)


STAGING_REGISTRY_VERSION = "connector.package.staging.v1"
STAGING_REGISTRY_RELATIVE_PATH = Path("security") / "connector-package-staging.json"
STAGING_STORE_RELATIVE_PATH = Path("security") / "connectors" / "staging"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 500


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_connector_package_staging_registry_path() -> Path:
    return Config.get_data_path() / STAGING_REGISTRY_RELATIVE_PATH


def default_connector_package_staging_store_path() -> Path:
    return Config.get_data_path() / STAGING_STORE_RELATIVE_PATH


def staging_registry_path_or_default(staging_registry_path: Path | None = None) -> Path:
    return (staging_registry_path or default_connector_package_staging_registry_path()).expanduser()


def staging_store_path_or_default(
    staging_registry_path: Path | None = None,
    staging_store_path: Path | None = None,
) -> Path:
    if staging_store_path is not None:
        return staging_store_path.expanduser()
    if staging_registry_path is not None:
        return staging_registry_path_or_default(staging_registry_path).parent / "connectors" / "staging"
    return default_connector_package_staging_store_path()


def empty_connector_package_staging_registry() -> dict[str, Any]:
    return {
        "version": STAGING_REGISTRY_VERSION,
        "updated_at": None,
        "packages": {},
        "audit": [],
    }


def load_connector_package_staging_registry(staging_registry_path: Path | None = None) -> dict[str, Any]:
    path = staging_registry_path_or_default(staging_registry_path)
    if not path.is_file():
        return empty_connector_package_staging_registry()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Connector package staging registry must be an object: {path}")
    registry = empty_connector_package_staging_registry()
    registry.update(data)
    registry["version"] = str(registry.get("version") or STAGING_REGISTRY_VERSION)
    registry["packages"] = registry.get("packages") if isinstance(registry.get("packages"), dict) else {}
    registry["audit"] = registry.get("audit") if isinstance(registry.get("audit"), list) else []
    return registry


def save_connector_package_staging_registry(
    registry: dict[str, Any],
    staging_registry_path: Path | None = None,
) -> dict[str, Any]:
    path = staging_registry_path_or_default(staging_registry_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    registry["version"] = STAGING_REGISTRY_VERSION
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


def list_staged_connector_packages(staging_registry_path: Path | None = None) -> list[dict[str, Any]]:
    registry = load_connector_package_staging_registry(staging_registry_path)
    records = [dict(record) for record in registry["packages"].values() if isinstance(record, dict)]
    records.sort(key=lambda item: str(item.get("uploaded_at", "")), reverse=True)
    return records


async def stage_connector_package_artifact(
    *,
    filename: str,
    content: bytes,
    staging_registry_path: Path | None = None,
    staging_store_path: Path | None = None,
) -> dict[str, Any]:
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Connector package artifact is too large: {len(content)} bytes")
    archive_format = _archive_format(filename)
    staging_id = f"staged-connector-package-{uuid4().hex}"
    store = staging_store_path_or_default(staging_registry_path, staging_store_path)
    stage_root = store / staging_id
    archive_name = _safe_filename(filename)
    archive_path = stage_root / "artifact" / archive_name
    extract_root = stage_root / "extract"
    now = utc_now()

    try:
        archive_path.parent.mkdir(parents=True, exist_ok=False)
        extract_root.mkdir(parents=True, exist_ok=False)
        archive_path.write_bytes(content)
        _extract_archive(archive_path, extract_root, archive_format=archive_format)
        _validate_extracted_tree(extract_root)
        package_root, root_errors = _find_extracted_package_root(extract_root)
        record: dict[str, Any] = {
            "id": staging_id,
            "status": "uploaded",
            "source": "upload",
            "filename": archive_name,
            "original_filename": filename,
            "archive_format": archive_format,
            "artifact_path": str(archive_path.resolve()),
            "artifact_size": len(content),
            "artifact_hash": _sha256_bytes(content),
            "staging_root": str(stage_root.resolve()),
            "extract_root": str(extract_root.resolve()),
            "package_root": str(package_root.resolve()),
            "uploaded_at": now,
            "updated_at": now,
            "validated_at": None,
            "validation_result": None,
            "errors": root_errors,
            "warnings": [],
        }
        _upsert_staged_record(record, staging_registry_path, action="upload")
        if root_errors:
            record = _mark_staged_record_invalid(record, root_errors, staging_registry_path)
        else:
            record = await validate_staged_connector_package(staging_id, staging_registry_path=staging_registry_path)
        return record
    except Exception:
        if stage_root.exists():
            shutil.rmtree(stage_root, ignore_errors=True)
        raise


async def validate_staged_connector_package(
    staging_id: str,
    *,
    staging_registry_path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_package_staging_registry(staging_registry_path)
    record = registry["packages"].get(staging_id)
    if not isinstance(record, dict):
        raise ValueError(f"Staged connector package not found: {staging_id}")
    updated = dict(record)
    errors: list[str] = []
    warnings: list[str] = []
    package_root = Path(str(updated.get("package_root") or "")).expanduser()
    try:
        _validate_extracted_tree(package_root)
        package = load_connector_package(package_root, source="upload")
        package_hash = compute_connector_package_hash(package.root)
        validation = await validate_connector_package(package)
        runtime_manifest = build_package_manifest(package)
        validation_result = validation.model_dump(mode="json")
        errors.extend(validation.errors)
        warnings.extend(validation.warnings)
        updated.update(
            {
                "package_id": package.connector_id,
                "name": str(package.manifest_data.get("name") or package.connector_id),
                "vendor": package.manifest_data.get("vendor"),
                "product": package.manifest_data.get("product"),
                "version": str(package.manifest_data.get("product_version") or package.manifest_data.get("version") or ""),
                "package_version": str(
                    package.manifest_data.get("package_version")
                    or package.manifest_data.get("product_version")
                    or package.manifest_data.get("version")
                    or ""
                ),
                "manifest_path": str(package.manifest_path),
                "package_hash": package_hash,
                "capabilities": [capability.value for capability in package.adapter_paths],
                "validation_result": validation_result,
                "release": runtime_manifest.raw_response.get("release"),
                "compatibility": runtime_manifest.normalized_data.get("compatibility"),
            }
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
        updated["validation_result"] = _failed_validation_result(updated, errors)

    now = utc_now()
    updated["status"] = "invalid" if errors else "validated"
    updated["errors"] = errors
    updated["warnings"] = warnings
    updated["validated_at"] = now
    updated["updated_at"] = now
    registry["packages"][staging_id] = updated
    _append_audit(registry, "validate", staging_id, status="error" if errors else "success", metadata=_audit_metadata(updated))
    save_connector_package_staging_registry(registry, staging_registry_path)
    return dict(updated)


async def install_staged_connector_package(
    staging_id: str,
    *,
    enabled: bool = False,
    installed_registry_path: Path | None = None,
    staging_registry_path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_package_staging_registry(staging_registry_path)
    record = registry["packages"].get(staging_id)
    if not isinstance(record, dict):
        raise ValueError(f"Staged connector package not found: {staging_id}")
    if record.get("status") != "validated":
        raise ValueError(f"Staged connector package is not validated: {staging_id}")
    validation_result = record.get("validation_result") if isinstance(record.get("validation_result"), dict) else {}
    if validation_result.get("success") is False or validation_result.get("status") == "error":
        raise ValueError(f"Staged connector package validation failed: {staging_id}")

    package_root = Path(str(record.get("package_root"))).expanduser()
    current_hash = compute_connector_package_hash(package_root)
    if current_hash != record.get("package_hash"):
        raise ValueError(f"Staged connector package changed since validation: {staging_id}")

    installed = await install_connector_package(
        package_root,
        enabled=enabled,
        source="upload",
        registry_path=installed_registry_path,
        source_metadata={
            "staging_id": staging_id,
            "upload_filename": record.get("filename"),
            "upload_original_filename": record.get("original_filename"),
            "artifact_hash": record.get("artifact_hash"),
            "artifact_size": record.get("artifact_size"),
            "archive_format": record.get("archive_format"),
            "staged_at": record.get("uploaded_at"),
            "validated_at": record.get("validated_at"),
        },
    )
    now = utc_now()
    updated = dict(record)
    updated["status"] = "installed"
    updated["installed_at"] = now
    updated["installed_package_id"] = installed.get("id")
    updated["installed_version"] = installed.get("version")
    updated["updated_at"] = now
    registry["packages"][staging_id] = updated
    _append_audit(registry, "install", staging_id, status="success", metadata=_audit_metadata(updated))
    save_connector_package_staging_registry(registry, staging_registry_path)
    return installed


def discard_staged_connector_package(
    staging_id: str,
    *,
    staging_registry_path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_package_staging_registry(staging_registry_path)
    record = registry["packages"].pop(staging_id, None)
    if not isinstance(record, dict):
        raise ValueError(f"Staged connector package not found: {staging_id}")
    root_value = record.get("staging_root")
    if root_value:
        shutil.rmtree(Path(str(root_value)).expanduser(), ignore_errors=True)
    snapshot = dict(record)
    snapshot["discarded_at"] = utc_now()
    _append_audit(registry, "discard", staging_id, status="success", metadata=_audit_metadata(snapshot))
    save_connector_package_staging_registry(registry, staging_registry_path)
    return snapshot


def staging_registry_summary(staging_registry_path: Path | None = None) -> dict[str, Any]:
    registry = load_connector_package_staging_registry(staging_registry_path)
    packages = [record for record in registry["packages"].values() if isinstance(record, dict)]
    return {
        "path": str(staging_registry_path_or_default(staging_registry_path)),
        "staging_store": str(staging_store_path_or_default(staging_registry_path)),
        "version": registry.get("version"),
        "staged_packages": len(packages),
        "validated_packages": sum(1 for record in packages if record.get("status") == "validated"),
        "invalid_packages": sum(1 for record in packages if record.get("status") == "invalid"),
        "audit_events": len(registry.get("audit") or []),
    }


def _upsert_staged_record(record: dict[str, Any], staging_registry_path: Path | None, *, action: str) -> None:
    registry = load_connector_package_staging_registry(staging_registry_path)
    registry["packages"][str(record["id"])] = dict(record)
    _append_audit(registry, action, str(record["id"]), status="success", metadata=_audit_metadata(record))
    save_connector_package_staging_registry(registry, staging_registry_path)


def _mark_staged_record_invalid(
    record: dict[str, Any],
    errors: list[str],
    staging_registry_path: Path | None,
) -> dict[str, Any]:
    registry = load_connector_package_staging_registry(staging_registry_path)
    updated = dict(record)
    updated["status"] = "invalid"
    updated["errors"] = errors
    updated["validation_result"] = _failed_validation_result(updated, errors)
    updated["validated_at"] = utc_now()
    updated["updated_at"] = updated["validated_at"]
    registry["packages"][str(updated["id"])] = updated
    _append_audit(registry, "validate", str(updated["id"]), status="error", metadata=_audit_metadata(updated))
    save_connector_package_staging_registry(registry, staging_registry_path)
    return updated


def _append_audit(
    registry: dict[str, Any],
    action: str,
    staging_id: str,
    *,
    status: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    registry.setdefault("audit", []).append(
        {
            "id": f"connector-package-staging-event-{uuid4().hex}",
            "action": f"connector_package_staging.{action}",
            "staging_id": staging_id,
            "status": status,
            "created_at": utc_now(),
            "metadata": metadata or {},
        }
    )


def _audit_metadata(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "status": record.get("status"),
        "package_id": record.get("package_id"),
        "version": record.get("package_version") or record.get("version"),
        "artifact_hash": record.get("artifact_hash"),
        "package_hash": record.get("package_hash"),
    }


def _archive_format(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return "tar.gz"
    raise ValueError("Connector package artifact must be .zip, .tar.gz, or .tgz")


def _safe_filename(filename: str) -> str:
    base = Path(filename or "connector-package").name
    cleaned = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in base)
    cleaned = cleaned.strip(".-")
    return cleaned or "connector-package"


def _sha256_bytes(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _extract_archive(archive_path: Path, extract_root: Path, *, archive_format: str) -> None:
    if archive_format == "zip":
        _extract_zip(archive_path, extract_root)
    elif archive_format == "tar.gz":
        _extract_tar(archive_path, extract_root)
    else:
        raise ValueError(f"Unsupported connector package archive format: {archive_format}")


def _extract_zip(archive_path: Path, extract_root: Path) -> None:
    total_size = 0
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Connector package archive has too many entries: {len(infos)}")
        for info in infos:
            if _zip_info_is_symlink(info):
                raise ValueError(f"Connector package archive contains symlink: {info.filename}")
            target = _safe_extract_target(extract_root, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total_size += int(info.file_size)
            if total_size > MAX_EXTRACTED_BYTES:
                raise ValueError(f"Connector package archive expands beyond {MAX_EXTRACTED_BYTES} bytes")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)


def _extract_tar(archive_path: Path, extract_root: Path) -> None:
    total_size = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Connector package archive has too many entries: {len(members)}")
        for member in members:
            target = _safe_extract_target(extract_root, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(f"Connector package archive contains unsupported entry: {member.name}")
            total_size += int(member.size)
            if total_size > MAX_EXTRACTED_BYTES:
                raise ValueError(f"Connector package archive expands beyond {MAX_EXTRACTED_BYTES} bytes")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"Connector package archive entry cannot be read: {member.name}")
            with source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)


def _safe_extract_target(root: Path, raw_name: str) -> Path:
    normalized_name = raw_name.replace("\\", "/")
    pure = PurePosixPath(normalized_name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"Connector package archive path is unsafe: {raw_name}")
    target = (root / Path(*pure.parts)).resolve()
    root_resolved = root.resolve()
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"Connector package archive path escapes staging root: {raw_name}") from exc
    return target


def _zip_info_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o777777
    return stat.S_ISLNK(mode)


def _validate_extracted_tree(root: Path) -> None:
    if not root.is_dir():
        raise ValueError(f"Staged connector package directory not found: {root}")
    for path in root.rglob("*"):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Staged connector package path escapes package root: {path}") from exc
        if path.is_symlink():
            raise ValueError(f"Staged connector package contains symlink: {path}")
        if not path.is_dir() and not path.is_file():
            raise ValueError(f"Staged connector package contains unsupported filesystem entry: {path}")


def _find_extracted_package_root(extract_root: Path) -> tuple[Path, list[str]]:
    if (extract_root / "manifest.json").is_file():
        return extract_root, []
    manifests = sorted(extract_root.glob("*/manifest.json"))
    if len(manifests) == 1:
        return manifests[0].parent, []
    if len(manifests) > 1:
        return extract_root, ["Connector package artifact must contain exactly one connector package manifest."]
    return extract_root, ["Connector package artifact does not contain manifest.json."]


def _failed_validation_result(record: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    return {
        "connector_id": record.get("package_id") or record.get("id") or "unknown",
        "success": False,
        "status": "error",
        "message": "Connector package staging validation failed.",
        "capabilities": record.get("capabilities") or [],
        "adapter_contracts": {},
        "mapping_contracts": {},
        "warnings": record.get("warnings") or [],
        "errors": errors,
    }
