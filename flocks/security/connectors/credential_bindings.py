"""Credential binding store for connector package runtime env values."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import uuid4

from flocks.config.config import Config
from flocks.security.secrets import get_secret_manager


CREDENTIAL_BINDING_VERSION = "connector.credential.profiles.v1"
CREDENTIAL_BINDING_RELATIVE_PATH = Path("security") / "connector-credential-bindings.json"
SENSITIVE_ENV_MARKERS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL")
DEFAULT_PROFILE_ID = "default"
CREDENTIAL_HEALTH_VERSION = "connector.credential.health.v1"
BLOCKING_PROFILE_STATUSES = {"expired", "failed", "missing", "pending_test"}
CREDENTIAL_HEALTH_REASON_TAXONOMY = {
    "healthy": {
        "reason": "credential_profile_healthy",
        "severity": "info",
        "blocking": False,
    },
    "not_configured": {
        "reason": "credentials_not_configured",
        "severity": "info",
        "blocking": False,
    },
    "expired": {
        "reason": "credential_profile_expired",
        "severity": "critical",
        "blocking": True,
    },
    "failed": {
        "reason": "credential_profile_failed",
        "severity": "high",
        "blocking": True,
    },
    "missing": {
        "reason": "credential_profile_missing",
        "severity": "critical",
        "blocking": True,
    },
    "pending_test": {
        "reason": "credential_profile_pending_test",
        "severity": "medium",
        "blocking": True,
    },
    "not_active": {
        "reason": "credential_profile_not_active",
        "severity": "low",
        "blocking": False,
    },
}
CREDENTIAL_AUDIT_RETENTION_POLICY = {
    "max_items": 1000,
    "max_days": 730,
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_connector_credential_binding_path() -> Path:
    return Config.get_data_path() / CREDENTIAL_BINDING_RELATIVE_PATH


def credential_binding_path_or_default(path: Path | None = None) -> Path:
    return (path or default_connector_credential_binding_path()).expanduser()


def empty_connector_credential_binding_registry() -> dict[str, Any]:
    return {
        "version": CREDENTIAL_BINDING_VERSION,
        "updated_at": None,
        "bindings": {},
        "audit": [],
    }


def load_connector_credential_binding_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = credential_binding_path_or_default(path)
    if not registry_path.is_file():
        return empty_connector_credential_binding_registry()
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Connector credential binding registry must be an object: {registry_path}")
    registry = empty_connector_credential_binding_registry()
    registry.update(data)
    registry["version"] = str(registry.get("version") or CREDENTIAL_BINDING_VERSION)
    registry["bindings"] = registry.get("bindings") if isinstance(registry.get("bindings"), dict) else {}
    registry["audit"] = registry.get("audit") if isinstance(registry.get("audit"), list) else []
    return registry


def save_connector_credential_binding_registry(
    registry: dict[str, Any],
    path: Path | None = None,
) -> dict[str, Any]:
    registry_path = credential_binding_path_or_default(path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry["version"] = CREDENTIAL_BINDING_VERSION
    registry["updated_at"] = utc_now()
    registry["audit"] = _apply_audit_retention(list(registry.get("audit") or []))
    payload = json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=registry_path.parent,
        prefix=f".{registry_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write(payload)
    os.replace(tmp_path, registry_path)
    return registry


def bind_connector_credentials(
    connector_id: str,
    values: dict[str, str],
    *,
    secret_keys: list[str] | None = None,
    profile_id: str = DEFAULT_PROFILE_ID,
    profile_name: str | None = None,
    make_active: bool = True,
    expires_at: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    return _upsert_connector_credential_profile(
        connector_id,
        values,
        secret_keys=secret_keys,
        profile_id=profile_id,
        profile_name=profile_name,
        make_active=make_active,
        expires_at=expires_at,
        action="bind",
        actor=actor,
        path=path,
    )


def rotate_connector_credentials(
    connector_id: str,
    profile_id: str,
    values: dict[str, str],
    *,
    secret_keys: list[str] | None = None,
    expires_at: str | None = None,
    make_active: bool = True,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    return _upsert_connector_credential_profile(
        connector_id,
        values,
        secret_keys=secret_keys,
        profile_id=profile_id,
        make_active=make_active,
        expires_at=expires_at,
        action="rotate",
        actor=actor,
        path=path,
    )


def _upsert_connector_credential_profile(
    connector_id: str,
    values: dict[str, str],
    *,
    secret_keys: list[str] | None = None,
    profile_id: str = DEFAULT_PROFILE_ID,
    profile_name: str | None = None,
    make_active: bool = True,
    expires_at: str | None = None,
    action: str,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    connector_id = str(connector_id).strip()
    if not connector_id:
        raise ValueError("Connector credential binding requires connector_id")
    profile_id = _profile_id(profile_id)
    env_values = {str(key).strip(): str(value) for key, value in values.items() if str(key).strip()}
    registry = load_connector_credential_binding_registry(path)
    existing = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
    existing_profiles = existing.setdefault("profiles", {})
    existing_profile = existing_profiles.get(profile_id) if isinstance(existing_profiles.get(profile_id), dict) else {}
    if not env_values and not existing_profile:
        raise ValueError("Connector credential binding requires at least one env value")

    secret_key_set = {str(key) for key in (secret_keys or [])}
    now = utc_now()
    entries: dict[str, Any] = {}
    secret_manager = get_secret_manager()
    for env_name, value in sorted(env_values.items()):
        if env_name in secret_key_set or _is_sensitive_env(env_name):
            secret_id = _secret_id(connector_id, env_name, profile_id=profile_id)
            secret_manager.set(secret_id, value)
            entries[env_name] = {
                "kind": "secret",
                "secret_id": secret_id,
                "masked": secret_manager.mask(value),
                "updated_at": now,
            }
        else:
            entries[env_name] = {
                "kind": "value",
                "value": value,
                "updated_at": now,
            }

    rotation_count = int(existing_profile.get("rotation_count") or 0) + (1 if action == "rotate" else 0)
    profile = {
        "id": profile_id,
        "name": profile_name or existing_profile.get("name") or profile_id,
        "env": {**dict(existing_profile.get("env") or {}), **entries},
        "status": "pending_test" if action in {"bind", "rotate"} else existing_profile.get("status") or "untested",
        "created_at": existing_profile.get("created_at") or now,
        "updated_at": now,
        "expires_at": expires_at if expires_at is not None else existing_profile.get("expires_at"),
        "last_rotated_at": now if action == "rotate" else existing_profile.get("last_rotated_at"),
        "rotation_count": rotation_count,
        "last_test_at": existing_profile.get("last_test_at"),
        "last_test_status": existing_profile.get("last_test_status"),
        "last_test_message": existing_profile.get("last_test_message"),
        "last_sync_at": existing_profile.get("last_sync_at"),
        "last_successful_sync_at": existing_profile.get("last_successful_sync_at"),
        "last_failed_sync_at": existing_profile.get("last_failed_sync_at"),
        "last_failure_reason": existing_profile.get("last_failure_reason"),
    }
    existing_profiles[profile_id] = profile
    binding = {
        "connector_id": connector_id,
        "active_profile_id": profile_id if make_active or not existing.get("active_profile_id") else existing.get("active_profile_id"),
        "profiles": existing_profiles,
        "created_at": existing.get("created_at") or now,
        "updated_at": now,
    }
    registry["bindings"][connector_id] = binding
    _append_audit(
        registry,
        action,
        connector_id,
        profile_id=profile_id,
        status="success",
        metadata={"env_keys": sorted(entries), "make_active": bool(make_active)},
        actor=actor,
    )
    save_connector_credential_binding_registry(registry, path)
    return summarize_connector_credential_binding(binding)


def set_active_connector_credential_profile(
    connector_id: str,
    profile_id: str,
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_credential_binding_registry(path)
    binding = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
    profile_id = _profile_id(profile_id)
    if profile_id not in binding.get("profiles", {}):
        raise ValueError(f"Connector credential profile not found: {connector_id}/{profile_id}")
    binding["active_profile_id"] = profile_id
    binding["updated_at"] = utc_now()
    registry["bindings"][connector_id] = binding
    _append_audit(registry, "activate", connector_id, profile_id=profile_id, status="success", actor=actor)
    save_connector_credential_binding_registry(registry, path)
    return summarize_connector_credential_binding(binding)


def delete_connector_credentials(
    connector_id: str,
    *,
    profile_id: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_credential_binding_registry(path)
    if profile_id:
        binding = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
        normalized_profile_id = _profile_id(profile_id)
        profiles = binding.get("profiles") if isinstance(binding.get("profiles"), dict) else {}
        removed = profiles.pop(normalized_profile_id, None)
        if not isinstance(removed, dict):
            raise ValueError(f"Connector credential profile not found: {connector_id}/{normalized_profile_id}")
        if not profiles:
            registry["bindings"].pop(connector_id, None)
        else:
            if binding.get("active_profile_id") == normalized_profile_id:
                binding["active_profile_id"] = sorted(profiles.keys())[0]
            binding["updated_at"] = utc_now()
            registry["bindings"][connector_id] = binding
        _append_audit(
            registry,
            "delete_profile",
            connector_id,
            profile_id=normalized_profile_id,
            status="success",
            metadata={"env_keys": sorted((removed.get("env") or {}).keys())},
            actor=actor,
        )
        save_connector_credential_binding_registry(registry, path)
        return summarize_connector_credential_binding(registry["bindings"].get(connector_id) or _empty_binding(connector_id))

    binding = registry["bindings"].pop(connector_id, None)
    if not isinstance(binding, dict):
        raise ValueError(f"Connector credential binding not found: {connector_id}")
    binding = _normalize_binding(connector_id, binding)
    _append_audit(
        registry,
        "delete",
        connector_id,
        status="success",
        metadata={"profile_ids": sorted((binding.get("profiles") or {}).keys())},
        actor=actor,
    )
    save_connector_credential_binding_registry(registry, path)
    return summarize_connector_credential_binding(binding)


def record_connector_credential_test_result(
    connector_id: str,
    profile_id: str,
    *,
    success: bool,
    message: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    return _record_profile_status(
        connector_id,
        profile_id,
        status="ok" if success else "failed",
        test_message=message,
        test_success=success,
        audit_action="test",
        actor=actor,
        path=path,
    )


def record_connector_credential_sync_result(
    connector_id: str,
    profile_id: str | None,
    *,
    success: bool,
    run_id: str | None = None,
    message: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any] | None:
    registry = load_connector_credential_binding_registry(path)
    binding = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
    if not binding.get("profiles"):
        return None
    resolved_profile_id = _profile_id(profile_id or binding.get("active_profile_id") or DEFAULT_PROFILE_ID)
    if resolved_profile_id not in binding["profiles"]:
        return None
    return _record_profile_status(
        connector_id,
        resolved_profile_id,
        status="ok" if success else "failed",
        sync_message=message,
        sync_success=success,
        run_id=run_id,
        audit_action="sync_success" if success else "sync_failure",
        actor=actor,
        path=path,
    )


def _record_profile_status(
    connector_id: str,
    profile_id: str,
    *,
    status: str,
    test_message: str | None = None,
    test_success: bool | None = None,
    sync_message: str | None = None,
    sync_success: bool | None = None,
    run_id: str | None = None,
    audit_action: str,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_credential_binding_registry(path)
    binding = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
    profile_id = _profile_id(profile_id)
    profile = binding.get("profiles", {}).get(profile_id)
    if not isinstance(profile, dict):
        raise ValueError(f"Connector credential profile not found: {connector_id}/{profile_id}")
    now = utc_now()
    profile["status"] = status
    profile["updated_at"] = now
    if test_success is not None:
        profile["last_test_at"] = now
        profile["last_test_status"] = "success" if test_success else "error"
        profile["last_test_message"] = test_message
        if test_success:
            profile["last_failure_reason"] = None
        else:
            profile["last_failure_reason"] = test_message
    if sync_success is not None:
        profile["last_sync_at"] = now
        profile["last_sync_run_id"] = run_id
        if sync_success:
            profile["last_successful_sync_at"] = now
            profile["last_failure_reason"] = None
        else:
            profile["last_failed_sync_at"] = now
            profile["last_failure_reason"] = sync_message
    binding["profiles"][profile_id] = profile
    binding["updated_at"] = now
    registry["bindings"][connector_id] = binding
    _append_audit(
        registry,
        audit_action,
        connector_id,
        profile_id=profile_id,
        status="success" if status == "ok" else status,
        metadata={"message": test_message or sync_message, "run_id": run_id},
        actor=actor,
    )
    save_connector_credential_binding_registry(registry, path)
    return summarize_connector_credential_binding(binding)


def list_connector_credential_bindings(path: Path | None = None) -> list[dict[str, Any]]:
    registry = load_connector_credential_binding_registry(path)
    bindings = [
        summarize_connector_credential_binding(_normalize_binding(str(connector_id), binding))
        for connector_id, binding in registry["bindings"].items()
        if isinstance(binding, dict)
    ]
    bindings.sort(key=lambda item: str(item.get("connector_id") or ""))
    return bindings


def get_connector_credential_binding(connector_id: str, *, path: Path | None = None) -> dict[str, Any] | None:
    registry = load_connector_credential_binding_registry(path)
    binding = registry["bindings"].get(connector_id)
    return summarize_connector_credential_binding(_normalize_binding(connector_id, binding)) if isinstance(binding, dict) else None


def get_connector_credential_health(
    connector_id: str,
    *,
    profile_id: str | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Return the run-gating health state for a connector credential profile."""
    registry = load_connector_credential_binding_registry(path)
    binding = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
    resolved_profile_id = _profile_id(profile_id or binding.get("active_profile_id") or DEFAULT_PROFILE_ID)
    profiles = binding.get("profiles") if isinstance(binding.get("profiles"), dict) else {}
    profile = profiles.get(resolved_profile_id) if isinstance(profiles, dict) else None
    is_active = resolved_profile_id == _profile_id(binding.get("active_profile_id") or DEFAULT_PROFILE_ID)
    if not profiles and profile_id is None:
        return _credential_health_result(
            connector_id,
            resolved_profile_id,
            status="not_configured",
            reason_code="not_configured",
            message="No credential profile is configured; connector sync can run without credential env values.",
            actions=[_credential_action("bind_credentials", connector_id, resolved_profile_id)],
        )
    if not isinstance(profile, dict):
        return _credential_health_result(
            connector_id,
            resolved_profile_id,
            status="missing",
            reason_code="missing",
            message=f"Credential profile is missing: {connector_id}/{resolved_profile_id}",
            actions=[
                _credential_action("bind_credentials", connector_id, resolved_profile_id),
                _credential_action("activate_profile", connector_id, resolved_profile_id),
            ],
        )

    runtime_status = _profile_runtime_status(profile)
    actions = [_credential_action("test_profile", connector_id, resolved_profile_id, profile=profile)]
    if runtime_status in {"expired", "failed", "pending_test", "untested"}:
        actions.append(_credential_action("rotate_credentials", connector_id, resolved_profile_id, profile=profile))
    if not is_active:
        actions.append(_credential_action("activate_profile", connector_id, resolved_profile_id, profile=profile))
    if runtime_status == "expired":
        return _credential_health_result(
            connector_id,
            resolved_profile_id,
            status=runtime_status,
            reason_code="expired",
            message=f"Credential profile expired at {profile.get('expires_at')}",
            profile=profile,
            profile_active=is_active,
            actions=actions,
        )
    if runtime_status == "failed":
        message = str(profile.get("last_failure_reason") or profile.get("last_test_message") or "Credential profile failed validation")
        return _credential_health_result(
            connector_id,
            resolved_profile_id,
            status=runtime_status,
            reason_code="failed",
            message=message,
            profile=profile,
            profile_active=is_active,
            actions=actions,
        )
    if runtime_status in {"pending_test", "untested"}:
        return _credential_health_result(
            connector_id,
            resolved_profile_id,
            status="pending_test",
            reason_code="pending_test",
            message="Credential profile must pass a connection test before connector sync can run.",
            profile=profile,
            profile_active=is_active,
            actions=actions,
        )
    if not is_active:
        return _credential_health_result(
            connector_id,
            resolved_profile_id,
            status=runtime_status,
            reason_code="not_active",
            message="Credential profile is healthy but is not the active profile for default connector sync.",
            profile=profile,
            profile_active=is_active,
            actions=actions,
        )
    return _credential_health_result(
        connector_id,
        resolved_profile_id,
        status=runtime_status,
        reason_code="healthy",
        message="Credential profile is eligible for connector sync.",
        profile=profile,
        profile_active=is_active,
        actions=actions,
    )


def get_connector_credential_env(
    connector_id: str,
    *,
    profile_id: str | None = None,
    path: Path | None = None,
) -> dict[str, str]:
    registry = load_connector_credential_binding_registry(path)
    binding = _normalize_binding(connector_id, registry["bindings"].get(connector_id))
    if not isinstance(binding, dict):
        return {}
    resolved_profile_id = _profile_id(profile_id or binding.get("active_profile_id") or DEFAULT_PROFILE_ID)
    profile = (binding.get("profiles") or {}).get(resolved_profile_id)
    if not isinstance(profile, dict):
        return {}
    env: dict[str, str] = {}
    secret_manager = get_secret_manager()
    for env_name, entry in (profile.get("env") or {}).items():
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") == "secret":
            value = secret_manager.get(str(entry.get("secret_id") or ""))
        else:
            value = entry.get("value")
        if value is not None:
            env[str(env_name)] = str(value)
    return env


def summarize_connector_credential_binding(binding: dict[str, Any]) -> dict[str, Any]:
    binding = _normalize_binding(str(binding.get("connector_id") or ""), binding)
    active_profile_id = _profile_id(binding.get("active_profile_id") or DEFAULT_PROFILE_ID)
    profiles = []
    active_env_summary: dict[str, Any] = {}
    for profile_id, profile in sorted((binding.get("profiles") or {}).items()):
        if not isinstance(profile, dict):
            continue
        env_summary = _summarize_env(profile.get("env") or {})
        profile_summary = {
            "id": profile_id,
            "name": profile.get("name") or profile_id,
            "status": _profile_runtime_status(profile),
            "env": env_summary,
            "env_keys": sorted(env_summary.keys()),
            "active": profile_id == active_profile_id,
            "expires_at": profile.get("expires_at"),
            "expired": _is_expired(profile.get("expires_at")),
            "rotation_count": int(profile.get("rotation_count") or 0),
            "last_rotated_at": profile.get("last_rotated_at"),
            "last_test_at": profile.get("last_test_at"),
            "last_test_status": profile.get("last_test_status"),
            "last_test_message": profile.get("last_test_message"),
            "last_sync_at": profile.get("last_sync_at"),
            "last_successful_sync_at": profile.get("last_successful_sync_at"),
            "last_failed_sync_at": profile.get("last_failed_sync_at"),
            "last_sync_run_id": profile.get("last_sync_run_id"),
            "last_failure_reason": profile.get("last_failure_reason"),
            "created_at": profile.get("created_at"),
            "updated_at": profile.get("updated_at"),
        }
        profiles.append(profile_summary)
        if profile_id == active_profile_id:
            active_env_summary = env_summary
    return {
        "connector_id": binding.get("connector_id"),
        "active_profile_id": active_profile_id,
        "active_profile": next((profile for profile in profiles if profile["id"] == active_profile_id), None),
        "profiles": profiles,
        "profile_count": len(profiles),
        "env": active_env_summary,
        "env_keys": sorted(active_env_summary.keys()),
        "created_at": binding.get("created_at"),
        "updated_at": binding.get("updated_at"),
    }


def credential_binding_summary(path: Path | None = None) -> dict[str, Any]:
    registry = load_connector_credential_binding_registry(path)
    bindings = [
        _normalize_binding(str(connector_id), binding)
        for connector_id, binding in registry["bindings"].items()
        if isinstance(binding, dict)
    ]
    profiles = [
        profile
        for binding in bindings
        for profile in (binding.get("profiles") or {}).values()
        if isinstance(profile, dict)
    ]
    return {
        "path": str(credential_binding_path_or_default(path)),
        "version": registry.get("version"),
        "bindings": len(bindings),
        "profiles": len(profiles),
        "expired_profiles": sum(1 for profile in profiles if _is_expired(profile.get("expires_at"))),
        "failed_profiles": sum(1 for profile in profiles if _profile_runtime_status(profile) == "failed"),
        "audit_events": len(registry.get("audit") or []),
        "audit_retention": dict(CREDENTIAL_AUDIT_RETENTION_POLICY),
    }


def _credential_health_result(
    connector_id: str,
    profile_id: str,
    *,
    status: str,
    reason_code: str,
    message: str,
    profile: dict[str, Any] | None = None,
    profile_active: bool | None = None,
    actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    reason_meta = CREDENTIAL_HEALTH_REASON_TAXONOMY.get(reason_code, CREDENTIAL_HEALTH_REASON_TAXONOMY["failed"])
    healthy = not bool(reason_meta["blocking"])
    profile_summary: dict[str, Any] | None = None
    if isinstance(profile, dict):
        profile_summary = {
            "id": profile_id,
            "name": profile.get("name") or profile_id,
            "status": status,
            "active": bool(profile_active),
            "expires_at": profile.get("expires_at"),
            "expired": _is_expired(profile.get("expires_at")),
            "last_test_at": profile.get("last_test_at"),
            "last_test_status": profile.get("last_test_status"),
            "last_test_message": profile.get("last_test_message"),
            "last_sync_at": profile.get("last_sync_at"),
            "last_successful_sync_at": profile.get("last_successful_sync_at"),
            "last_failed_sync_at": profile.get("last_failed_sync_at"),
            "last_failure_reason": profile.get("last_failure_reason"),
            "rotation_count": int(profile.get("rotation_count") or 0),
        }
    return {
        "version": CREDENTIAL_HEALTH_VERSION,
        "connector_id": connector_id,
        "profile_id": profile_id,
        "status": status,
        "healthy": bool(healthy),
        "blocking": not healthy,
        "reason": reason_meta["reason"],
        "reason_code": reason_code,
        "reason_taxonomy": "credential_health_reason.v1",
        "severity": reason_meta["severity"],
        "message": message,
        "checked_at": utc_now(),
        "profile_active": bool(profile_active) if profile_active is not None else None,
        "profile": profile_summary,
        "actions": actions or [],
    }


def _credential_action(action: str, connector_id: str, profile_id: str, *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    base = f"/api/security/connectors/{connector_id}/credentials"
    if action == "bind_credentials":
        return {
            "id": action,
            "kind": action,
            "label": "Bind credentials",
            "method": "PUT",
            "path": base,
            "connector_id": connector_id,
            "profile_id": profile_id,
        }
    profile_base = f"{base}/profiles/{profile_id}"
    labels = {
        "test_profile": "Test profile",
        "rotate_credentials": "Rotate credentials",
        "activate_profile": "Activate profile",
    }
    paths = {
        "test_profile": f"{profile_base}/test",
        "rotate_credentials": f"{profile_base}/rotate",
        "activate_profile": f"{profile_base}/activate",
    }
    payload = {
        "id": action,
        "kind": action,
        "label": labels.get(action, action),
        "method": "POST",
        "path": paths.get(action, profile_base),
        "connector_id": connector_id,
        "profile_id": profile_id,
    }
    if isinstance(profile, dict):
        payload["profile_expires_at"] = profile.get("expires_at")
    return payload


def _append_audit(
    registry: dict[str, Any],
    action: str,
    connector_id: str,
    *,
    profile_id: str | None = None,
    status: str,
    metadata: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
) -> None:
    registry.setdefault("audit", []).append(
        {
            "id": f"connector-credential-event-{uuid4().hex}",
            "action": f"connector_credential.{action}",
            "connector_id": connector_id,
            "profile_id": profile_id,
            "status": status,
            "created_at": utc_now(),
            "actor": _actor(actor),
            "metadata": metadata or {},
        }
    )


def _actor(actor: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(actor, dict):
        return {"type": "system", "id": "system", "username": "system", "role": "system"}
    return {
        "type": str(actor.get("type") or "user"),
        "id": str(actor.get("id") or actor.get("username") or "unknown"),
        "username": str(actor.get("username") or actor.get("id") or "unknown"),
        "role": str(actor.get("role") or ""),
    }


def _is_sensitive_env(env_name: str) -> bool:
    upper = env_name.upper()
    return any(marker in upper for marker in SENSITIVE_ENV_MARKERS)


def _secret_id(connector_id: str, env_name: str, *, profile_id: str = DEFAULT_PROFILE_ID) -> str:
    return f"connector_{_safe_segment(connector_id)}_{_safe_segment(profile_id)}_{_safe_segment(env_name)}"


def _profile_id(value: Any) -> str:
    text = str(value or DEFAULT_PROFILE_ID).strip()
    return _safe_segment(text) or DEFAULT_PROFILE_ID


def normalize_connector_credential_profile_id(value: Any) -> str:
    return _profile_id(value)


def _empty_binding(connector_id: str) -> dict[str, Any]:
    return {
        "connector_id": connector_id,
        "active_profile_id": DEFAULT_PROFILE_ID,
        "profiles": {},
        "created_at": None,
        "updated_at": None,
    }


def _normalize_binding(connector_id: str, binding: Any) -> dict[str, Any]:
    if not isinstance(binding, dict):
        return _empty_binding(connector_id)
    connector_id = str(binding.get("connector_id") or connector_id)
    profiles = binding.get("profiles") if isinstance(binding.get("profiles"), dict) else {}
    if not profiles and isinstance(binding.get("env"), dict):
        profiles = {
            DEFAULT_PROFILE_ID: {
                "id": DEFAULT_PROFILE_ID,
                "name": DEFAULT_PROFILE_ID,
                "env": dict(binding.get("env") or {}),
                "status": "untested",
                "created_at": binding.get("created_at"),
                "updated_at": binding.get("updated_at"),
                "expires_at": None,
                "rotation_count": 0,
            }
        }
    active_profile_id = _profile_id(binding.get("active_profile_id") or DEFAULT_PROFILE_ID)
    if active_profile_id not in profiles and profiles:
        active_profile_id = sorted(profiles.keys())[0]
    return {
        "connector_id": connector_id,
        "active_profile_id": active_profile_id,
        "profiles": profiles,
        "created_at": binding.get("created_at"),
        "updated_at": binding.get("updated_at"),
    }


def _summarize_env(env: dict[str, Any]) -> dict[str, Any]:
    env_summary: dict[str, Any] = {}
    for env_name, entry in env.items():
        if not isinstance(entry, dict):
            continue
        env_summary[str(env_name)] = {
            "kind": entry.get("kind"),
            "configured": bool(entry.get("secret_id") or entry.get("value") is not None),
            "masked": entry.get("masked") if entry.get("kind") == "secret" else None,
            "updated_at": entry.get("updated_at"),
        }
    return env_summary


def _profile_runtime_status(profile: dict[str, Any]) -> str:
    if _is_expired(profile.get("expires_at")):
        return "expired"
    status = str(profile.get("status") or profile.get("last_test_status") or "untested")
    if status == "error":
        return "failed"
    return status


def _is_expired(expires_at: Any) -> bool:
    if not isinstance(expires_at, str) or not expires_at:
        return False
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return parsed <= datetime.now(UTC)


def _apply_audit_retention(records: list[Any]) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC).timestamp() - (int(CREDENTIAL_AUDIT_RETENTION_POLICY["max_days"]) * 86400)
    kept: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        timestamp = _audit_timestamp(record)
        if timestamp is not None and timestamp < cutoff:
            continue
        kept.append(record)
    kept.sort(key=lambda item: _audit_timestamp(item) or 0)
    return kept[-int(CREDENTIAL_AUDIT_RETENTION_POLICY["max_items"]):]


def _audit_timestamp(record: dict[str, Any]) -> float | None:
    value = record.get("created_at")
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _safe_segment(value: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in value.lower())
    return "_".join(part for part in cleaned.split("_") if part) or "unknown"
