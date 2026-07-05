"""Connector sync schedule registry and lightweight run orchestrator."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
from time import perf_counter
from typing import Any
from uuid import uuid4

from flocks.config.config import Config


SYNC_SCHEDULE_REGISTRY_VERSION = "connector.sync.schedules.v1"
SYNC_SCHEDULE_REGISTRY_RELATIVE_PATH = Path("security") / "connector-sync-schedules.json"
SUPPORTED_SYNC_MODES = {"full", "incremental"}
DEFAULT_INTERVAL_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_RETRY_BACKOFF_SECONDS = 60
POLICY_RECOVERY_MODES = {"preview", "clear", "enable"}
SCHEDULE_AUDIT_RETENTION_POLICY = {
    "max_items": 1000,
    "max_days": 730,
}
_schedule_locks: dict[str, asyncio.Lock] = {}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_connector_sync_schedule_registry_path() -> Path:
    return Config.get_data_path() / SYNC_SCHEDULE_REGISTRY_RELATIVE_PATH


def sync_schedule_registry_path_or_default(path: Path | None = None) -> Path:
    return (path or default_connector_sync_schedule_registry_path()).expanduser()


def empty_connector_sync_schedule_registry() -> dict[str, Any]:
    return {
        "version": SYNC_SCHEDULE_REGISTRY_VERSION,
        "updated_at": None,
        "schedules": {},
        "audit": [],
    }


def load_connector_sync_schedule_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = sync_schedule_registry_path_or_default(path)
    if not registry_path.is_file():
        return empty_connector_sync_schedule_registry()
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Connector sync schedule registry must be an object: {registry_path}")
    registry = empty_connector_sync_schedule_registry()
    registry.update(data)
    registry["version"] = str(registry.get("version") or SYNC_SCHEDULE_REGISTRY_VERSION)
    registry["schedules"] = registry.get("schedules") if isinstance(registry.get("schedules"), dict) else {}
    registry["audit"] = registry.get("audit") if isinstance(registry.get("audit"), list) else []
    return registry


def save_connector_sync_schedule_registry(registry: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    registry_path = sync_schedule_registry_path_or_default(path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry["version"] = SYNC_SCHEDULE_REGISTRY_VERSION
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


def connector_sync_schedule_id(connector_id: str, capability: str) -> str:
    return f"{connector_id}:{capability}"


def _credential_profile_id(value: str | None) -> str | None:
    if value is None:
        return None
    from flocks.security.connectors.credential_bindings import normalize_connector_credential_profile_id

    return normalize_connector_credential_profile_id(value)


def list_connector_sync_schedules(
    *,
    connector_id: str | None = None,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    registry = load_connector_sync_schedule_registry(path)
    schedules = [_with_runtime_status(dict(item)) for item in registry["schedules"].values() if isinstance(item, dict)]
    if connector_id:
        schedules = [item for item in schedules if item.get("connector_id") == connector_id]
    schedules.sort(key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""), reverse=True)
    return schedules


def get_connector_sync_schedule(schedule_id: str, *, path: Path | None = None) -> dict[str, Any] | None:
    registry = load_connector_sync_schedule_registry(path)
    schedule = registry["schedules"].get(schedule_id)
    return _with_runtime_status(dict(schedule)) if isinstance(schedule, dict) else None


def upsert_connector_sync_schedule(
    connector_id: str,
    capability: str,
    *,
    enabled: bool = False,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    mode: str = "incremental",
    full_interval_seconds: int | None = None,
    retry_max_attempts: int = 1,
    retry_backoff_seconds: int = DEFAULT_RETRY_BACKOFF_SECONDS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    credential_profile_id: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    _validate_schedule_values(
        capability=capability,
        interval_seconds=interval_seconds,
        mode=mode,
        full_interval_seconds=full_interval_seconds,
        retry_max_attempts=retry_max_attempts,
        retry_backoff_seconds=retry_backoff_seconds,
        timeout_seconds=timeout_seconds,
    )
    registry = load_connector_sync_schedule_registry(path)
    schedule_id = connector_sync_schedule_id(connector_id, capability)
    now = utc_now()
    existing = registry["schedules"].get(schedule_id)
    record = dict(existing) if isinstance(existing, dict) else {}
    previous_interval = int(record.get("interval_seconds") or DEFAULT_INTERVAL_SECONDS)
    previous_enabled = bool(record.get("enabled"))
    normalized_credential_profile_id = _credential_profile_id(credential_profile_id)
    record.update(
        {
            "id": schedule_id,
            "connector_id": connector_id,
            "capability": capability,
            "enabled": bool(enabled),
            "interval_seconds": int(interval_seconds),
            "mode": mode,
            "full_interval_seconds": int(full_interval_seconds) if full_interval_seconds else None,
            "retry_max_attempts": int(retry_max_attempts),
            "retry_backoff_seconds": int(retry_backoff_seconds),
            "timeout_seconds": int(timeout_seconds),
            "credential_profile_id": normalized_credential_profile_id,
            "updated_at": now,
        }
    )
    record.setdefault("created_at", now)
    record.setdefault("last_run_id", None)
    record.setdefault("last_run_at", None)
    record.setdefault("last_successful_run_at", None)
    record.setdefault("last_failed_run_at", None)
    record.setdefault("last_status", None)
    record.setdefault("last_error", None)
    record.setdefault("last_trigger", None)
    record.setdefault("last_duration_ms", None)
    record.setdefault("consecutive_failures", 0)
    record.setdefault("run_count", 0)
    record.setdefault("manual_run_count", 0)
    record.setdefault("scheduled_run_count", 0)
    record.setdefault("policy_state", None)
    record.setdefault("policy_reason", None)
    record.setdefault("policy_reason_code", None)
    record.setdefault("policy_message", None)
    record.setdefault("policy_actions", [])
    record.setdefault("policy_paused_at", None)
    if enabled:
        _clear_policy_pause(record)
    interval_changed = previous_interval != int(interval_seconds)
    enabled_changed = previous_enabled != bool(enabled)
    if bool(enabled) and (interval_changed or enabled_changed):
        record["next_run_at"] = _next_time(int(interval_seconds), base=now)
    else:
        record["next_run_at"] = _coerce_next_run(record.get("next_run_at"), now, int(interval_seconds), bool(enabled))
    record["next_full_run_at"] = _coerce_next_full_run(record, now)
    registry["schedules"][schedule_id] = record
    _append_audit(registry, "upsert", schedule_id, {"enabled": bool(enabled)}, actor=actor)
    save_connector_sync_schedule_registry(registry, path)
    return _with_runtime_status(record)


def enable_connector_sync_schedule(
    schedule_id: str,
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_sync_schedule_registry(path)
    record = _require_schedule(registry, schedule_id)
    was_policy_paused = record.get("policy_state") == "paused"
    previous_policy = _policy_snapshot(record) if was_policy_paused else None
    record["enabled"] = True
    _clear_policy_pause(record)
    record["updated_at"] = utc_now()
    record["next_run_at"] = record.get("next_run_at") or _next_time(int(record.get("interval_seconds") or DEFAULT_INTERVAL_SECONDS))
    _append_audit(
        registry,
        "enable",
        schedule_id,
        {
            "recovered_policy_pause": was_policy_paused,
            "previous_policy": previous_policy,
        },
        actor=actor,
    )
    if was_policy_paused:
        _append_audit(
            registry,
            "policy_recovered",
            schedule_id,
            {
                "mode": "manual_enable",
                "connector_id": record.get("connector_id"),
                "credential_profile_id": record.get("credential_profile_id"),
                "previous_policy": previous_policy,
            },
            actor=actor,
        )
    save_connector_sync_schedule_registry(registry, path)
    return _with_runtime_status(record)


def disable_connector_sync_schedule(
    schedule_id: str,
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_sync_schedule_registry(path)
    record = _require_schedule(registry, schedule_id)
    record["enabled"] = False
    _clear_policy_pause(record)
    record["updated_at"] = utc_now()
    _append_audit(registry, "disable", schedule_id, actor=actor)
    save_connector_sync_schedule_registry(registry, path)
    return _with_runtime_status(record)


def delete_connector_sync_schedule(
    schedule_id: str,
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_sync_schedule_registry(path)
    record = _require_schedule(registry, schedule_id)
    removed = dict(record)
    registry["schedules"].pop(schedule_id, None)
    _append_audit(registry, "delete", schedule_id, {"record": removed}, actor=actor)
    save_connector_sync_schedule_registry(registry, path)
    return {**_with_runtime_status(removed), "deleted_at": utc_now()}


def sync_schedule_summary(path: Path | None = None) -> dict[str, Any]:
    registry = load_connector_sync_schedule_registry(path)
    schedules = [item for item in registry["schedules"].values() if isinstance(item, dict)]
    enabled = [item for item in schedules if item.get("enabled")]
    due = [item for item in enabled if _is_due(item)]
    running = [item for item in schedules if _is_locked(str(item.get("id") or ""))]
    policy_paused = [item for item in schedules if item.get("policy_state") == "paused"]
    return {
        "path": str(sync_schedule_registry_path_or_default(path)),
        "version": registry.get("version"),
        "schedules": len(schedules),
        "enabled": len(enabled),
        "due": len(due),
        "running": len(running),
        "policy_paused": len(policy_paused),
        "policy_paused_reasons": _reason_counts(policy_paused),
        "audit": len(registry["audit"]),
        "audit_retention": dict(SCHEDULE_AUDIT_RETENTION_POLICY),
    }


def recover_policy_paused_schedules_for_credential(
    connector_id: str,
    profile_id: str,
    *,
    mode: str = "preview",
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Preview or recover schedules paused by a now-healthy credential profile."""
    mode = str(mode or "preview")
    if mode not in POLICY_RECOVERY_MODES:
        raise ValueError(f"Unsupported connector sync schedule recovery mode: {mode}")
    profile_id = _credential_profile_id(profile_id) or ""
    registry = load_connector_sync_schedule_registry(path)
    candidates = [
        record
        for record in registry["schedules"].values()
        if isinstance(record, dict)
        and record.get("connector_id") == connector_id
        and record.get("credential_profile_id") == profile_id
        and record.get("policy_state") == "paused"
    ]
    result = {
        "version": "connector.sync.schedule.recovery.v1",
        "mode": mode,
        "connector_id": connector_id,
        "profile_id": profile_id,
        "matched": len(candidates),
        "recovered": 0,
        "requires_confirmation": mode == "preview" and bool(candidates),
        "schedules": [_with_runtime_status(dict(record)) for record in candidates],
    }
    if mode == "preview" or not candidates:
        return result

    now = utc_now()
    recovered_records: list[dict[str, Any]] = []
    for record in candidates:
        schedule_id = str(record.get("id") or "")
        previous_policy = _policy_snapshot(record)
        if mode == "enable":
            record["enabled"] = True
            record["next_run_at"] = _next_time(int(record.get("interval_seconds") or DEFAULT_INTERVAL_SECONDS), base=now)
        _clear_policy_pause(record)
        record["updated_at"] = now
        _append_audit(
            registry,
            "policy_recovered",
            schedule_id,
            {
                "mode": mode,
                "connector_id": connector_id,
                "credential_profile_id": profile_id,
                "previous_policy": previous_policy,
                "enabled": bool(record.get("enabled")),
            },
            actor=actor,
        )
        recovered_records.append(_with_runtime_status(dict(record)))
    save_connector_sync_schedule_registry(registry, path)
    result["recovered"] = len(recovered_records)
    result["requires_confirmation"] = False
    result["schedules"] = recovered_records
    return result


async def run_connector_sync_schedule(
    schedule_id: str,
    *,
    trigger: str = "manual",
    mode: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_sync_schedule_registry(path)
    record = _require_schedule(registry, schedule_id)
    if trigger == "scheduled" and not record.get("enabled"):
        return {"status": "skipped", "reason": "schedule_disabled", "schedule": _with_runtime_status(record), "run": None}
    lock = _schedule_locks.setdefault(schedule_id, asyncio.Lock())
    if lock.locked():
        return {"status": "busy", "reason": "schedule_already_running", "schedule": _with_runtime_status(record), "run": None}

    async with lock:
        started = perf_counter()
        run_mode = mode or _selected_mode(record)
        attempts = max(1, int(record.get("retry_max_attempts") or 1))
        backoff = max(0, int(record.get("retry_backoff_seconds") or 0))
        timeout = max(1, int(record.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS))
        last_run: dict[str, Any] | None = None
        errors: list[str] = []
        for attempt in range(1, attempts + 1):
            try:
                run = await asyncio.wait_for(
                    _run_connector_sync(record, mode=run_mode, trigger=trigger, schedule_id=schedule_id),
                    timeout=timeout,
                )
            except Exception as exc:
                run = _orchestration_error_run(record, run_mode, exc)
            run["orchestration"] = {
                "schedule_id": schedule_id,
                "trigger": trigger,
                "attempt": attempt,
                "attempts": attempts,
                "timeout_seconds": timeout,
            }
            last_run = run
            if run.get("status") != "error":
                break
            errors.extend(str(item) for item in run.get("errors", []))
            if attempt < attempts and backoff > 0:
                await asyncio.sleep(backoff * attempt)

        registry = load_connector_sync_schedule_registry(path)
        current = _require_schedule(registry, schedule_id)
        was_policy_paused = current.get("policy_state") == "paused"
        previous_policy = _policy_snapshot(current) if was_policy_paused else None
        finished_at = utc_now()
        _apply_run_outcome(
            current,
            run=last_run or {},
            trigger=trigger,
            mode=run_mode,
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
            errors=errors,
            finished_at=finished_at,
        )
        if current.get("policy_state") == "paused":
            _append_audit(
                registry,
                "policy_pause",
                schedule_id,
                {
                    "run_id": (last_run or {}).get("id"),
                    "status": current.get("last_status"),
                    "reason": current.get("policy_reason"),
                    "reason_code": current.get("policy_reason_code"),
                    "message": current.get("policy_message"),
                    "credential_profile_id": current.get("credential_profile_id"),
                },
                actor=actor,
            )
        elif was_policy_paused and current.get("policy_state") is None:
            _append_audit(
                registry,
                "policy_recovered",
                schedule_id,
                {
                    "mode": "successful_manual_run",
                    "run_id": (last_run or {}).get("id"),
                    "connector_id": current.get("connector_id"),
                    "credential_profile_id": current.get("credential_profile_id"),
                    "previous_policy": previous_policy,
                    "enabled": bool(current.get("enabled")),
                },
                actor=actor,
            )
        _append_audit(registry, "run", schedule_id, {"trigger": trigger, "status": current.get("last_status")}, actor=actor)
        save_connector_sync_schedule_registry(registry, path)
        return {
            "status": current.get("last_status"),
            "schedule": _with_runtime_status(current),
            "run": last_run,
        }


async def run_due_connector_sync_schedules(*, path: Path | None = None) -> dict[str, Any]:
    due = [item for item in list_connector_sync_schedules(path=path) if item.get("enabled") and _is_due(item)]
    results = []
    for schedule in due:
        results.append(await run_connector_sync_schedule(str(schedule["id"]), trigger="scheduled", path=path))
    return {
        "checked_at": utc_now(),
        "due": len(due),
        "ran": sum(1 for item in results if item.get("run")),
        "busy": sum(1 for item in results if item.get("status") == "busy"),
        "results": results,
    }


class ConnectorSyncScheduler:
    """In-process periodic worker for connector sync schedules."""

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._poll_interval = 30
        self._registry_path: Path | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self, *, poll_interval: int = 30, registry_path: Path | None = None) -> None:
        if self.running:
            return
        self._poll_interval = max(1, int(poll_interval))
        self._registry_path = registry_path
        self._task = asyncio.create_task(self._loop(), name="connector-sync-scheduler")

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def tick(self) -> dict[str, Any]:
        return await run_due_connector_sync_schedules(path=self._registry_path)

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "poll_interval_seconds": self._poll_interval,
            "registry_path": str(sync_schedule_registry_path_or_default(self._registry_path)),
        }

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
                pass
            await asyncio.sleep(self._poll_interval)


connector_sync_scheduler = ConnectorSyncScheduler()


def _validate_schedule_values(
    *,
    capability: str,
    interval_seconds: int,
    mode: str,
    full_interval_seconds: int | None,
    retry_max_attempts: int,
    retry_backoff_seconds: int,
    timeout_seconds: int,
) -> None:
    if not capability:
        raise ValueError("Connector sync schedule capability is required")
    if mode not in SUPPORTED_SYNC_MODES:
        raise ValueError(f"Unsupported connector sync schedule mode: {mode}")
    if int(interval_seconds) < 1:
        raise ValueError("Connector sync schedule interval_seconds must be >= 1")
    if full_interval_seconds is not None and int(full_interval_seconds) < 1:
        raise ValueError("Connector sync schedule full_interval_seconds must be >= 1")
    if int(retry_max_attempts) < 1:
        raise ValueError("Connector sync schedule retry_max_attempts must be >= 1")
    if int(retry_backoff_seconds) < 0:
        raise ValueError("Connector sync schedule retry_backoff_seconds must be >= 0")
    if int(timeout_seconds) < 1:
        raise ValueError("Connector sync schedule timeout_seconds must be >= 1")


def _require_schedule(registry: dict[str, Any], schedule_id: str) -> dict[str, Any]:
    record = registry["schedules"].get(schedule_id)
    if not isinstance(record, dict):
        raise ValueError(f"Connector sync schedule not found: {schedule_id}")
    return record


def _with_runtime_status(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("policy_state") == "paused":
        runtime_status = "policy_paused"
    elif _is_locked(str(record.get("id") or "")):
        runtime_status = "running"
    elif record.get("enabled"):
        runtime_status = "enabled"
    else:
        runtime_status = "disabled"
    record["runtime_status"] = runtime_status
    record["due"] = bool(record.get("enabled") and record.get("policy_state") != "paused" and _is_due(record))
    return record


def _is_locked(schedule_id: str) -> bool:
    lock = _schedule_locks.get(schedule_id)
    return bool(lock and lock.locked())


def _is_due(record: dict[str, Any]) -> bool:
    next_run_at = record.get("next_run_at")
    if not isinstance(next_run_at, str) or not next_run_at:
        return True
    due_at = _parse_datetime(next_run_at)
    return due_at is None or due_at <= datetime.now(UTC)


def _selected_mode(record: dict[str, Any]) -> str:
    full_interval = record.get("full_interval_seconds")
    next_full = record.get("next_full_run_at")
    if full_interval and isinstance(next_full, str):
        due_at = _parse_datetime(next_full)
        if due_at is None or due_at <= datetime.now(UTC):
            return "full"
    return str(record.get("mode") or "incremental")


async def _run_connector_sync(record: dict[str, Any], *, mode: str, trigger: str, schedule_id: str) -> dict[str, Any]:
    from flocks.security.connectors.registry import connector_registry

    return await connector_registry.sync(
        str(record["connector_id"]),
        str(record["capability"]),
        mode=mode,
        trigger=trigger,
        schedule_id=schedule_id,
        credential_profile_id=record.get("credential_profile_id"),
    )


def _orchestration_error_run(record: dict[str, Any], mode: str, exc: Exception) -> dict[str, Any]:
    return {
        "id": f"connector-orchestration-error-{uuid4().hex}",
        "connector_id": record.get("connector_id"),
        "capability": record.get("capability"),
        "sync_mode": mode,
        "status": "error",
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "duration_ms": 0,
        "source": "orchestrator",
        "counts": {},
        "object_ids": {},
        "skipped_counts": {},
        "quality": {},
        "dead_letter_count": 0,
        "warnings": [],
        "errors": [str(exc)],
    }


def _apply_run_outcome(
    record: dict[str, Any],
    *,
    run: dict[str, Any],
    trigger: str,
    mode: str,
    duration_ms: int,
    errors: list[str],
    finished_at: str,
) -> None:
    status = str(run.get("status") or "error")
    is_error = status == "error"
    is_blocked = status == "blocked"
    record["last_run_id"] = run.get("id")
    record["last_run_at"] = finished_at
    record["last_status"] = status
    record["last_error"] = "; ".join(errors or [str(item) for item in run.get("errors", [])]) if is_error or is_blocked else None
    record["last_trigger"] = trigger
    record["last_duration_ms"] = duration_ms
    record["last_mode"] = mode
    record["run_count"] = int(record.get("run_count") or 0) + 1
    if trigger == "scheduled":
        record["scheduled_run_count"] = int(record.get("scheduled_run_count") or 0) + 1
    else:
        record["manual_run_count"] = int(record.get("manual_run_count") or 0) + 1
    if is_error or is_blocked:
        record["failure_count"] = int(record.get("failure_count") or 0) + 1
        record["consecutive_failures"] = int(record.get("consecutive_failures") or 0) + 1
        record["last_failed_run_at"] = finished_at
        if is_blocked:
            _apply_policy_pause(record, run, finished_at)
    else:
        record["consecutive_failures"] = 0
        record["last_successful_run_at"] = finished_at
        _clear_policy_pause(record)
    if record.get("enabled"):
        record["next_run_at"] = _next_time(int(record.get("interval_seconds") or DEFAULT_INTERVAL_SECONDS), base=finished_at)
    if mode == "full" and record.get("full_interval_seconds"):
        record["next_full_run_at"] = _next_time(int(record["full_interval_seconds"]), base=finished_at)
    record["updated_at"] = finished_at


def _apply_policy_pause(record: dict[str, Any], run: dict[str, Any], finished_at: str) -> None:
    run_policy = run.get("run_policy") if isinstance(run.get("run_policy"), dict) else {}
    record["enabled"] = False
    record["next_run_at"] = None
    record["policy_state"] = "paused"
    record["policy_reason"] = run_policy.get("reason") or "connector_run_policy_blocked"
    credential_health = run_policy.get("credential_health") if isinstance(run_policy.get("credential_health"), dict) else {}
    record["policy_reason_code"] = credential_health.get("reason_code") or run_policy.get("reason_code")
    record["policy_message"] = run_policy.get("message") or "; ".join(str(item) for item in run.get("errors", []))
    record["policy_actions"] = list(run_policy.get("actions") or [])
    record["policy_paused_at"] = finished_at
    record["run_policy"] = run_policy


def _clear_policy_pause(record: dict[str, Any]) -> None:
    record["policy_state"] = None
    record["policy_reason"] = None
    record["policy_reason_code"] = None
    record["policy_message"] = None
    record["policy_actions"] = []
    record["policy_paused_at"] = None
    record.pop("run_policy", None)


def _policy_snapshot(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_state": record.get("policy_state"),
        "policy_reason": record.get("policy_reason"),
        "policy_reason_code": record.get("policy_reason_code"),
        "policy_message": record.get("policy_message"),
        "policy_paused_at": record.get("policy_paused_at"),
        "run_policy": record.get("run_policy"),
    }


def _reason_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        reason = str(record.get("policy_reason_code") or record.get("policy_reason") or "unknown")
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def _coerce_next_run(current: Any, now: str, interval_seconds: int, enabled: bool) -> str | None:
    if not enabled:
        return current if isinstance(current, str) else None
    if isinstance(current, str) and current:
        return current
    return _next_time(interval_seconds, base=now)


def _coerce_next_full_run(record: dict[str, Any], now: str) -> str | None:
    full_interval = record.get("full_interval_seconds")
    if not full_interval:
        return None
    current = record.get("next_full_run_at")
    if isinstance(current, str) and current:
        return current
    return _next_time(int(full_interval), base=now)


def _next_time(seconds: int, *, base: str | None = None) -> str:
    base_dt = _parse_datetime(base) if base else None
    base_dt = base_dt or datetime.now(UTC)
    return (base_dt + timedelta(seconds=max(1, int(seconds)))).isoformat()


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _append_audit(
    registry: dict[str, Any],
    action: str,
    schedule_id: str,
    details: dict[str, Any] | None = None,
    *,
    actor: dict[str, Any] | None = None,
) -> None:
    registry.setdefault("audit", []).append(
        {
            "id": f"connector-sync-schedule-audit-{uuid4().hex}",
            "action": action,
            "schedule_id": schedule_id,
            "created_at": utc_now(),
            "actor": _actor(actor),
            "details": details or {},
        }
    )


def _apply_audit_retention(records: list[Any]) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC).timestamp() - (int(SCHEDULE_AUDIT_RETENTION_POLICY["max_days"]) * 86400)
    kept: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        timestamp = _audit_timestamp(record)
        if timestamp is not None and timestamp < cutoff:
            continue
        kept.append(record)
    kept.sort(key=lambda item: _audit_timestamp(item) or 0)
    return kept[-int(SCHEDULE_AUDIT_RETENTION_POLICY["max_items"]):]


def _audit_timestamp(record: dict[str, Any]) -> float | None:
    parsed = _parse_datetime(record.get("created_at"))
    return parsed.timestamp() if parsed else None


def _actor(actor: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(actor, dict):
        return {"type": "system", "id": "system", "username": "system", "role": "system"}
    return {
        "type": str(actor.get("type") or "user"),
        "id": str(actor.get("id") or actor.get("username") or "unknown"),
        "username": str(actor.get("username") or actor.get("id") or "unknown"),
        "role": str(actor.get("role") or ""),
    }
