"""Connector sync runtime: mapped connector payloads into Security Store."""

from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
from time import perf_counter
import tempfile
from typing import Any, Callable
from uuid import uuid4

from flocks.config.config import Config
from flocks.security.asset_identity import build_asset_identity, source_device_id, source_instance_id
from flocks.security.connectors.models import ConnectorPreviewResult
from flocks.security.evidence_graph import evidence_graph_summary, rebuild_evidence_graph
from flocks.security.models import Alert, Asset, HoneypotEvent, Vulnerability
from flocks.security.schemas import SecurityListFilters
from flocks.security.store import SecurityStore, default_store


SYNC_RUN_REGISTRY_VERSION = "connector.sync.runs.v1"
SYNC_RUN_REGISTRY_RELATIVE_PATH = Path("security") / "connector-sync-runs.json"
SUPPORTED_SYNC_MODES = {"full", "incremental"}
QUALITY_VERSION = "connector.evidence.v1"
EVIDENCE_IMPACT_VERSION = "connector.evidence.impact.v1"
RUN_POLICY_VERSION = "connector.run.policy.v1"
BLOCKED_RUN_RETENTION_POLICY = {
    "retained": True,
    "reason": "audit_history",
    "max_items": 500,
    "max_days": 730,
    "message": "Blocked connector sync runs are retained as audit history. A recovered credential profile creates a later non-blocked run; it does not erase prior blocked evidence.",
}
SYNC_RUN_RETENTION_POLICY = {
    "runs_max": 500,
    "runs_days": 365,
    "dead_letters_max": 1000,
    "dead_letters_days": 365,
    "controls_max": 500,
    "controls_days": 180,
    "audit_max": 1000,
    "audit_days": 730,
    "blocked_runs": BLOCKED_RUN_RETENTION_POLICY,
}
_sync_locks: dict[str, asyncio.Lock] = {}
_active_runs: dict[str, dict[str, Any]] = {}
_cancel_events: dict[str, asyncio.Event] = {}


class ConnectorSyncCancelled(Exception):
    """Raised when a connector sync run receives a runtime cancellation request."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_connector_sync_run_registry_path() -> Path:
    return Config.get_data_path() / SYNC_RUN_REGISTRY_RELATIVE_PATH


def sync_run_registry_path_or_default(path: Path | None = None) -> Path:
    return (path or default_connector_sync_run_registry_path()).expanduser()


def empty_connector_sync_run_registry() -> dict[str, Any]:
    return {
        "version": SYNC_RUN_REGISTRY_VERSION,
        "updated_at": None,
        "runs": [],
        "cursors": {},
        "dead_letters": [],
        "controls": [],
        "audit": [],
    }


def load_connector_sync_run_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = sync_run_registry_path_or_default(path)
    if not registry_path.is_file():
        return empty_connector_sync_run_registry()
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Connector sync run registry must be an object: {registry_path}")
    registry = empty_connector_sync_run_registry()
    registry.update(data)
    registry["version"] = str(registry.get("version") or SYNC_RUN_REGISTRY_VERSION)
    registry["runs"] = registry.get("runs") if isinstance(registry.get("runs"), list) else []
    registry["cursors"] = registry.get("cursors") if isinstance(registry.get("cursors"), dict) else {}
    registry["dead_letters"] = registry.get("dead_letters") if isinstance(registry.get("dead_letters"), list) else []
    registry["controls"] = registry.get("controls") if isinstance(registry.get("controls"), list) else []
    registry["audit"] = registry.get("audit") if isinstance(registry.get("audit"), list) else []
    return registry


def save_connector_sync_run_registry(registry: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    registry_path = sync_run_registry_path_or_default(path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry["version"] = SYNC_RUN_REGISTRY_VERSION
    registry["updated_at"] = utc_now()
    registry["runs"] = _retain_sync_runs(list(registry.get("runs") or []))
    registry["dead_letters"] = _apply_retention(
        list(registry.get("dead_letters") or []),
        max_items=SYNC_RUN_RETENTION_POLICY["dead_letters_max"],
        max_days=SYNC_RUN_RETENTION_POLICY["dead_letters_days"],
        timestamp_keys=("created_at", "last_replay_at"),
    )
    registry["controls"] = _apply_retention(
        list(registry.get("controls") or []),
        max_items=SYNC_RUN_RETENTION_POLICY["controls_max"],
        max_days=SYNC_RUN_RETENTION_POLICY["controls_days"],
        timestamp_keys=("created_at",),
    )
    registry["audit"] = _apply_retention(
        list(registry.get("audit") or []),
        max_items=SYNC_RUN_RETENTION_POLICY["audit_max"],
        max_days=SYNC_RUN_RETENTION_POLICY["audit_days"],
        timestamp_keys=("created_at",),
    )
    registry["cursors"] = registry.get("cursors") if isinstance(registry.get("cursors"), dict) else {}
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


def list_connector_sync_runs(
    *,
    connector_id: str | None = None,
    limit: int = 50,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    registry = load_connector_sync_run_registry(path)
    runs = [dict(run) for run in registry["runs"] if isinstance(run, dict)]
    if connector_id:
        runs = [run for run in runs if run.get("connector_id") == connector_id]
    runs.sort(key=lambda item: str(item.get("started_at") or ""), reverse=True)
    return runs[:limit]


def list_connector_sync_cursors(
    *,
    connector_id: str | None = None,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    registry = load_connector_sync_run_registry(path)
    cursors = [dict(value) for value in registry["cursors"].values() if isinstance(value, dict)]
    if connector_id:
        cursors = [cursor for cursor in cursors if cursor.get("connector_id") == connector_id]
    cursors.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
    return cursors


def list_connector_sync_dead_letters(
    *,
    connector_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    registry = load_connector_sync_run_registry(path)
    letters = [dict(item) for item in registry["dead_letters"] if isinstance(item, dict)]
    if connector_id:
        letters = [item for item in letters if item.get("connector_id") == connector_id]
    if status:
        letters = [item for item in letters if item.get("status") == status]
    letters.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return letters[:limit]


def list_active_connector_sync_runs(
    *,
    connector_id: str | None = None,
    capability: str | None = None,
) -> list[dict[str, Any]]:
    runs = [dict(item) for item in _active_runs.values()]
    if connector_id:
        runs = [item for item in runs if item.get("connector_id") == connector_id]
    if capability:
        runs = [item for item in runs if item.get("capability") == capability]
    runs.sort(key=lambda item: str(item.get("started_at") or ""), reverse=True)
    return runs


def request_connector_sync_cancel(
    *,
    run_id: str | None = None,
    connector_id: str | None = None,
    capability: str | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    matched: list[dict[str, Any]] = []
    for active_run_id, run in list(_active_runs.items()):
        if run_id and active_run_id != run_id:
            continue
        if connector_id and run.get("connector_id") != connector_id:
            continue
        if capability and run.get("capability") != capability:
            continue
        event = _cancel_events.get(active_run_id)
        if event is not None:
            event.set()
        matched.append(dict(run))

    registry = load_connector_sync_run_registry(path)
    control = {
        "id": f"connector-sync-control-{uuid4().hex}",
        "action": "cancel",
        "run_id": run_id,
        "connector_id": connector_id,
        "capability": capability,
        "matched": len(matched),
        "matched_run_ids": [item.get("id") for item in matched],
        "created_at": utc_now(),
    }
    registry.setdefault("controls", []).append(control)
    save_connector_sync_run_registry(registry, path)
    return {
        "cancel_requested": bool(matched),
        "matched": len(matched),
        "runs": matched,
        "control": control,
    }


def reset_connector_sync_cursor(
    connector_id: str,
    *,
    capability: str | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_sync_run_registry(path)
    removed: list[dict[str, Any]] = []
    for key, value in list(registry["cursors"].items()):
        if not isinstance(value, dict):
            continue
        if value.get("connector_id") != connector_id:
            continue
        if capability and value.get("capability") != capability:
            continue
        removed.append(dict(value))
        registry["cursors"].pop(key, None)
    save_connector_sync_run_registry(registry, path)
    return {
        "connector_id": connector_id,
        "capability": capability,
        "reset": len(removed),
        "removed": removed,
        "reset_at": utc_now(),
    }


def record_blocked_connector_sync_run(
    connector_id: str,
    capability: str,
    *,
    mode: str = "full",
    trigger: str = "manual",
    schedule_id: str | None = None,
    credential_profile_id: str | None = None,
    package_metadata: dict[str, Any] | None = None,
    credential_health: dict[str, Any],
    path: Path | None = None,
) -> dict[str, Any]:
    if mode not in SUPPORTED_SYNC_MODES:
        raise ValueError(f"Unsupported connector sync mode: {mode}")
    now = utc_now()
    message = str(credential_health.get("message") or "Connector sync blocked by credential health gate")
    run_policy = {
        "version": RUN_POLICY_VERSION,
        "decision": "block",
        "state": "blocked",
        "reason": credential_health.get("reason") or "credential_health_blocked",
        "message": message,
        "checked_at": now,
        "actions": list(credential_health.get("actions") or []),
        "credential_health": credential_health,
    }
    run = {
        "id": f"connector-sync-blocked-{uuid4().hex}",
        "connector_id": connector_id,
        "capability": capability,
        "operation": "sync",
        "trigger": trigger,
        "schedule_id": schedule_id,
        "credential_profile_id": credential_profile_id,
        "package": package_metadata or {},
        "sync_mode": mode,
        "cursor_before": _get_cursor(
            connector_id,
            capability,
            credential_profile_id=credential_profile_id,
            path=path,
        ),
        "cursor_after": None,
        "cursor_updated": False,
        "reset_cursor": False,
        "status": "blocked",
        "started_at": now,
        "finished_at": now,
        "duration_ms": 0,
        "source": "credential_health_gate",
        "input_counts": {},
        "counts": {},
        "object_ids": {},
        "skipped_counts": {},
        "quality": _empty_quality_summary(),
        "evidence_impact": _empty_evidence_impact(),
        "dead_letter_count": 0,
        "warnings": [],
        "errors": [message],
        "run_policy": run_policy,
        "credential_health": credential_health,
    }
    _append_run(
        run,
        path,
        cursor_after=None,
        dead_letters=[],
        audit_event=_run_audit_event(
            "blocked",
            run,
            {
                "reason": run_policy["reason"],
                "reason_code": credential_health.get("reason_code"),
                "severity": credential_health.get("severity"),
                "message": message,
            },
        ),
    )
    return run


async def replay_connector_sync_dead_letters(
    *,
    ids: list[str] | None = None,
    connector_id: str | None = None,
    limit: int = 50,
    payload_updates: dict[str, dict[str, Any]] | None = None,
    store: SecurityStore | None = None,
    path: Path | None = None,
    evidence_graph_path: Path | None = None,
) -> dict[str, Any]:
    store = store or default_store
    registry = load_connector_sync_run_registry(path)
    selected = _select_replay_dead_letters(registry, ids=ids, connector_id=connector_id, limit=limit)
    run = _start_replay_run(selected, connector_id=connector_id)
    started = perf_counter()
    updates = payload_updates or {}
    graph_before = evidence_graph_summary(evidence_graph_path)
    quality = _empty_quality_summary()
    if not selected:
        run["errors"].append("No connector sync dead letters selected for replay")

    for letter in selected:
        target = str(letter.get("target") or "")
        quality["by_target"].setdefault(target, {"complete": 0, "partial": 0, "invalid": 0, "skipped": 0})
        payload = copy.deepcopy(letter.get("payload") if isinstance(letter.get("payload"), dict) else {})
        payload = _deep_merge(payload, updates.get(str(letter.get("id"))) or {})
        evidence = copy.deepcopy(letter.get("evidence") if isinstance(letter.get("evidence"), dict) else {})
        original_run_id = evidence.get("sync_run_id") or letter.get("run_id")
        evidence["original_sync_run_id"] = original_run_id
        evidence["sync_run_id"] = run["id"]
        evidence["sync_mode"] = "replay"
        evidence["replayed_from_dead_letter_id"] = letter.get("id")
        evidence["replayed_at"] = utc_now()
        assessment = _assess_quality(target, payload, evidence, {"warnings": []})
        evidence["quality_status"] = assessment["status"]
        evidence["confidence"] = assessment["confidence"]
        if assessment["status"] == "invalid":
            _mark_dead_letter_replay_failed(letter, run, assessment.get("errors") or [])
            quality["invalid"] += 1
            quality["by_target"][target]["invalid"] += 1
            run["errors"].extend(str(item) for item in assessment.get("errors") or [])
            continue

        try:
            obj = await _upsert_target(store, target, _with_replay_metadata(payload, letter, evidence))
        except Exception as exc:
            _mark_dead_letter_replay_failed(letter, run, [str(exc)])
            quality["invalid"] += 1
            quality["by_target"][target]["invalid"] += 1
            run["errors"].append(str(exc))
            continue

        object_id = getattr(obj, "id", "")
        run["counts"][target] = int(run["counts"].get(target) or 0) + 1
        run["object_ids"].setdefault(target, []).append(object_id)
        quality[assessment["status"]] += 1
        quality["by_target"][target][assessment["status"]] += 1
        _mark_dead_letter_replayed(letter, run, object_id)

    quality["score"] = _quality_score(quality)
    run["quality"] = quality
    replayed = sum(1 for item in selected if item.get("last_replay_run_id") == run["id"] and item.get("last_replay_status") == "success")
    failed = len(selected) - replayed
    run["dead_letter_count"] = failed
    run["replay"] = {
        "requested": len(selected),
        "replayed": replayed,
        "failed": failed,
        "dead_letter_ids": [item.get("id") for item in selected],
        "replayed_dead_letter_ids": [
            item.get("id") for item in selected if item.get("last_replay_run_id") == run["id"] and item.get("last_replay_status") == "success"
        ],
        "failed_dead_letter_ids": [
            item.get("id") for item in selected if item.get("last_replay_run_id") == run["id"] and item.get("last_replay_status") != "success"
        ],
    }
    run["status"] = "success" if selected and failed == 0 else "partial" if replayed > 0 else "error"
    run["finished_at"] = utc_now()
    run["duration_ms"] = max(0, round((perf_counter() - started) * 1000))
    if replayed > 0:
        try:
            graph = await rebuild_evidence_graph(store=store, path=evidence_graph_path)
            run["evidence_graph"] = graph.get("summary", {})
            run["evidence_impact"] = _build_evidence_impact(run, graph_before, graph.get("summary", {}))
        except Exception as exc:
            run.setdefault("warnings", []).append(f"Evidence graph rebuild failed: {exc}")
            run["evidence_graph"] = {"status": "error", "error": str(exc)}
            run["evidence_impact"] = _build_evidence_impact(run, graph_before, {})
    registry.setdefault("runs", []).append(dict(run))
    save_connector_sync_run_registry(registry, path)
    return run


async def sync_connector_preview_result(
    preview: ConnectorPreviewResult,
    *,
    mode: str = "full",
    reset_cursor: bool = False,
    trigger: str = "manual",
    schedule_id: str | None = None,
    credential_profile_id: str | None = None,
    package_metadata: dict[str, Any] | None = None,
    store: SecurityStore | None = None,
    path: Path | None = None,
    evidence_graph_path: Path | None = None,
) -> dict[str, Any]:
    if mode not in SUPPORTED_SYNC_MODES:
        raise ValueError(f"Unsupported connector sync mode: {mode}")
    capability = _capability_value(preview)
    lock_key = _cursor_key(preview.connector_id, capability, credential_profile_id=credential_profile_id)
    lock = _sync_locks.setdefault(lock_key, asyncio.Lock())
    if lock.locked():
        cursor_before = _get_cursor(
            preview.connector_id,
            capability,
            credential_profile_id=credential_profile_id,
            path=path,
        )
        run = _start_run(
            preview,
            mode=mode,
            cursor_before=cursor_before,
            reset_cursor=reset_cursor,
            trigger=trigger,
            schedule_id=schedule_id,
            credential_profile_id=credential_profile_id,
            package_metadata=package_metadata,
        )
        run["status"] = "busy"
        run["finished_at"] = utc_now()
        run["duration_ms"] = 0
        run["errors"] = [f"Connector sync already running: {lock_key}"]
        run["run_control"] = {"lock_key": lock_key, "busy": True, "cancellable": False}
        _append_run(run, path, cursor_after=None, dead_letters=[])
        return run

    async with lock:
        return await _sync_connector_preview_result_locked(
            preview,
            mode=mode,
            reset_cursor=reset_cursor,
            trigger=trigger,
            schedule_id=schedule_id,
            credential_profile_id=credential_profile_id,
            package_metadata=package_metadata,
            store=store,
            path=path,
            evidence_graph_path=evidence_graph_path,
            lock_key=lock_key,
        )


async def _sync_connector_preview_result_locked(
    preview: ConnectorPreviewResult,
    *,
    mode: str,
    reset_cursor: bool,
    trigger: str,
    schedule_id: str | None,
    credential_profile_id: str | None,
    package_metadata: dict[str, Any] | None,
    store: SecurityStore | None,
    path: Path | None,
    evidence_graph_path: Path | None,
    lock_key: str,
) -> dict[str, Any]:
    store = store or default_store
    capability = _capability_value(preview)
    if reset_cursor:
        reset_connector_sync_cursor(preview.connector_id, capability=capability, path=path)
    cursor_before = _get_cursor(
        preview.connector_id,
        capability,
        credential_profile_id=credential_profile_id,
        path=path,
    )
    run = _start_run(
        preview,
        mode=mode,
        cursor_before=cursor_before,
        reset_cursor=reset_cursor,
        trigger=trigger,
        schedule_id=schedule_id,
        credential_profile_id=credential_profile_id,
        package_metadata=package_metadata,
    )
    cancel_event = asyncio.Event()
    _active_runs[str(run["id"])] = {
        "id": run["id"],
        "connector_id": preview.connector_id,
        "capability": capability,
        "sync_mode": mode,
        "trigger": trigger,
        "schedule_id": schedule_id,
        "credential_profile_id": credential_profile_id,
        "started_at": run["started_at"],
        "status": "running",
        "lock_key": lock_key,
    }
    _cancel_events[str(run["id"])] = cancel_event
    run["run_control"] = {"lock_key": lock_key, "busy": False, "cancellable": True}
    started = perf_counter()
    dead_letters: list[dict[str, Any]] = []
    cursor_candidate: str | None = None
    try:
        if cancel_event.is_set():
            raise ConnectorSyncCancelled("Connector sync cancelled before write started")
        if not preview.success:
            raise ValueError("Connector preview failed")
        write_result = await _write_mapping_result(
            preview,
            store,
            run_id=str(run["id"]),
            mode=mode,
            cursor_before=cursor_before,
            credential_profile_id=credential_profile_id,
            is_cancelled=cancel_event.is_set,
        )
        counts, object_ids, errors, quality, skipped_counts, dead_letters, cursor_candidate = write_result
        run["counts"] = counts
        run["object_ids"] = object_ids
        run["errors"] = errors
        run["quality"] = quality
        run["skipped_counts"] = skipped_counts
        run["dead_letter_count"] = len(dead_letters)
        run["warnings"] = list(preview.warnings or [])
        run["status"] = "success" if not errors and not dead_letters else "partial"
    except ConnectorSyncCancelled as exc:
        run["status"] = "canceled"
        run["errors"] = [str(exc)]
    except Exception as exc:
        run["status"] = "error"
        run["errors"] = [str(exc)]
    run["finished_at"] = utc_now()
    run["duration_ms"] = max(0, round((perf_counter() - started) * 1000))
    cursor_after = _next_cursor(cursor_before, cursor_candidate)
    run["cursor_after"] = cursor_after
    run["cursor_updated"] = cursor_after != cursor_before and run["status"] not in {"error", "canceled", "busy"}
    if run["status"] not in {"error", "canceled", "busy"}:
        graph_before = evidence_graph_summary(evidence_graph_path)
        try:
            graph = await rebuild_evidence_graph(store=store, path=evidence_graph_path)
            run["evidence_graph"] = graph.get("summary", {})
            run["evidence_impact"] = _build_evidence_impact(run, graph_before, graph.get("summary", {}))
        except Exception as exc:
            run.setdefault("warnings", []).append(f"Evidence graph rebuild failed: {exc}")
            run["evidence_graph"] = {"status": "error", "error": str(exc)}
            run["evidence_impact"] = _build_evidence_impact(run, graph_before, {})
    _append_run(
        run,
        path,
        cursor_after=cursor_after if run["status"] not in {"error", "canceled", "busy"} else None,
        dead_letters=dead_letters,
    )
    _active_runs.pop(str(run["id"]), None)
    _cancel_events.pop(str(run["id"]), None)
    return run


def sync_run_summary(path: Path | None = None) -> dict[str, Any]:
    registry = load_connector_sync_run_registry(path)
    runs = [run for run in registry["runs"] if isinstance(run, dict)]
    dead_letters = [item for item in registry["dead_letters"] if isinstance(item, dict)]
    last_run = max(runs, key=lambda item: str(item.get("started_at") or ""), default=None)
    blocked_runs = [run for run in runs if run.get("status") == "blocked"]
    return {
        "path": str(sync_run_registry_path_or_default(path)),
        "version": registry.get("version"),
        "runs": len(runs),
        "cursors": len(registry["cursors"]),
        "dead_letters": len(dead_letters),
        "pending_dead_letters": sum(1 for item in dead_letters if item.get("status") in {"invalid", "replay_failed"}),
        "replayed_dead_letters": sum(1 for item in dead_letters if item.get("status") == "replayed"),
        "blocked_runs": len(blocked_runs),
        "blocked_run_retention": dict(BLOCKED_RUN_RETENTION_POLICY),
        "retention": dict(SYNC_RUN_RETENTION_POLICY),
        "last_blocked_run": dict(max(blocked_runs, key=lambda item: str(item.get("started_at") or ""), default={})) or None,
        "active_runs": len(_active_runs),
        "controls": len(registry["controls"]),
        "audit_events": len(registry.get("audit") or []),
        "last_run": dict(last_run) if isinstance(last_run, dict) else None,
    }


def _start_run(
    preview: ConnectorPreviewResult,
    *,
    mode: str,
    cursor_before: str | None,
    reset_cursor: bool,
    trigger: str,
    schedule_id: str | None,
    credential_profile_id: str | None,
    package_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "id": f"connector-sync-{uuid4().hex}",
        "connector_id": preview.connector_id,
        "capability": _capability_value(preview),
        "operation": "sync",
        "trigger": trigger,
        "schedule_id": schedule_id,
        "credential_profile_id": credential_profile_id,
        "package": package_metadata or {},
        "sync_mode": mode,
        "cursor_before": cursor_before,
        "cursor_after": None,
        "cursor_updated": False,
        "reset_cursor": reset_cursor,
        "status": "running",
        "started_at": utc_now(),
        "finished_at": None,
        "duration_ms": None,
        "source": preview.source,
        "input_counts": _input_counts(preview),
        "counts": {},
        "object_ids": {},
        "skipped_counts": {},
        "quality": _empty_quality_summary(),
        "evidence_impact": _empty_evidence_impact(),
        "dead_letter_count": 0,
        "warnings": list(preview.warnings or []),
        "errors": [],
    }


def _start_replay_run(selected: list[dict[str, Any]], *, connector_id: str | None) -> dict[str, Any]:
    connector_ids = sorted({str(item.get("connector_id") or "") for item in selected if item.get("connector_id")})
    capabilities = sorted({str(item.get("capability") or "") for item in selected if item.get("capability")})
    now = utc_now()
    return {
        "id": f"connector-replay-{uuid4().hex}",
        "connector_id": connector_id or (connector_ids[0] if len(connector_ids) == 1 else "multiple"),
        "capability": capabilities[0] if len(capabilities) == 1 else "multiple",
        "operation": "dead_letter_replay",
        "trigger": "manual",
        "schedule_id": None,
        "package": {},
        "sync_mode": "replay",
        "cursor_before": None,
        "cursor_after": None,
        "cursor_updated": False,
        "reset_cursor": False,
        "status": "running",
        "started_at": now,
        "finished_at": None,
        "duration_ms": None,
        "source": "dead_letter",
        "input_counts": {"dead_letters": len(selected)},
        "counts": {},
        "object_ids": {},
        "skipped_counts": {},
        "quality": _empty_quality_summary(),
        "evidence_impact": _empty_evidence_impact(),
        "dead_letter_count": 0,
        "warnings": [],
        "errors": [],
        "replay": {"requested": len(selected), "replayed": 0, "failed": 0},
    }


def _select_replay_dead_letters(
    registry: dict[str, Any],
    *,
    ids: list[str] | None,
    connector_id: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    id_set = {str(item) for item in ids or [] if item}
    selected: list[dict[str, Any]] = []
    for item in registry.get("dead_letters") or []:
        if not isinstance(item, dict):
            continue
        if id_set and str(item.get("id")) not in id_set:
            continue
        if connector_id and item.get("connector_id") != connector_id:
            continue
        if item.get("status") == "replayed" and not id_set:
            continue
        selected.append(item)
    selected.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return selected[: max(1, int(limit))]


def _mark_dead_letter_replayed(letter: dict[str, Any], run: dict[str, Any], object_id: str) -> None:
    now = utc_now()
    letter["status"] = "replayed"
    letter["replayed_at"] = now
    letter["replayed_object_id"] = object_id
    letter["last_replay_at"] = now
    letter["last_replay_run_id"] = run["id"]
    letter["last_replay_status"] = "success"
    letter["last_replay_errors"] = []
    letter["replay_count"] = int(letter.get("replay_count") or 0) + 1


def _mark_dead_letter_replay_failed(letter: dict[str, Any], run: dict[str, Any], errors: list[str]) -> None:
    now = utc_now()
    letter["status"] = "replay_failed"
    letter["last_replay_at"] = now
    letter["last_replay_run_id"] = run["id"]
    letter["last_replay_status"] = "error"
    letter["last_replay_errors"] = list(errors)
    letter["replay_count"] = int(letter.get("replay_count") or 0) + 1


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _input_counts(preview: ConnectorPreviewResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for target, items in (preview.mapping_result or {}).items():
        counts[str(target)] = len(items) if isinstance(items, list) else 0
    return counts


async def _write_mapping_result(
    preview: ConnectorPreviewResult,
    store: SecurityStore,
    *,
    run_id: str,
    mode: str,
    cursor_before: str | None,
    credential_profile_id: str | None,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[dict[str, int], dict[str, list[str]], list[str], dict[str, Any], dict[str, int], list[dict[str, Any]], str | None]:
    counts: dict[str, int] = {}
    object_ids: dict[str, list[str]] = {}
    errors: list[str] = []
    skipped_counts: dict[str, int] = {}
    dead_letters: list[dict[str, Any]] = []
    quality = _empty_quality_summary()
    cursor_candidate: str | None = None
    for target, items in (preview.mapping_result or {}).items():
        if is_cancelled and is_cancelled():
            raise ConnectorSyncCancelled("Connector sync cancelled")
        if not isinstance(items, list):
            continue
        counts[target] = 0
        object_ids[target] = []
        skipped_counts[target] = 0
        quality["by_target"][target] = {"complete": 0, "partial": 0, "invalid": 0, "skipped": 0}
        for index, item in enumerate(items):
            if is_cancelled and is_cancelled():
                raise ConnectorSyncCancelled("Connector sync cancelled")
            if not isinstance(item, dict):
                errors.append(f"{target}[{index}] is not an object")
                quality["invalid"] += 1
                quality["by_target"][target]["invalid"] += 1
                continue
            payload = dict(item)
            diagnostics = _item_mapping_diagnostics(preview, index)
            evidence = _build_evidence(
                payload,
                preview,
                target=target,
                run_id=run_id,
                sync_mode=mode,
                index=index,
                credential_profile_id=credential_profile_id,
            )
            if mode == "incremental" and _should_skip_for_cursor(evidence.get("source_timestamp"), cursor_before):
                skipped_counts[target] += 1
                quality["skipped"] += 1
                quality["by_target"][target]["skipped"] += 1
                continue
            payload = await _apply_source_identity(store, target, payload, evidence)
            assessment = _assess_quality(target, payload, evidence, diagnostics)
            evidence["quality_status"] = assessment["status"]
            evidence["confidence"] = assessment["confidence"]
            payload = _with_sync_metadata(payload, preview, target=target, evidence=evidence)
            if assessment["status"] == "invalid":
                dead_letters.append(_dead_letter(preview, run_id, target, index, payload, evidence, assessment))
                quality["invalid"] += 1
                quality["by_target"][target]["invalid"] += 1
                continue
            try:
                obj = await _upsert_target(store, target, payload)
            except Exception as exc:
                errors.append(f"{target}[{index}] {payload.get('id') or ''}: {exc}")
                dead_letters.append(
                    _dead_letter(
                        preview,
                        run_id,
                        target,
                        index,
                        payload,
                        evidence,
                        {"status": "invalid", "errors": [str(exc)], "warnings": [], "confidence": "low"},
                    )
                )
                quality["invalid"] += 1
                quality["by_target"][target]["invalid"] += 1
                continue
            counts[target] += 1
            object_ids[target].append(getattr(obj, "id", ""))
            quality[assessment["status"]] += 1
            quality["by_target"][target][assessment["status"]] += 1
            cursor_candidate = _max_timestamp(cursor_candidate, evidence.get("source_timestamp"))
    quality["score"] = _quality_score(quality)
    return counts, object_ids, errors, quality, skipped_counts, dead_letters, cursor_candidate


async def _upsert_target(store: SecurityStore, target: str, payload: dict[str, Any]) -> Any:
    if target == "assets":
        return await store.upsert_asset(payload)
    if target == "vulnerabilities":
        return await store.upsert_vulnerability(payload)
    if target == "alerts":
        if not payload.get("raw_event") and isinstance(payload.get("raw_data"), dict):
            payload["raw_event"] = payload["raw_data"].get("response") or payload["raw_data"]
        return await store.upsert_alert(payload)
    if target == "honeypot_events":
        return await store.upsert_honeypot_event(payload)
    raise ValueError(f"Unsupported connector sync target: {target}")


def _with_sync_metadata(
    payload: dict[str, Any],
    preview: ConnectorPreviewResult,
    *,
    target: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    metadata = {
        "connector_id": preview.connector_id,
        "capability": _capability_value(preview),
        "target": target,
        "sync_run_id": evidence.get("sync_run_id"),
        "sync_mode": evidence.get("sync_mode"),
        "synced_at": utc_now(),
        "source": preview.source,
        "source_instance_id": evidence.get("source_instance_id"),
        "credential_profile_id": evidence.get("credential_profile_id"),
        "device_id": evidence.get("device_id"),
        "source_object_id": evidence.get("source_object_id"),
        "source_fingerprint": evidence.get("source_fingerprint"),
        "source_timestamp": evidence.get("source_timestamp"),
        "quality_status": evidence.get("quality_status"),
    }
    raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
    payload["raw_data"] = {**raw_data, "connector_sync": metadata, "connector_evidence": evidence}
    normalized_data = payload.get("normalized_data") if isinstance(payload.get("normalized_data"), dict) else {}
    payload["normalized_data"] = {**normalized_data, "connector_sync": metadata, "connector_evidence": evidence}
    if target == "assets":
        identity = build_asset_identity(payload, evidence=evidence)
        raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
        normalized_data = payload.get("normalized_data") if isinstance(payload.get("normalized_data"), dict) else {}
        payload["raw_data"] = {
            **raw_data,
            "asset_identity": identity,
            "source_observation": identity.get("source_observation", {}),
        }
        payload["normalized_data"] = {
            **normalized_data,
            "asset_identity": identity,
            "source_observation": identity.get("source_observation", {}),
            "ip_observations": identity.get("ip_observations", []),
        }
    return payload


def _with_replay_metadata(
    payload: dict[str, Any],
    letter: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    target = str(letter.get("target") or evidence.get("target") or "")
    metadata = {
        "connector_id": letter.get("connector_id"),
        "capability": letter.get("capability"),
        "target": target,
        "sync_run_id": evidence.get("sync_run_id"),
        "sync_mode": "replay",
        "synced_at": utc_now(),
        "source": evidence.get("source_system"),
        "source_instance_id": evidence.get("source_instance_id"),
        "credential_profile_id": evidence.get("credential_profile_id"),
        "device_id": evidence.get("device_id"),
        "source_object_id": evidence.get("source_object_id"),
        "source_fingerprint": evidence.get("source_fingerprint"),
        "source_timestamp": evidence.get("source_timestamp"),
        "quality_status": evidence.get("quality_status"),
        "replayed_from_dead_letter_id": letter.get("id"),
        "original_sync_run_id": evidence.get("original_sync_run_id"),
    }
    raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
    payload["raw_data"] = {**raw_data, "connector_sync": metadata, "connector_evidence": evidence}
    normalized_data = payload.get("normalized_data") if isinstance(payload.get("normalized_data"), dict) else {}
    payload["normalized_data"] = {**normalized_data, "connector_sync": metadata, "connector_evidence": evidence}
    if target == "assets":
        identity = build_asset_identity(payload, evidence=evidence)
        raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
        normalized_data = payload.get("normalized_data") if isinstance(payload.get("normalized_data"), dict) else {}
        payload["raw_data"] = {
            **raw_data,
            "asset_identity": identity,
            "source_observation": identity.get("source_observation", {}),
        }
        payload["normalized_data"] = {
            **normalized_data,
            "asset_identity": identity,
            "source_observation": identity.get("source_observation", {}),
            "ip_observations": identity.get("ip_observations", []),
        }
    return payload


def _append_run(
    run: dict[str, Any],
    path: Path | None,
    *,
    cursor_after: str | None,
    dead_letters: list[dict[str, Any]],
    audit_event: dict[str, Any] | None = None,
) -> None:
    registry = load_connector_sync_run_registry(path)
    registry.setdefault("runs", []).append(dict(run))
    if cursor_after:
        key = _cursor_key(
            str(run["connector_id"]),
            str(run["capability"]),
            credential_profile_id=run.get("credential_profile_id"),
        )
        registry.setdefault("cursors", {})[key] = {
            "key": key,
            "connector_id": run["connector_id"],
            "capability": run["capability"],
            "credential_profile_id": run.get("credential_profile_id"),
            "cursor": cursor_after,
            "updated_at": run["finished_at"],
            "last_run_id": run["id"],
            "source": run.get("source"),
        }
    registry.setdefault("dead_letters", []).extend(dead_letters)
    if audit_event:
        registry.setdefault("audit", []).append(audit_event)
    save_connector_sync_run_registry(registry, path)


def _retain_sync_runs(records: list[Any]) -> list[dict[str, Any]]:
    blocked = [
        record for record in records
        if isinstance(record, dict) and record.get("status") == "blocked"
    ]
    other = [
        record for record in records
        if isinstance(record, dict) and record.get("status") != "blocked"
    ]
    retained_blocked = _apply_retention(
        blocked,
        max_items=int(BLOCKED_RUN_RETENTION_POLICY["max_items"]),
        max_days=int(BLOCKED_RUN_RETENTION_POLICY["max_days"]),
        timestamp_keys=("started_at", "finished_at"),
    )
    retained_other = _apply_retention(
        other,
        max_items=SYNC_RUN_RETENTION_POLICY["runs_max"],
        max_days=SYNC_RUN_RETENTION_POLICY["runs_days"],
        timestamp_keys=("started_at", "finished_at"),
    )
    remaining = max(0, int(SYNC_RUN_RETENTION_POLICY["runs_max"]) - len(retained_blocked))
    merged = retained_other[-remaining:] + retained_blocked if remaining else retained_blocked
    merged.sort(key=lambda item: _record_timestamp(item, ("started_at", "finished_at")) or 0)
    return merged[-SYNC_RUN_RETENTION_POLICY["runs_max"]:]


def _apply_retention(
    records: list[Any],
    *,
    max_items: int,
    max_days: int,
    timestamp_keys: tuple[str, ...],
) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC).timestamp() - (max_days * 86400)
    kept: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        timestamp = _record_timestamp(record, timestamp_keys)
        if timestamp is not None and timestamp < cutoff:
            continue
        kept.append(record)
    kept.sort(key=lambda item: _record_timestamp(item, timestamp_keys) or 0)
    return kept[-max_items:]


def _record_timestamp(record: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for key in keys:
        parsed = _parse_datetime(record.get(key))
        if parsed is not None:
            return parsed.timestamp()
    return None


def _run_audit_event(action: str, run: dict[str, Any], details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": f"connector-sync-audit-{uuid4().hex}",
        "action": f"connector_sync.{action}",
        "run_id": run.get("id"),
        "connector_id": run.get("connector_id"),
        "capability": run.get("capability"),
        "schedule_id": run.get("schedule_id"),
        "credential_profile_id": run.get("credential_profile_id"),
        "status": run.get("status"),
        "created_at": utc_now(),
        "details": details or {},
    }


def _capability_value(preview: ConnectorPreviewResult) -> str:
    return str(preview.capability.value if hasattr(preview.capability, "value") else preview.capability)


def _cursor_key(connector_id: str, capability: str, *, credential_profile_id: Any = None) -> str:
    profile = str(credential_profile_id or "").strip()
    if profile:
        return f"{connector_id}:{profile}:{capability}"
    return f"{connector_id}:{capability}"


def _get_cursor(
    connector_id: str,
    capability: str,
    *,
    credential_profile_id: Any = None,
    path: Path | None,
) -> str | None:
    registry = load_connector_sync_run_registry(path)
    cursor = registry["cursors"].get(
        _cursor_key(connector_id, capability, credential_profile_id=credential_profile_id)
    )
    if isinstance(cursor, dict) and isinstance(cursor.get("cursor"), str):
        return cursor["cursor"]
    return None


def _next_cursor(cursor_before: str | None, cursor_candidate: str | None) -> str | None:
    if not cursor_candidate:
        return cursor_before
    return _max_timestamp(cursor_before, cursor_candidate)


def _empty_quality_summary() -> dict[str, Any]:
    return {
        "version": QUALITY_VERSION,
        "complete": 0,
        "partial": 0,
        "invalid": 0,
        "skipped": 0,
        "score": 100,
        "by_target": {},
    }


def _empty_evidence_impact() -> dict[str, Any]:
    return {
        "version": EVIDENCE_IMPACT_VERSION,
        "targets": {},
        "graph_before": {},
        "graph_after": {},
        "graph_delta": {},
        "quality_score": None,
        "dead_letter_count": 0,
    }


def _build_evidence_impact(
    run: dict[str, Any],
    graph_before: dict[str, Any] | None,
    graph_after: dict[str, Any] | None,
) -> dict[str, Any]:
    before = _graph_numbers(graph_before or {})
    after = _graph_numbers(graph_after or {})
    input_counts = run.get("input_counts") if isinstance(run.get("input_counts"), dict) else {}
    counts = run.get("counts") if isinstance(run.get("counts"), dict) else {}
    object_ids = run.get("object_ids") if isinstance(run.get("object_ids"), dict) else {}
    skipped_counts = run.get("skipped_counts") if isinstance(run.get("skipped_counts"), dict) else {}
    targets: dict[str, Any] = {}
    for target in sorted({*input_counts.keys(), *counts.keys(), *object_ids.keys(), *skipped_counts.keys()}):
        ids = list(object_ids.get(target) or [])
        targets[target] = {
            "input": int(input_counts.get(target) or 0),
            "written": int(counts.get(target) or 0),
            "skipped": int(skipped_counts.get(target) or 0),
            "object_ids": ids,
        }
    return {
        "version": EVIDENCE_IMPACT_VERSION,
        "targets": targets,
        "graph_before": before,
        "graph_after": after,
        "graph_delta": {key: int(after.get(key) or 0) - int(before.get(key) or 0) for key in sorted({*before.keys(), *after.keys()})},
        "quality_score": (run.get("quality") or {}).get("score") if isinstance(run.get("quality"), dict) else None,
        "dead_letter_count": int(run.get("dead_letter_count") or 0),
    }


def _graph_numbers(summary: dict[str, Any]) -> dict[str, int]:
    keys = ["nodes", "edges", "asset_entities", "merge_candidates", "conflicts"]
    return {key: int(summary.get(key) or 0) for key in keys}


def _build_evidence(
    payload: dict[str, Any],
    preview: ConnectorPreviewResult,
    *,
    target: str,
    run_id: str,
    sync_mode: str,
    index: int,
    credential_profile_id: str | None,
) -> dict[str, Any]:
    source_object_id = _source_object_id(payload)
    source_timestamp = _source_timestamp(payload)
    instance_id = source_instance_id(
        preview.connector_id,
        preview.source,
        credential_profile_id=credential_profile_id,
        adapter_request=preview.adapter_request,
    )
    device_id = source_device_id(preview.adapter_request)
    source_system = instance_id
    raw_ref = _raw_ref(payload, target, index)
    fingerprint_basis = source_object_id or _canonical_payload(payload)
    source_fingerprint = _fingerprint(
        {
            "connector_id": preview.connector_id,
            "capability": _capability_value(preview),
            "target": target,
            "source_instance_id": instance_id,
            "identity": fingerprint_basis,
        }
    )
    return {
        "version": QUALITY_VERSION,
        "connector_id": preview.connector_id,
        "capability": _capability_value(preview),
        "target": target,
        "sync_run_id": run_id,
        "sync_mode": sync_mode,
        "credential_profile_id": credential_profile_id,
        "device_id": device_id,
        "source_instance_id": instance_id,
        "source_system": source_system,
        "source_object_id": source_object_id,
        "source_fingerprint": source_fingerprint,
        "source_timestamp": source_timestamp,
        "ingested_at": utc_now(),
        "confidence": "low",
        "quality_status": "partial",
        "raw_ref": raw_ref,
    }


async def _apply_source_identity(
    store: SecurityStore,
    target: str,
    payload: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    existing_id = await _existing_id_for_fingerprint(store, target, str(evidence["source_fingerprint"]))
    if existing_id:
        payload["id"] = existing_id
        return payload
    if target == "assets":
        payload["id"] = _generated_object_id(target, str(evidence["source_fingerprint"]))
        return payload
    if not payload.get("id"):
        payload["id"] = _generated_object_id(target, str(evidence["source_fingerprint"]))
    return payload


async def _existing_id_for_fingerprint(store: SecurityStore, target: str, fingerprint: str) -> str | None:
    items = await _list_existing_target(store, target)
    for item in items:
        data = item.model_dump(mode="json")
        raw_data = data.get("raw_data") if isinstance(data.get("raw_data"), dict) else {}
        normalized_data = data.get("normalized_data") if isinstance(data.get("normalized_data"), dict) else {}
        for envelope in (raw_data.get("connector_evidence"), normalized_data.get("connector_evidence")):
            if isinstance(envelope, dict) and envelope.get("source_fingerprint") == fingerprint:
                return str(data.get("id") or "")
    return None


async def _list_existing_target(store: SecurityStore, target: str) -> list[Any]:
    filters = SecurityListFilters(limit=500)
    if target == "assets":
        return await store.list_assets(filters)
    if target == "vulnerabilities":
        return await store.list_vulnerabilities(filters)
    if target == "alerts":
        return await store.list_alerts(filters)
    if target == "honeypot_events":
        return await store.list_honeypot_events(filters)
    return []


def _generated_object_id(target: str, fingerprint: str) -> str:
    prefix = {
        "assets": "asset",
        "vulnerabilities": "vulnerability",
        "alerts": "alert",
        "honeypot_events": "honeypot",
    }.get(target, "security")
    return f"{prefix}-connector-{fingerprint[:16]}"


def _source_object_id(payload: dict[str, Any]) -> str | None:
    raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
    response = raw_data.get("response") if isinstance(raw_data.get("response"), dict) else {}
    candidates = [
        payload.get("source_object_id"),
        response.get("id"),
        response.get("asset_id"),
        response.get("alert_id"),
        response.get("vulnerability_id"),
        payload.get("id"),
        payload.get("name"),
        payload.get("title"),
    ]
    for candidate in candidates:
        if candidate not in (None, "", [], {}):
            return str(candidate)
    return None


def _source_timestamp(payload: dict[str, Any]) -> str | None:
    raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
    response = raw_data.get("response") if isinstance(raw_data.get("response"), dict) else {}
    normalized_data = payload.get("normalized_data") if isinstance(payload.get("normalized_data"), dict) else {}
    keys = [
        "updated_at",
        "updatedAt",
        "last_seen",
        "lastSeen",
        "observed_at",
        "observedAt",
        "occurred_at",
        "occurredAt",
        "discovered_at",
        "first_seen",
        "firstSeen",
        "timestamp",
        "time",
        "created_at",
        "createdAt",
    ]
    for root in (payload, normalized_data, response):
        for key in keys:
            value = root.get(key) if isinstance(root, dict) else None
            if value not in (None, "", [], {}):
                return str(value)
    return None


def _raw_ref(payload: dict[str, Any], target: str, index: int) -> str:
    raw_data = payload.get("raw_data") if isinstance(payload.get("raw_data"), dict) else {}
    if isinstance(raw_data.get("response"), dict):
        return "raw_data.response"
    return f"mapping_result.{target}[{index}]"


def _assess_quality(
    target: str,
    payload: dict[str, Any],
    evidence: dict[str, Any],
    diagnostics: dict[str, list[str]],
) -> dict[str, Any]:
    errors = list(diagnostics.get("missing_required_fields") or [])
    warnings = list(diagnostics.get("warnings") or [])
    if not evidence.get("source_object_id"):
        warnings.append("source_object_id is missing")
    if not evidence.get("source_timestamp"):
        warnings.append("source_timestamp is missing")
    try:
        _model_for_target(target).model_validate(payload)
    except Exception as exc:
        errors.append(str(exc))
    if errors:
        return {"status": "invalid", "errors": errors, "warnings": warnings, "confidence": "low"}
    confidence = "high" if evidence.get("source_object_id") and evidence.get("source_timestamp") else "medium"
    status = "complete" if not warnings and confidence == "high" else "partial"
    return {"status": status, "errors": [], "warnings": warnings, "confidence": confidence}


def _model_for_target(target: str) -> Any:
    if target == "assets":
        return Asset
    if target == "vulnerabilities":
        return Vulnerability
    if target == "alerts":
        return Alert
    if target == "honeypot_events":
        return HoneypotEvent
    raise ValueError(f"Unsupported connector sync target: {target}")


def _item_mapping_diagnostics(preview: ConnectorPreviewResult, index: int) -> dict[str, list[str]]:
    marker = f"[{index}]"
    missing_required = [item for item in preview.missing_required_fields if marker in item]
    warnings = [item for item in preview.transform_warnings if marker in item]
    warnings.extend(item for item in preview.unmapped_fields if marker in item)
    return {"missing_required_fields": missing_required, "warnings": warnings}


def _dead_letter(
    preview: ConnectorPreviewResult,
    run_id: str,
    target: str,
    index: int,
    payload: dict[str, Any],
    evidence: dict[str, Any],
    assessment: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": f"connector-dead-letter-{uuid4().hex}",
        "run_id": run_id,
        "connector_id": preview.connector_id,
        "capability": _capability_value(preview),
        "target": target,
        "index": index,
        "status": "invalid",
        "errors": list(assessment.get("errors") or []),
        "warnings": list(assessment.get("warnings") or []),
        "evidence": dict(evidence),
        "payload": payload,
        "replay_count": 0,
        "last_replay_at": None,
        "last_replay_run_id": None,
        "last_replay_status": None,
        "replayed_at": None,
        "replayed_object_id": None,
        "created_at": utc_now(),
    }


def _should_skip_for_cursor(source_timestamp: Any, cursor_before: str | None) -> bool:
    if not cursor_before or not source_timestamp:
        return False
    source_dt = _parse_datetime(str(source_timestamp))
    cursor_dt = _parse_datetime(cursor_before)
    if source_dt and cursor_dt:
        return source_dt <= cursor_dt
    return str(source_timestamp) <= cursor_before


def _max_timestamp(current: str | None, candidate: Any) -> str | None:
    if not candidate:
        return current
    candidate_text = str(candidate)
    if not current:
        return candidate_text
    current_dt = _parse_datetime(current)
    candidate_dt = _parse_datetime(candidate_text)
    if current_dt and candidate_dt:
        return candidate_text if candidate_dt > current_dt else current
    return candidate_text if candidate_text > current else current


def _parse_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical_payload(value).encode("utf-8")).hexdigest()


def _canonical_payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _quality_score(quality: dict[str, Any]) -> int:
    complete = int(quality.get("complete") or 0)
    partial = int(quality.get("partial") or 0)
    invalid = int(quality.get("invalid") or 0)
    total = complete + partial + invalid
    if total <= 0:
        return 100
    return max(0, min(100, round(((complete * 1.0) + (partial * 0.6)) / total * 100)))
