"""Operational event registry for connector credential remediation."""

from __future__ import annotations

from datetime import UTC, datetime
from email.message import EmailMessage
import copy
import smtplib
import ssl
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from uuid import uuid4

from flocks.config.config import Config
from flocks.security.secrets import get_secret_manager


CONNECTOR_OPERATIONS_VERSION = "connector.operations.v1"
CONNECTOR_OPERATIONS_RELATIVE_PATH = Path("security") / "connector-operations.json"
EVENT_STATUSES = {"open", "acknowledged"}
EVENT_KINDS = {
    "credential_expiring_soon",
    "credential_expired",
    "sync_blocked",
    "schedule_policy_paused",
    "credential_remediation_requested",
}
BULK_ACTIONS = {"test", "enable_schedules", "notify"}
DEFAULT_RETENTION_SETTINGS = {
    "events_max": 1000,
    "events_days": 365,
    "bulk_runs_max": 200,
    "bulk_runs_days": 180,
    "notification_deliveries_max": 1000,
    "notification_deliveries_days": 90,
    "audit_max": 1000,
    "audit_days": 365,
}
DEFAULT_EXPIRY_MONITOR_SETTINGS = {
    "enabled": True,
    "days": 14,
    "interval_seconds": 86400,
    "notify": True,
    "last_run_at": None,
    "next_run_at": None,
}
DEFAULT_NOTIFICATION_SETTINGS = {
    "enabled": True,
    "notify_on_repeat": False,
    "sinks": [],
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_connector_operations_registry_path() -> Path:
    return Config.get_data_path() / CONNECTOR_OPERATIONS_RELATIVE_PATH


def connector_operations_registry_path_or_default(path: Path | None = None) -> Path:
    return (path or default_connector_operations_registry_path()).expanduser()


def empty_connector_operations_registry() -> dict[str, Any]:
    return {
        "version": CONNECTOR_OPERATIONS_VERSION,
        "updated_at": None,
        "settings": default_connector_operations_settings(),
        "events": [],
        "bulk_runs": [],
        "notification_deliveries": [],
        "audit": [],
    }


def default_connector_operations_settings() -> dict[str, Any]:
    return {
        "retention": copy.deepcopy(DEFAULT_RETENTION_SETTINGS),
        "expiry_monitor": copy.deepcopy(DEFAULT_EXPIRY_MONITOR_SETTINGS),
        "notifications": copy.deepcopy(DEFAULT_NOTIFICATION_SETTINGS),
    }


def load_connector_operations_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = connector_operations_registry_path_or_default(path)
    if not registry_path.is_file():
        return empty_connector_operations_registry()
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Connector operations registry must be an object: {registry_path}")
    registry = empty_connector_operations_registry()
    registry.update(data)
    registry["version"] = str(registry.get("version") or CONNECTOR_OPERATIONS_VERSION)
    registry["settings"] = _normalize_settings(registry.get("settings"))
    registry["events"] = registry.get("events") if isinstance(registry.get("events"), list) else []
    registry["bulk_runs"] = registry.get("bulk_runs") if isinstance(registry.get("bulk_runs"), list) else []
    registry["notification_deliveries"] = (
        registry.get("notification_deliveries")
        if isinstance(registry.get("notification_deliveries"), list)
        else []
    )
    registry["audit"] = registry.get("audit") if isinstance(registry.get("audit"), list) else []
    return registry


def save_connector_operations_registry(registry: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    registry_path = connector_operations_registry_path_or_default(path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry["version"] = CONNECTOR_OPERATIONS_VERSION
    registry["updated_at"] = utc_now()
    registry["settings"] = _normalize_settings(registry.get("settings"))
    retention = registry["settings"]["retention"]
    registry["events"] = _apply_retention(
        list(registry.get("events") or []),
        max_items=int(retention["events_max"]),
        max_days=int(retention["events_days"]),
        timestamp_keys=("last_seen_at", "created_at"),
    )
    registry["bulk_runs"] = _apply_retention(
        list(registry.get("bulk_runs") or []),
        max_items=int(retention["bulk_runs_max"]),
        max_days=int(retention["bulk_runs_days"]),
        timestamp_keys=("created_at",),
    )
    registry["notification_deliveries"] = _apply_retention(
        list(registry.get("notification_deliveries") or []),
        max_items=int(retention["notification_deliveries_max"]),
        max_days=int(retention["notification_deliveries_days"]),
        timestamp_keys=("created_at",),
    )
    registry["audit"] = _apply_retention(
        list(registry.get("audit") or []),
        max_items=int(retention["audit_max"]),
        max_days=int(retention["audit_days"]),
        timestamp_keys=("created_at",),
    )
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


def record_connector_operation_event(
    kind: str,
    *,
    severity: str = "info",
    connector_id: str | None = None,
    profile_id: str | None = None,
    schedule_id: str | None = None,
    run_id: str | None = None,
    reason_code: str | None = None,
    title: str | None = None,
    message: str | None = None,
    metadata: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    kind = _event_kind(kind)
    now = utc_now()
    registry = load_connector_operations_registry(path)
    event_dedupe_key = dedupe_key or _event_dedupe_key(
        kind,
        connector_id=connector_id,
        profile_id=profile_id,
        schedule_id=schedule_id,
        run_id=run_id,
        metadata=metadata,
    )
    existing = _find_event(registry, event_dedupe_key)
    if existing is not None:
        existing["last_seen_at"] = now
        existing["seen_count"] = int(existing.get("seen_count") or 1) + 1
        existing["severity"] = str(severity or existing.get("severity") or "info")
        existing["reason_code"] = reason_code
        existing["message"] = message or existing.get("message")
        existing["metadata"] = metadata or existing.get("metadata") or {}
        existing["updated_by"] = _actor(actor)
        if existing.get("status") not in EVENT_STATUSES:
            existing["status"] = "open"
        save_connector_operations_registry(registry, path)
        return dict(existing)

    event = {
        "id": f"connector-operation-event-{uuid4().hex}",
        "version": "connector.operation.event.v1",
        "kind": kind,
        "status": "open",
        "severity": str(severity or "info"),
        "connector_id": connector_id,
        "profile_id": profile_id,
        "schedule_id": schedule_id,
        "run_id": run_id,
        "reason_code": reason_code,
        "title": title or _default_title(kind, connector_id, profile_id),
        "message": message or "",
        "created_at": now,
        "last_seen_at": now,
        "acknowledged_at": None,
        "acknowledged_by": None,
        "seen_count": 1,
        "dedupe_key": event_dedupe_key,
        "metadata": metadata or {},
        "created_by": _actor(actor),
        "updated_by": _actor(actor),
        "notifications": [],
    }
    registry.setdefault("events", []).append(event)
    _append_audit(
        registry,
        "event.record",
        actor=actor,
        target=event["id"],
        details={"kind": kind, "dedupe_key": event_dedupe_key},
    )
    save_connector_operations_registry(registry, path)
    return dict(event)


def list_connector_operation_events(
    *,
    status: str | None = None,
    kind: str | None = None,
    severity: str | None = None,
    connector_id: str | None = None,
    profile_id: str | None = None,
    schedule_id: str | None = None,
    reason_code: str | None = None,
    keyword: str | None = None,
    limit: int = 100,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    registry = load_connector_operations_registry(path)
    events = [dict(event) for event in registry["events"] if isinstance(event, dict)]
    if status:
        events = [event for event in events if event.get("status") == status]
    if kind:
        events = [event for event in events if event.get("kind") == kind]
    if severity:
        events = [event for event in events if event.get("severity") == severity]
    if connector_id:
        events = [event for event in events if event.get("connector_id") == connector_id]
    if profile_id:
        events = [event for event in events if event.get("profile_id") == profile_id]
    if schedule_id:
        events = [event for event in events if event.get("schedule_id") == schedule_id]
    if reason_code:
        events = [event for event in events if event.get("reason_code") == reason_code]
    if keyword:
        needle = keyword.lower()
        events = [event for event in events if needle in json.dumps(event, ensure_ascii=False).lower()]
    events.sort(key=lambda item: str(item.get("last_seen_at") or item.get("created_at") or ""), reverse=True)
    return events[: max(1, int(limit))]


def get_connector_operation_event(event_id: str, *, path: Path | None = None) -> dict[str, Any] | None:
    registry = load_connector_operations_registry(path)
    for event in registry["events"]:
        if isinstance(event, dict) and event.get("id") == event_id:
            return dict(event)
    return None


def acknowledge_connector_operation_event(
    event_id: str,
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_operations_registry(path)
    for event in registry["events"]:
        if isinstance(event, dict) and event.get("id") == event_id:
            event["status"] = "acknowledged"
            event["acknowledged_at"] = utc_now()
            event["acknowledged_by"] = _actor(actor)
            event["updated_by"] = _actor(actor)
            _append_audit(
                registry,
                "event.acknowledge",
                actor=actor,
                target=event_id,
                details={"kind": event.get("kind")},
            )
            save_connector_operations_registry(registry, path)
            return dict(event)
    raise ValueError(f"Connector operation event not found: {event_id}")


def acknowledge_connector_operation_events(
    event_ids: list[str],
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    requested = [str(event_id) for event_id in event_ids if str(event_id or "").strip()]
    registry = load_connector_operations_registry(path)
    acknowledged: list[dict[str, Any]] = []
    missing: list[str] = []
    now = utc_now()
    for event_id in requested:
        matched = None
        for event in registry["events"]:
            if isinstance(event, dict) and event.get("id") == event_id:
                matched = event
                break
        if matched is None:
            missing.append(event_id)
            continue
        matched["status"] = "acknowledged"
        matched["acknowledged_at"] = now
        matched["acknowledged_by"] = _actor(actor)
        matched["updated_by"] = _actor(actor)
        acknowledged.append(dict(matched))
    if acknowledged:
        _append_audit(
            registry,
            "event.bulk_acknowledge",
            actor=actor,
            target="connector-operation-events",
            details={"event_ids": [event["id"] for event in acknowledged], "missing": missing},
        )
        save_connector_operations_registry(registry, path)
    return {
        "version": "connector.operation.event.bulk_ack.v1",
        "requested": len(requested),
        "acknowledged": len(acknowledged),
        "missing": missing,
        "events": acknowledged,
    }


def record_connector_bulk_operation(
    *,
    action: str,
    requested: int,
    succeeded: int,
    failed: int,
    results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    action = str(action or "")
    if action not in BULK_ACTIONS:
        raise ValueError(f"Unsupported connector bulk remediation action: {action}")
    registry = load_connector_operations_registry(path)
    record = {
        "id": f"connector-bulk-remediation-{uuid4().hex}",
        "version": "connector.bulk.remediation.v1",
        "action": action,
        "requested": int(requested),
        "succeeded": int(succeeded),
        "failed": int(failed),
        "created_at": utc_now(),
        "metadata": metadata or {},
        "results": results,
        "actor": _actor(actor),
    }
    registry.setdefault("bulk_runs", []).append(record)
    _append_audit(
        registry,
        "bulk.record",
        actor=actor,
        target=record["id"],
        details={"action": action, "requested": requested, "succeeded": succeeded, "failed": failed},
    )
    save_connector_operations_registry(registry, path)
    return dict(record)


def get_connector_operations_settings(path: Path | None = None) -> dict[str, Any]:
    registry = load_connector_operations_registry(path)
    return copy.deepcopy(registry["settings"])


def update_connector_operations_settings(
    updates: dict[str, Any],
    *,
    actor: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_operations_registry(path)
    current = copy.deepcopy(registry["settings"])
    merged = _deep_merge(current, updates if isinstance(updates, dict) else {})
    merged = _normalize_settings(_protect_notification_sink_secrets(merged))
    registry["settings"] = merged
    _append_audit(
        registry,
        "settings.update",
        actor=actor,
        target="connector-operations-settings",
        details={"sections": sorted((updates or {}).keys())},
    )
    save_connector_operations_registry(registry, path)
    return copy.deepcopy(merged)


def mark_expiry_monitor_run(
    result: dict[str, Any],
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    registry = load_connector_operations_registry(path)
    settings = registry["settings"]
    monitor = settings["expiry_monitor"]
    checked_at = str(result.get("checked_at") or utc_now())
    monitor["last_run_at"] = checked_at
    monitor["last_result"] = {
        "matched": int(result.get("matched") or 0),
        "expired": int(result.get("expired") or 0),
        "expiring_soon": int(result.get("expiring_soon") or 0),
        "events": len(result.get("events") or []),
    }
    monitor["next_run_at"] = _next_time(int(monitor.get("interval_seconds") or 86400), base=checked_at)
    registry["settings"] = settings
    save_connector_operations_registry(registry, path)
    return copy.deepcopy(monitor)


def deliver_connector_operation_event_notifications(
    event_id: str,
    *,
    force: bool = False,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    registry = load_connector_operations_registry(path)
    event = None
    for item in registry["events"]:
        if isinstance(item, dict) and item.get("id") == event_id:
            event = item
            break
    if event is None:
        raise ValueError(f"Connector operation event not found: {event_id}")

    notification_settings = registry["settings"]["notifications"]
    sinks = [
        sink
        for sink in notification_settings.get("sinks") or []
        if isinstance(sink, dict) and sink.get("enabled", True)
    ]
    if not notification_settings.get("enabled", True) or not sinks:
        return []
    already_delivered = any(
        isinstance(item, dict) and item.get("status") == "success"
        for item in event.get("notifications") or []
    )
    if already_delivered and not (force or notification_settings.get("notify_on_repeat")):
        return []

    deliveries: list[dict[str, Any]] = []
    for sink in sinks:
        deliveries.append(_deliver_to_sink(dict(sink), dict(event)))
    event.setdefault("notifications", []).extend(
        {
            "delivery_id": item["id"],
            "sink_id": item.get("sink_id"),
            "sink_type": item.get("sink_type"),
            "status": item.get("status"),
            "created_at": item.get("created_at"),
            "error": item.get("error"),
        }
        for item in deliveries
    )
    registry.setdefault("notification_deliveries", []).extend(deliveries)
    save_connector_operations_registry(registry, path)
    return deliveries


def connector_operations_summary(path: Path | None = None) -> dict[str, Any]:
    registry = load_connector_operations_registry(path)
    events = [event for event in registry["events"] if isinstance(event, dict)]
    open_events = [event for event in events if event.get("status") == "open"]
    settings = registry["settings"]
    notification_sinks = [
        sink for sink in settings["notifications"].get("sinks") or []
        if isinstance(sink, dict)
    ]
    return {
        "path": str(connector_operations_registry_path_or_default(path)),
        "version": registry.get("version"),
        "events": len(events),
        "open_events": len(open_events),
        "events_by_kind": _counts(events, "kind"),
        "open_events_by_kind": _counts(open_events, "kind"),
        "bulk_runs": len([item for item in registry["bulk_runs"] if isinstance(item, dict)]),
        "notification_sinks": len(notification_sinks),
        "enabled_notification_sinks": sum(1 for sink in notification_sinks if sink.get("enabled", True)),
        "notification_deliveries": len([item for item in registry["notification_deliveries"] if isinstance(item, dict)]),
        "audit_events": len([item for item in registry["audit"] if isinstance(item, dict)]),
        "retention": copy.deepcopy(settings["retention"]),
        "expiry_monitor": copy.deepcopy(settings["expiry_monitor"]),
        "last_event": dict(max(events, key=lambda item: str(item.get("last_seen_at") or item.get("created_at") or ""), default={})) or None,
    }


def _normalize_settings(raw: Any) -> dict[str, Any]:
    settings = default_connector_operations_settings()
    if isinstance(raw, dict):
        settings = _deep_merge(settings, raw)
    retention = settings["retention"]
    for key, default_value in DEFAULT_RETENTION_SETTINGS.items():
        retention[key] = _coerce_int(retention.get(key), default_value, minimum=1)
    monitor = settings["expiry_monitor"]
    monitor["enabled"] = bool(monitor.get("enabled", True))
    monitor["days"] = _coerce_int(monitor.get("days"), DEFAULT_EXPIRY_MONITOR_SETTINGS["days"], minimum=0)
    monitor["interval_seconds"] = _coerce_int(
        monitor.get("interval_seconds"),
        DEFAULT_EXPIRY_MONITOR_SETTINGS["interval_seconds"],
        minimum=60,
    )
    monitor["notify"] = bool(monitor.get("notify", True))
    notifications = settings["notifications"]
    notifications["enabled"] = bool(notifications.get("enabled", True))
    notifications["notify_on_repeat"] = bool(notifications.get("notify_on_repeat", False))
    sinks = notifications.get("sinks") if isinstance(notifications.get("sinks"), list) else []
    notifications["sinks"] = [_normalize_sink(sink) for sink in sinks if isinstance(sink, dict)]
    return settings


def _normalize_sink(raw: dict[str, Any]) -> dict[str, Any]:
    sink = dict(raw)
    sink_id = str(sink.get("id") or "").strip() or f"operation-sink-{uuid4().hex}"
    sink["id"] = _safe_segment(sink_id) or sink_id
    sink["type"] = str(sink.get("type") or "webhook").strip().lower()
    sink["enabled"] = bool(sink.get("enabled", True))
    sink["name"] = str(sink.get("name") or sink["id"])
    if sink["type"] == "email":
        email = sink.get("email") if isinstance(sink.get("email"), dict) else {}
        sink["email"] = {
            "smtp_host": str(email.get("smtp_host") or ""),
            "smtp_port": _coerce_int(email.get("smtp_port"), 587, minimum=1),
            "smtp_username": str(email.get("smtp_username") or ""),
            "smtp_password_secret_id": email.get("smtp_password_secret_id"),
            "smtp_starttls": bool(email.get("smtp_starttls", True)),
            "from": str(email.get("from") or email.get("smtp_username") or ""),
            "to": [str(item) for item in email.get("to") or [] if str(item or "").strip()],
        }
    return sink


def _protect_notification_sink_secrets(settings: dict[str, Any]) -> dict[str, Any]:
    protected = copy.deepcopy(settings)
    sinks = ((protected.get("notifications") or {}).get("sinks") or [])
    secret_manager = get_secret_manager()
    for raw_sink in sinks:
        if not isinstance(raw_sink, dict):
            continue
        sink_id = _safe_segment(str(raw_sink.get("id") or f"operation-sink-{uuid4().hex}"))
        url = raw_sink.pop("url", None)
        if isinstance(url, str) and url:
            secret_id = f"connector_operation_notification_{sink_id}_url"
            secret_manager.set(secret_id, url)
            raw_sink["url_secret_id"] = secret_id
            raw_sink["url_masked"] = secret_manager.mask(url)
        if isinstance(raw_sink.get("email"), dict):
            password = raw_sink["email"].pop("smtp_password", None)
            if isinstance(password, str) and password:
                secret_id = f"connector_operation_notification_{sink_id}_smtp_password"
                secret_manager.set(secret_id, password)
                raw_sink["email"]["smtp_password_secret_id"] = secret_id
                raw_sink["email"]["smtp_password_masked"] = secret_manager.mask(password)
    return protected


def _deliver_to_sink(sink: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    delivery = {
        "id": f"connector-operation-notification-{uuid4().hex}",
        "version": "connector.operation.notification.delivery.v1",
        "event_id": event.get("id"),
        "event_kind": event.get("kind"),
        "sink_id": sink.get("id"),
        "sink_type": sink.get("type"),
        "status": "pending",
        "created_at": utc_now(),
        "error": None,
    }
    try:
        sink_type = str(sink.get("type") or "webhook")
        if sink_type == "email":
            _send_email_notification(sink, event)
        else:
            _send_http_notification(sink, event)
        delivery["status"] = "success"
    except Exception as exc:
        delivery["status"] = "error"
        delivery["error"] = str(exc)
    return delivery


def _send_http_notification(sink: dict[str, Any], event: dict[str, Any]) -> None:
    url = _resolve_secret_or_value(sink.get("url_secret_id"), sink.get("url"))
    if not url:
        raise ValueError(f"Notification sink {sink.get('id')} is missing url")
    sink_type = str(sink.get("type") or "webhook")
    text = _format_event_text(event)
    if sink_type == "slack":
        payload = {"text": text, "event": event}
    elif sink_type == "wecom":
        payload = {"msgtype": "text", "text": {"content": text}}
    else:
        payload = {"event": event, "text": text}
    _send_http_json(str(url), payload, timeout=float(sink.get("timeout_seconds") or 5))


def _send_http_json(url: str, payload: dict[str, Any], *, timeout: float = 5) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            if response.status >= 400:
                raise ValueError(f"Webhook notification failed with HTTP {response.status}")
    except HTTPError as exc:
        raise ValueError(f"Webhook notification failed with HTTP {exc.code}") from exc
    except URLError as exc:
        raise ValueError(f"Webhook notification failed: {exc.reason}") from exc


def _send_email_notification(sink: dict[str, Any], event: dict[str, Any]) -> None:
    email = sink.get("email") if isinstance(sink.get("email"), dict) else {}
    smtp_host = str(email.get("smtp_host") or "")
    recipients = [str(item) for item in email.get("to") or [] if str(item or "").strip()]
    sender = str(email.get("from") or email.get("smtp_username") or "")
    if not smtp_host or not sender or not recipients:
        raise ValueError(f"Email notification sink {sink.get('id')} is missing smtp_host/from/to")
    message = EmailMessage()
    message["Subject"] = f"[Flocks] {event.get('title') or event.get('kind')}"
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(_format_event_text(event))
    password = _resolve_secret_or_value(email.get("smtp_password_secret_id"), email.get("smtp_password"))
    port = int(email.get("smtp_port") or 587)
    if email.get("smtp_starttls", True):
        with smtplib.SMTP(smtp_host, port, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if email.get("smtp_username"):
                smtp.login(str(email.get("smtp_username")), str(password or ""))
            smtp.send_message(message)
    else:
        with smtplib.SMTP(smtp_host, port, timeout=10) as smtp:
            if email.get("smtp_username"):
                smtp.login(str(email.get("smtp_username")), str(password or ""))
            smtp.send_message(message)


def _format_event_text(event: dict[str, Any]) -> str:
    parts = [
        str(event.get("title") or event.get("kind") or "Connector operation event"),
        f"severity={event.get('severity') or '-'} status={event.get('status') or '-'}",
    ]
    target = "/".join(str(item) for item in [event.get("connector_id"), event.get("profile_id")] if item)
    if target:
        parts.append(f"target={target}")
    if event.get("schedule_id"):
        parts.append(f"schedule={event.get('schedule_id')}")
    if event.get("reason_code"):
        parts.append(f"reason={event.get('reason_code')}")
    if event.get("message"):
        parts.append(str(event.get("message")))
    return "\n".join(parts)


def _resolve_secret_or_value(secret_id: Any, value: Any = None) -> str | None:
    if secret_id:
        return get_secret_manager().get(str(secret_id))
    return str(value) if value else None


def _append_audit(
    registry: dict[str, Any],
    action: str,
    *,
    actor: dict[str, Any] | None,
    target: str,
    details: dict[str, Any] | None = None,
) -> None:
    registry.setdefault("audit", []).append(
        {
            "id": f"connector-operation-audit-{uuid4().hex}",
            "action": f"connector_operation.{action}",
            "target": target,
            "actor": _actor(actor),
            "created_at": utc_now(),
            "details": details or {},
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


def _apply_retention(
    records: list[Any],
    *,
    max_items: int,
    max_days: int,
    timestamp_keys: tuple[str, ...],
) -> list[Any]:
    cutoff = datetime.now(UTC).timestamp() - (max_days * 86400)
    kept: list[Any] = []
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


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _next_time(seconds: int, *, base: str | None = None) -> str:
    base_dt = _parse_datetime(base) if base else None
    base_dt = base_dt or datetime.now(UTC)
    return datetime.fromtimestamp(base_dt.timestamp() + max(60, int(seconds)), tz=UTC).isoformat()


def _coerce_int(value: Any, default: int, *, minimum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = int(default)
    return max(minimum, result)


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _safe_segment(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in str(value).strip())[:96]


def _event_kind(value: str) -> str:
    kind = str(value or "").strip()
    if kind not in EVENT_KINDS:
        raise ValueError(f"Unsupported connector operation event kind: {kind}")
    return kind


def _find_event(registry: dict[str, Any], dedupe_key: str) -> dict[str, Any] | None:
    for event in registry.get("events") or []:
        if isinstance(event, dict) and event.get("dedupe_key") == dedupe_key:
            return event
    return None


def _event_dedupe_key(
    kind: str,
    *,
    connector_id: str | None,
    profile_id: str | None,
    schedule_id: str | None,
    run_id: str | None,
    metadata: dict[str, Any] | None,
) -> str:
    expires_at = (metadata or {}).get("expires_at")
    return ":".join(
        [
            kind,
            connector_id or "-",
            profile_id or "-",
            schedule_id or "-",
            run_id or str(expires_at or "-"),
        ]
    )


def _default_title(kind: str, connector_id: str | None, profile_id: str | None) -> str:
    target = "/".join(item for item in [connector_id, profile_id] if item)
    labels = {
        "credential_expiring_soon": "Credential profile expiring soon",
        "credential_expired": "Credential profile expired",
        "sync_blocked": "Connector sync blocked",
        "schedule_policy_paused": "Connector schedule policy-paused",
        "credential_remediation_requested": "Credential remediation requested",
    }
    return f"{labels.get(kind, kind)}: {target}" if target else labels.get(kind, kind)


def _counts(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value = str(record.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts
