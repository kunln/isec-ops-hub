from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any


WORKFLOW_ID = "security_alert_triage_notify"
DEFAULT_SEVERITIES = ["critical", "high"]
DEFAULT_STATUSES = ["new"]


def _list(value: Any, default: list[str]) -> list[str]:
    if value in (None, ""):
        return list(default)
    if isinstance(value, str):
        return [item.strip().lower() for item in value.replace("，", ",").split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip().lower() for item in value if str(item).strip()]
    return list(default)


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on", "是", "开启"}
    return bool(value)


def _int(value: Any, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        result = int(value)
    except Exception:
        result = default
    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)
    return result


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        numeric = float(raw)
        if numeric > 10_000_000_000:
            numeric = numeric / 1000
        if numeric > 0:
            return datetime.fromtimestamp(numeric, UTC)
    except ValueError:
        pass
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _alert_time(alert: Any) -> datetime | None:
    for attr in ("occurred_at", "created_at", "updated_at"):
        parsed = _parse_time(getattr(alert, attr, None))
        if parsed is not None:
            return parsed
    return None


def _trim(text: Any, limit: int = 280) -> str:
    value = str(text or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _display_time(*values: Any) -> str:
    for value in values:
        parsed = _parse_time(value)
        if parsed is not None:
            return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        if value not in (None, ""):
            return str(value)
    return "-"


def _cancelled() -> bool:
    checker = globals().get("cancelled")
    if callable(checker):
        try:
            return bool(checker())
        except Exception:
            return False
    return False


def _state_key(channel_id: str, target: str) -> str:
    target_hash = hashlib.sha256((target or "unbound").encode("utf-8")).hexdigest()[:16]
    safe_channel = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in channel_id) or "channel"
    return f"workflow/{WORKFLOW_ID}/dedupe/{safe_channel}/{target_hash}"


async def _resolve_target(channel_id: str, explicit_to: str, explicit_account_id: str) -> tuple[str, str, str | None]:
    if explicit_to:
        return explicit_to, explicit_account_id, None

    from flocks.channel.inbound.session_binding import SessionBindingService

    bindings = await SessionBindingService().list_bindings(channel_id=channel_id)
    if not bindings:
        return "", explicit_account_id, None

    binding = bindings[0]
    return binding.chat_id, explicit_account_id or binding.account_id, binding.session_id


def _format_message(
    *,
    channel_id: str,
    target: str,
    triaged: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    remaining: int,
) -> str:
    now = datetime.now(UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    parts = [
        "[Flocks] 安全告警研判通知",
        f"时间：{now}",
        f"通道：{channel_id}",
        f"目标：{target}",
        f"本次研判：{len(triaged)} 条",
    ]
    if remaining > 0:
        parts.append(f"还有 {remaining} 条候选告警未在本批次处理。")
    if errors:
        parts.append(f"研判异常：{len(errors)} 条")

    for index, item in enumerate(triaged, start=1):
        alert = item["alert"]
        triage = item["triage"]
        recommendations = triage.get("recommended_actions") or []
        rec_text = "；".join(_trim(text, 120) for text in recommendations[:3]) or "-"
        parts.extend(
            [
                "",
                f"{index}. [{alert.get('severity')}] {alert.get('title') or alert.get('id')}",
                f"告警ID：{alert.get('id')}",
                f"来源/状态：{alert.get('source') or '-'} / {alert.get('status') or '-'}",
                f"资产：{alert.get('asset_id') or '-'}",
                f"发生时间：{_display_time(alert.get('occurred_at'), alert.get('created_at'))}",
                f"研判结论：{_trim(triage.get('summary') or triage.get('analysis') or '-', 320)}",
                f"置信度：{triage.get('confidence') or '-'}",
                f"事件ID：{triage.get('incident_id') or '未创建'}",
                f"推荐动作：{rec_text}",
            ]
        )

    if errors:
        parts.append("")
        parts.append("异常明细：")
        for error in errors[:5]:
            parts.append(f"- {error.get('alert_id')}: {_trim(error.get('error'), 160)}")

    return "\n".join(parts)


async def _deliver(channel_id: str, account_id: str, target: str, text: str, session_id: str | None) -> list[dict[str, Any]]:
    from flocks.channel.base import OutboundContext
    from flocks.channel.outbound.deliver import OutboundDelivery

    result = await OutboundDelivery.deliver(
        OutboundContext(
            channel_id=channel_id,
            account_id=account_id or None,
            to=target,
            text=text,
        ),
        session_id=session_id,
    )
    return [asdict(item) for item in result]


async def run(raw_inputs: dict[str, Any]) -> dict[str, Any]:
    from flocks.security.schemas import SecurityListFilters
    from flocks.security.store import default_store
    from flocks.security.triage import triage_alert
    from flocks.storage.storage import Storage

    await Storage.init()

    channel_id = str(raw_inputs.get("channel_id") or raw_inputs.get("channel") or "weixin").strip().lower()
    explicit_to = str(raw_inputs.get("to") or raw_inputs.get("target") or "").strip()
    explicit_account_id = str(raw_inputs.get("account_id") or raw_inputs.get("accountId") or "").strip()
    target, account_id, session_id = await _resolve_target(channel_id, explicit_to, explicit_account_id)

    if not target:
        return {
            "success": False,
            "reason": "no_channel_binding",
            "message": "未找到通道收件人。请先从对应 IM 通道给 Flocks Bot 发送一条消息，或在任务 context.to 中配置目标 ID。",
            "channel_id": channel_id,
        }

    severities = set(_list(raw_inputs.get("severity_levels", raw_inputs.get("severities")), DEFAULT_SEVERITIES))
    statuses = set(_list(raw_inputs.get("statuses"), DEFAULT_STATUSES))
    include_sources = set(_list(raw_inputs.get("sources"), []))
    max_alerts = _int(raw_inputs.get("max_alerts"), 10, minimum=1, maximum=50)
    scan_limit = _int(raw_inputs.get("scan_limit"), 500, minimum=max_alerts, maximum=500)
    lookback_minutes = _int(raw_inputs.get("lookback_minutes"), 24 * 60, minimum=0, maximum=30 * 24 * 60)
    create_incident = _bool(raw_inputs.get("create_incident"), True)
    dry_run = _bool(raw_inputs.get("dry_run"), False)
    reset_state = _bool(raw_inputs.get("reset_state"), False)
    send_when_empty = _bool(raw_inputs.get("send_when_empty"), False)

    state_key = _state_key(channel_id, target)
    if reset_state:
        state = {}
    else:
        loaded = await Storage.read(state_key)
        state = loaded if isinstance(loaded, dict) else {}
    sent_ids = {str(item) for item in state.get("sent_alert_ids") or []}

    cutoff = datetime.now(UTC) - timedelta(minutes=lookback_minutes) if lookback_minutes else None
    alerts = await default_store.list_alerts(SecurityListFilters(limit=scan_limit))
    candidates = []
    for alert in alerts:
        if alert.id in sent_ids:
            continue
        if str(alert.severity).lower() not in severities:
            continue
        if statuses and str(alert.status).lower() not in statuses:
            continue
        if include_sources and str(alert.source).lower() not in include_sources:
            continue
        event_time = _alert_time(alert)
        if cutoff is not None and event_time is not None and event_time < cutoff:
            continue
        candidates.append(alert)

    selected = candidates[:max_alerts]
    triaged: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for alert in selected:
        if _cancelled():
            return {"success": False, "reason": "cancelled", "processed": len(triaged)}
        try:
            triage = await triage_alert(alert.id, create_incident=create_incident)
            triaged.append(
                {
                    "alert": alert.model_dump(mode="json"),
                    "triage": triage.model_dump(mode="json"),
                }
            )
        except Exception as exc:
            errors.append({"alert_id": alert.id, "error": str(exc)})

    if not triaged and not send_when_empty:
        return {
            "success": True,
            "channel_id": channel_id,
            "target": target,
            "processed": 0,
            "candidate_count": len(candidates),
            "errors": errors,
            "message": "没有符合条件且未推送过的高危/严重告警。",
        }

    text = _format_message(
        channel_id=channel_id,
        target=target,
        triaged=triaged,
        errors=errors,
        remaining=max(0, len(candidates) - len(selected)),
    )
    delivery_results: list[dict[str, Any]] = []
    delivery_ok = True
    if dry_run:
        delivery_results = [{"channel_id": channel_id, "success": True, "message_id": "dry-run"}]
    else:
        delivery_results = await _deliver(channel_id, account_id, target, text, session_id)
        delivery_ok = all(item.get("success") for item in delivery_results)

    if delivery_ok and not dry_run:
        next_sent = list(dict.fromkeys([*list(sent_ids), *[item["alert"]["id"] for item in triaged]]))[-5000:]
        await Storage.write(
            state_key,
            {
                "updated_at": datetime.now(UTC).isoformat(),
                "channel_id": channel_id,
                "target_hash": hashlib.sha256(target.encode("utf-8")).hexdigest()[:16],
                "sent_alert_ids": next_sent,
            },
        )

    return {
        "success": delivery_ok,
        "channel_id": channel_id,
        "target": target,
        "processed": len(triaged),
        "candidate_count": len(candidates),
        "remaining": max(0, len(candidates) - len(selected)),
        "dry_run": dry_run,
        "state_key": state_key,
        "delivery": delivery_results,
        "errors": errors,
        "preview": text if dry_run else text[:1200],
    }


outputs.update(asyncio.run(run(inputs)))
