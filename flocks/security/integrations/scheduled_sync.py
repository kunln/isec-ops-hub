"""Scheduled Sync plan-only skeleton for Integration Runtime v2.

This module evaluates Sync Profile scheduling intent and may record a planned
Integration Run. It never executes adapters or connectors, resolves
credentials, performs preview or ingest, updates Sync Profile state, or creates
Security objects.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from flocks.security.integrations.run_store import default_integration_run_store
from flocks.security.integrations.runs import IntegrationRunCreate
from flocks.security.integrations.sync_profile_store import default_sync_profile_store

_SCHEDULE_THRESHOLDS = {
    "hourly": 3_600,
    "daily": 86_400,
    "weekly": 604_800,
}
_LIMITATIONS = [
    "schedule evaluation and plan output only",
    "no worker or automatic scheduled execution",
    "no adapter, connector, vendor API, preview, or ingest",
    "no credential access or Sync Profile state updates",
    "no Evidence, Alert, Analysis Case, Incident, notification, or remediation",
]
_SAFETY_SUMMARY: dict[str, Any] = {
    "dry_run": True,
    "plan_only": True,
    "adapter_called": False,
    "connector_called": False,
    "vendor_api_called": False,
    "credentials_read": False,
    "preview_performed": False,
    "ingest_performed": False,
    "cursor_updated": False,
    "sync_profile_state_updated": False,
    "security_objects_created": False,
    "remediation_performed": False,
}
_NEXT_ACTIONS = {
    "disabled": "当前同步配置已禁用。",
    "manual_only": "当前配置为手动模式，请使用人工计划、预览、确认入库。",
    "never_synced": "当前同步配置尚未运行，可以生成调度计划。",
    "due": "当前同步配置已到期，可以生成调度计划。",
    "not_due": "当前同步配置未到期，可继续人工计划或等待后续调度。",
    "unsupported_schedule": "当前调度配置暂不支持，请调整为 manual/hourly/daily/weekly/interval。",
    "invalid_interval": "当前调度间隔无效，请配置正整数秒数。",
    "missing_profile": "未找到指定的同步配置。",
    "validation_failed": "调度状态校验失败，请检查最近同步时间与调度配置。",
}


class _ScheduledSyncBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScheduledSyncStatus(_ScheduledSyncBaseModel):
    sync_profile_id: str
    display_name: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    capability: str | None = None
    mode: str | None = None
    enabled: bool
    schedule_kind: str
    due: bool
    reason: str
    last_status: str | None = None
    last_synced_at: str | None = None
    last_run_id: str | None = None
    next_action: str
    limitations: list[str] = Field(default_factory=list)
    safety_summary: dict[str, Any] = Field(default_factory=dict)


class ScheduledSyncPlanRequest(_ScheduledSyncBaseModel):
    sync_profile_id: str
    requested_by: str | None = None
    dry_run: bool = True
    force: bool = False

    @model_validator(mode="after")
    def _force_dry_run(self) -> "ScheduledSyncPlanRequest":
        object.__setattr__(self, "dry_run", True)
        return self


class ScheduledSyncPlanResult(_ScheduledSyncBaseModel):
    status: str
    sync_profile_id: str
    due: bool
    reason: str
    run_id: str | None = None
    planned_action: str
    plan_summary: dict[str, Any] = Field(default_factory=dict)
    safety_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _copy_safety_summary() -> dict[str, Any]:
    return dict(_SAFETY_SUMMARY)


def _copy_limitations() -> list[str]:
    return list(_LIMITATIONS)


def _parse_positive_seconds(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            seconds = int(text)
            return seconds if seconds > 0 else None
    return None


def _parse_schedule(value: Any) -> tuple[str, int | None, str | None]:
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"manual", "hourly", "daily", "weekly"}:
            return text, _SCHEDULE_THRESHOLDS.get(text), None
        if text.startswith("interval:"):
            seconds = _parse_positive_seconds(text.split(":", 1)[1])
            return "interval", seconds, None if seconds is not None else "invalid_interval"
        return "unsupported", None, "unsupported_schedule"

    if isinstance(value, dict):
        declared_kind = value.get("kind", value.get("type"))
        if declared_kind in (None, "") and "interval_seconds" in value:
            declared_kind = "interval"
        kind = str(declared_kind or "").strip().lower()
        if kind in {"manual", "hourly", "daily", "weekly"}:
            return kind, _SCHEDULE_THRESHOLDS.get(kind), None
        if kind == "interval":
            seconds = _parse_positive_seconds(
                value.get("seconds", value.get("interval_seconds"))
            )
            return "interval", seconds, None if seconds is not None else "invalid_interval"
        return "unsupported", None, "unsupported_schedule"

    return "unsupported", None, "unsupported_schedule"


def _parse_last_synced_at(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _missing_status(sync_profile_id: str) -> ScheduledSyncStatus:
    return ScheduledSyncStatus(
        sync_profile_id=sync_profile_id,
        enabled=False,
        schedule_kind="unsupported",
        due=False,
        reason="missing_profile",
        next_action=_NEXT_ACTIONS["missing_profile"],
        limitations=_copy_limitations(),
        safety_summary=_copy_safety_summary(),
    )


def evaluate_scheduled_sync_status(
    profile: Any,
    *,
    now: datetime | None = None,
) -> ScheduledSyncStatus:
    """Evaluate one Sync Profile without invoking any runtime execution path."""

    schedule_value = getattr(profile, "schedule", None)
    if schedule_value is None:
        schedule_value = getattr(profile, "mode", None)
    schedule_kind, threshold_seconds, schedule_error = _parse_schedule(schedule_value)

    reason: str
    due = False
    if getattr(profile, "enabled", True) is False:
        reason = "disabled"
    elif schedule_error is not None:
        reason = schedule_error
    elif schedule_kind == "manual":
        reason = "manual_only"
    else:
        last_synced_at = getattr(profile, "last_synced_at", None)
        if not last_synced_at:
            due = True
            reason = "never_synced"
        else:
            parsed_last_sync = _parse_last_synced_at(last_synced_at)
            if parsed_last_sync is None:
                reason = "validation_failed"
            else:
                evaluated_at = now or datetime.now(UTC)
                if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
                    reason = "validation_failed"
                else:
                    elapsed = (evaluated_at.astimezone(UTC) - parsed_last_sync).total_seconds()
                    due = elapsed >= int(threshold_seconds or 0)
                    reason = "due" if due else "not_due"

    return ScheduledSyncStatus(
        sync_profile_id=profile.sync_profile_id,
        display_name=getattr(profile, "display_name", None),
        package_id=getattr(profile, "package_id", None),
        instance_id=getattr(profile, "instance_id", None),
        capability=getattr(profile, "capability", None),
        mode=getattr(profile, "mode", None),
        enabled=bool(getattr(profile, "enabled", True)),
        schedule_kind=schedule_kind,
        due=due,
        reason=reason,
        last_status=getattr(profile, "last_status", None),
        last_synced_at=getattr(profile, "last_synced_at", None),
        last_run_id=getattr(profile, "last_run_id", None),
        next_action=_NEXT_ACTIONS[reason],
        limitations=_copy_limitations(),
        safety_summary=_copy_safety_summary(),
    )


async def list_scheduled_sync_status(
    sync_profile_id: str | None = None,
    *,
    sync_profile_store: Any = None,
    now: datetime | None = None,
) -> list[ScheduledSyncStatus]:
    sync_profile_store = sync_profile_store or default_sync_profile_store
    if sync_profile_id is not None:
        profile = await _maybe_await(sync_profile_store.get_profile(sync_profile_id))
        return [
            evaluate_scheduled_sync_status(profile, now=now)
            if profile is not None
            else _missing_status(sync_profile_id)
        ]
    profiles = await _maybe_await(sync_profile_store.list_profiles())
    return [evaluate_scheduled_sync_status(profile, now=now) for profile in profiles]


async def list_due_scheduled_sync(
    due_only: bool = True,
    *,
    sync_profile_store: Any = None,
    now: datetime | None = None,
) -> list[ScheduledSyncStatus]:
    statuses = await list_scheduled_sync_status(
        sync_profile_store=sync_profile_store,
        now=now,
    )
    return [status for status in statuses if status.due] if due_only else statuses


async def plan_scheduled_sync(
    request: ScheduledSyncPlanRequest,
    *,
    sync_profile_store: Any = None,
    run_store: Any = None,
    now: datetime | None = None,
) -> ScheduledSyncPlanResult:
    """Create a plan-only Integration Run when a profile is due or forced."""

    if not isinstance(request, ScheduledSyncPlanRequest):
        request = ScheduledSyncPlanRequest.model_validate(request)
    sync_profile_store = sync_profile_store or default_sync_profile_store
    run_store = run_store or default_integration_run_store
    profile = await _maybe_await(sync_profile_store.get_profile(request.sync_profile_id))
    if profile is None:
        return ScheduledSyncPlanResult(
            status="not_found",
            sync_profile_id=request.sync_profile_id,
            due=False,
            reason="missing_profile",
            planned_action="none",
            safety_summary=_copy_safety_summary(),
            limitations=_copy_limitations(),
            errors=["Sync profile not found"],
        )

    schedule_status = evaluate_scheduled_sync_status(profile, now=now)
    result_status = {
        "disabled": "disabled",
        "manual_only": "manual_only",
        "unsupported_schedule": "unsupported_schedule",
        "invalid_interval": "validation_failed",
        "validation_failed": "validation_failed",
        "not_due": "not_due",
    }.get(schedule_status.reason)
    should_plan = schedule_status.due or (
        request.force and schedule_status.reason == "not_due"
    )
    plan_summary = {
        "schedule_kind": schedule_status.schedule_kind,
        "evaluated_reason": schedule_status.reason,
        "due": schedule_status.due,
        "force": request.force,
        "dry_run": True,
        "planned_action": "scheduled_sync_plan_only" if should_plan else "none",
    }

    if not should_plan:
        errors = (
            ["Invalid scheduled sync configuration"]
            if result_status == "validation_failed"
            else []
        )
        return ScheduledSyncPlanResult(
            status=result_status or "not_due",
            sync_profile_id=profile.sync_profile_id,
            due=schedule_status.due,
            reason=schedule_status.reason,
            planned_action="none",
            plan_summary=plan_summary,
            safety_summary=_copy_safety_summary(),
            limitations=_copy_limitations(),
            errors=errors,
        )

    run = await _maybe_await(
        run_store.create_run(
            IntegrationRunCreate(
                run_type="scheduled_sync_plan",
                package_id=profile.package_id,
                instance_id=profile.instance_id,
                sync_profile_id=profile.sync_profile_id,
                capability=profile.capability,
                mode=profile.mode,
                status="planned",
                requested_by=request.requested_by,
                request_summary={
                    "sync_profile_id": profile.sync_profile_id,
                    "dry_run": True,
                    "force": request.force,
                },
                plan_summary=plan_summary,
                metadata={
                    "source": "scheduled_sync",
                    "dry_run": True,
                    "plan_only": True,
                    "schedule_kind": schedule_status.schedule_kind,
                },
            )
        )
    )
    return ScheduledSyncPlanResult(
        status="planned",
        sync_profile_id=profile.sync_profile_id,
        due=schedule_status.due,
        reason=schedule_status.reason,
        run_id=run.run_id,
        planned_action="scheduled_sync_plan_only",
        plan_summary=run.plan_summary,
        safety_summary=_copy_safety_summary(),
        limitations=_copy_limitations(),
    )
