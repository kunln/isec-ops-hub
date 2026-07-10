"""Sync Engine manual dry-run planning skeleton.

This module connects Sync Profile metadata to Capability Runtime dry-run
planning and Integration Run history. It intentionally does not execute
connectors, perform HTTP requests, read credentials, resolve secret refs,
dispatch evidence, create Security objects, update Sync Profile cursors, or run
remediation.
"""

from __future__ import annotations

import inspect
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.instance_store import (
    default_integration_instance_store,
)
from flocks.security.integrations.instances import (
    build_capability_run_request_from_instance,
)
from flocks.security.integrations.run_store import default_integration_run_store
from flocks.security.integrations.runs import IntegrationRunCreate, safe_export_summary
from flocks.security.integrations.runtime import (
    SECRET_LIKE_VALUE_HINTS,
    SENSITIVE_PARAM_KEYWORDS,
    IntegrationCapabilityRuntime,
    sanitize_run_params,
)
from flocks.security.integrations.sync_profile_store import default_sync_profile_store


class _SyncEngineBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class SyncEnginePlanRequest(_SyncEngineBaseModel):
    sync_profile_id: str
    requested_by: str | None = None
    params_override: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True


class SyncEnginePlanResult(_SyncEngineBaseModel):
    status: str
    dry_run: bool = True
    sync_profile_id: str
    run_id: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    capability: str | None = None
    request_summary: dict[str, Any] = Field(default_factory=dict)
    plan_summary: dict[str, Any] = Field(default_factory=dict)
    safety_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _secret_like_errors(params: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key)
                if any(
                    keyword in key_text.lower() for keyword in SENSITIVE_PARAM_KEYWORDS
                ):
                    errors.append(
                        f"params_override contains secret-like key: {path}{key_text}"
                    )
                visit(item, f"{path}{key_text}.")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}{index}.")
        elif isinstance(value, str) and any(
            hint in value.lower() for hint in SECRET_LIKE_VALUE_HINTS
        ):
            errors.append(
                f"params_override contains secret-like value: {path.rstrip('.') or 'params_override'}"
            )

    visit(params, "")
    return errors


async def plan_sync_profile_run(
    request: SyncEnginePlanRequest,
    *,
    sync_profile_store=None,
    instance_store=None,
    run_store=None,
    runtime=None,
) -> SyncEnginePlanResult:
    """Plan a Sync Profile run without executing synchronization."""

    sync_profile_store = sync_profile_store or default_sync_profile_store
    instance_store = instance_store or default_integration_instance_store
    run_store = run_store or default_integration_run_store
    runtime = runtime or IntegrationCapabilityRuntime()

    profile = await _maybe_await(
        sync_profile_store.get_profile(request.sync_profile_id)
    )
    if profile is None:
        return SyncEnginePlanResult(
            status="not_found",
            sync_profile_id=request.sync_profile_id,
            errors=["Sync profile not found"],
        )

    override_errors = _secret_like_errors(request.params_override)
    if override_errors:
        run = await _maybe_await(
            run_store.create_run(
                IntegrationRunCreate(
                    run_type="sync_profile_plan",
                    package_id=profile.package_id,
                    instance_id=profile.instance_id,
                    sync_profile_id=profile.sync_profile_id,
                    capability=profile.capability,
                    mode=profile.mode,
                    status="validation_failed",
                    requested_by=request.requested_by,
                    request_summary={
                        "dry_run": True,
                        "params": sanitize_run_params(profile.params),
                        "params_override": sanitize_run_params(request.params_override),
                    },
                    plan_summary={"status": "validation_failed"},
                    metadata={"source": "SyncEngine", "dry_run": True},
                )
            )
        )
        return SyncEnginePlanResult(
            status="validation_failed",
            dry_run=True,
            sync_profile_id=profile.sync_profile_id,
            run_id=run.run_id,
            package_id=profile.package_id,
            instance_id=profile.instance_id,
            capability=profile.capability,
            request_summary=run.request_summary,
            plan_summary=run.plan_summary,
            safety_summary={
                "credential_access": "none",
                "http_requests": "disabled",
                "evidence_dispatch": "disabled",
            },
            errors=override_errors,
        )

    instance = await _maybe_await(instance_store.get_instance(profile.instance_id))
    if instance is None:
        errors = [f"Unknown integration instance: {profile.instance_id}"]
        run = await _record_plan_run(
            run_store, profile, request, "validation_failed", {}, errors
        )
        return _result_from_run(profile, run, {}, errors)

    merged_params = {**dict(profile.params), **dict(request.params_override)}
    capability_request = build_capability_run_request_from_instance(
        instance,
        profile.capability,
        params=merged_params,
        dry_run=True,
    ).model_copy(
        update={
            "mode": profile.mode,
            "requested_by": request.requested_by,
            "dry_run": True,
        }
    )
    plan = runtime.build_plan(capability_request)
    errors = [
        item
        for item in plan.limitations
        if item.startswith(("Unknown ", "Destructive "))
    ]
    run_status = "planned" if plan.status == "planned" else "validation_failed"
    run = await _record_plan_run(
        run_store,
        profile,
        request,
        run_status,
        plan.model_dump(mode="json"),
        errors,
        request_summary=plan.request_summary,
    )
    return _result_from_run(profile, run, plan.model_dump(mode="json"), errors)


async def _record_plan_run(
    run_store: Any,
    profile: Any,
    request: SyncEnginePlanRequest,
    status: str,
    plan: dict[str, Any],
    errors: list[str],
    request_summary: dict[str, Any] | None = None,
) -> Any:
    return await _maybe_await(
        run_store.create_run(
            IntegrationRunCreate(
                run_type="sync_profile_plan",
                package_id=profile.package_id,
                instance_id=profile.instance_id,
                sync_profile_id=profile.sync_profile_id,
                capability=profile.capability,
                mode=profile.mode,
                status=status,
                requested_by=request.requested_by,
                request_summary=request_summary
                or {
                    "sync_profile_id": profile.sync_profile_id,
                    "dry_run": True,
                    "params": sanitize_run_params(
                        {**dict(profile.params), **dict(request.params_override)}
                    ),
                },
                plan_summary=_safe_plan_summary(plan),
                error_message="; ".join(errors) if errors else None,
                metadata={"source": "SyncEngine", "dry_run": True},
            )
        )
    )


def _safe_plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
    return safe_export_summary(
        {
            "package_id": plan.get("package_id"),
            "capability": plan.get("capability"),
            "mode": plan.get("mode"),
            "status": plan.get("status"),
            "request_summary": plan.get("request_summary", {}),
            "capability_summary": plan.get("capability_summary", {}),
            "safety_summary": {
                "credential_access": plan.get("safety_summary", {}).get(
                    "credential_access"
                ),
                "http_requests": plan.get("safety_summary", {}).get("http_requests"),
                "v1_connector_invocation": plan.get("safety_summary", {}).get(
                    "v1_connector_invocation"
                ),
                "security_object_creation": plan.get("safety_summary", {}).get(
                    "security_object_creation"
                ),
                "package_known": plan.get("safety_summary", {}).get("package_known"),
            },
        }
    )


def _result_from_run(
    profile: Any, run: Any, plan: dict[str, Any], errors: list[str]
) -> SyncEnginePlanResult:
    return SyncEnginePlanResult(
        status=run.status,
        dry_run=True,
        sync_profile_id=profile.sync_profile_id,
        run_id=run.run_id,
        package_id=profile.package_id,
        instance_id=profile.instance_id,
        capability=profile.capability,
        request_summary=run.request_summary,
        plan_summary=run.plan_summary,
        safety_summary=plan.get(
            "safety_summary",
            {
                "credential_access": "none",
                "http_requests": "disabled",
                "evidence_dispatch": "disabled",
            },
        ),
        limitations=list(plan.get("limitations", [])),
        errors=errors,
    )
