"""Storage-backed Integration Run v2 metadata store skeleton."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.connector_runs import sanitize_error_message
from flocks.security.integrations.integration_runs import IntegrationRun, IntegrationRunCreate, IntegrationRunUpdate
from flocks.security.integrations.runtime import SENSITIVE_PARAM_KEYWORDS
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

INTEGRATION_RUN_PREFIX = "security/integration_runs/"
INTEGRATION_RUN_STORAGE_TYPE = "security.integration_runs"
_SECRET_VALUE_HINTS = ("api_key=", "apikey=", "secret=", "token=", "password=", "authorization:", "bearer ", "cookie:")


class IntegrationRunStore:
    """Persist safe Integration Run summaries without executing runtime behavior."""

    async def create_run(self, payload: IntegrationRunCreate) -> IntegrationRun:
        errors = validate_integration_run_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        now = utc_now()
        run = IntegrationRun(
            integration_run_id=f"intrun_{uuid4().hex}",
            package_id=payload.package_id,
            capability=payload.capability,
            instance_id=payload.instance_id,
            sync_profile_id=payload.sync_profile_id,
            connector_run_id=payload.connector_run_id,
            status=payload.status,
            trigger=payload.trigger,
            started_at=now,
            requested_by=payload.requested_by,
            request_summary=dict(payload.request_summary),
            created_at=now,
            updated_at=now,
            metadata=dict(payload.metadata),
        )
        await Storage.set(_run_key(run.integration_run_id), run, INTEGRATION_RUN_STORAGE_TYPE)
        return run

    async def get_run(self, run_id: str) -> IntegrationRun | None:
        return await Storage.get(_run_key(run_id), IntegrationRun)

    async def list_runs(self, package_id: str | None = None, status: str | None = None) -> list[IntegrationRun]:
        entries = await Storage.list_entries(INTEGRATION_RUN_PREFIX, IntegrationRun)
        runs = [value for _, value in entries]
        if package_id is not None:
            runs = [run for run in runs if run.package_id == package_id]
        if status is not None:
            runs = [run for run in runs if run.status == status]
        return sorted(runs, key=lambda run: run.created_at)

    async def update_run(self, run_id: str, payload: IntegrationRunUpdate) -> IntegrationRun | None:
        current = await self.get_run(run_id)
        if current is None:
            return None
        errors = validate_integration_run_payload(payload)
        if errors:
            raise ValueError("; ".join(errors))
        data = current.model_dump(mode="json")
        updates = payload.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        for key in {"status", "finished_at", "result_summary", "error_message", "item_refs", "metadata"}:
            if key in updates:
                data[key] = sanitize_error_message(updates[key]) if key == "error_message" else updates[key]
        data["updated_at"] = utc_now()
        updated = IntegrationRun(**data)
        await Storage.set(_run_key(run_id), updated, INTEGRATION_RUN_STORAGE_TYPE)
        return updated

    async def delete_run(self, run_id: str) -> bool:
        return await Storage.delete(_run_key(run_id))


async def record_integration_run(payload: IntegrationRunCreate) -> IntegrationRun:
    """Record a pending Integration Run summary without executing it."""

    return await default_integration_run_store.create_run(payload)


async def finish_integration_run(
    run_id: str,
    *,
    status: str = "success",
    result_summary: dict[str, Any] | None = None,
    error_message: str | None = None,
    item_refs: list[dict[str, Any]] | None = None,
) -> IntegrationRun | None:
    """Mark an Integration Run complete without creating Security objects."""

    return await default_integration_run_store.update_run(
        run_id,
        IntegrationRunUpdate(
            status=status,
            finished_at=utc_now(),
            result_summary=result_summary,
            error_message=error_message,
            item_refs=item_refs,
        ),
    )


def validate_integration_run_payload(payload: IntegrationRunCreate | IntegrationRunUpdate) -> list[str]:
    errors: list[str] = []
    for attr in ("request_summary", "result_summary", "metadata"):
        value = getattr(payload, attr, None)
        if value is not None:
            errors.extend(_validate_safe_metadata(attr, value))
    error_message = getattr(payload, "error_message", None)
    if error_message is not None and any(hint in error_message.lower() for hint in _SECRET_VALUE_HINTS):
        errors.append("error_message contains an obvious secret-like value")
    return errors


def _validate_safe_metadata(label: str, metadata: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if any(keyword in lowered for keyword in SENSITIVE_PARAM_KEYWORDS):
                    errors.append(f"{label} contains secret-like key: {path}{key}")
                visit(item, f"{path}{key}.")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}{index}.")
        elif isinstance(value, str) and any(hint in value.lower() for hint in _SECRET_VALUE_HINTS):
            errors.append(f"{label} contains obvious secret-like value: {path.rstrip('.') or label}")

    visit(metadata, "")
    return errors


def _run_key(run_id: str) -> str:
    return f"{INTEGRATION_RUN_PREFIX}{run_id}"


default_integration_run_store = IntegrationRunStore()
