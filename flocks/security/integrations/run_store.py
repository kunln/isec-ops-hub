"""Storage-backed Integration Run v2 history store."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from flocks.security.integrations.runs import IntegrationRun, IntegrationRunCreate, IntegrationRunUpdate
from flocks.security.store import utc_now
from flocks.storage.storage import Storage

INTEGRATION_RUN_PREFIX = "security/integration_runs/"
INTEGRATION_RUN_STORAGE_TYPE = "security.integration_runs"


class IntegrationRunStore:
    """Persistent Integration Run metadata store; never executes integrations."""

    async def create_run(self, payload: IntegrationRunCreate) -> IntegrationRun:
        now = utc_now()
        data = payload.model_dump(mode="json")
        run = IntegrationRun(
            run_id=f"intrun_{uuid4().hex}",
            started_at=now,
            created_at=now,
            updated_at=now,
            **data,
        )
        await Storage.set(_run_key(run.run_id), run, INTEGRATION_RUN_STORAGE_TYPE)
        return run

    async def get_run(self, run_id: str) -> IntegrationRun | None:
        return await Storage.get(_run_key(run_id), IntegrationRun)

    async def list_runs(
        self,
        package_id: str | None = None,
        instance_id: str | None = None,
        sync_profile_id: str | None = None,
        capability: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[IntegrationRun]:
        entries = await Storage.list_entries(INTEGRATION_RUN_PREFIX, IntegrationRun)
        runs = [value for _, value in entries]
        runs = _filter_runs(runs, package_id, instance_id, sync_profile_id, capability, status)
        runs.sort(key=lambda run: run.started_at or run.created_at or run.updated_at, reverse=True)
        return runs[: max(1, limit)]

    async def update_run(self, run_id: str, payload: IntegrationRunUpdate) -> IntegrationRun | None:
        current = await self.get_run(run_id)
        if current is None:
            return None
        data = current.model_dump(mode="json")
        updates = payload.model_dump(mode="json", exclude_unset=True)
        for key, value in updates.items():
            data[key] = value
        data["updated_at"] = utc_now()
        run = IntegrationRun(**data)
        await Storage.set(_run_key(run_id), run, INTEGRATION_RUN_STORAGE_TYPE)
        return run

    async def delete_run(self, run_id: str) -> bool:
        return await Storage.delete(_run_key(run_id))


def _run_key(run_id: str) -> str:
    return f"{INTEGRATION_RUN_PREFIX}{run_id}"


def _filter_runs(
    runs: list[IntegrationRun],
    package_id: str | None,
    instance_id: str | None,
    sync_profile_id: str | None,
    capability: str | None,
    status: str | None,
) -> list[IntegrationRun]:
    if package_id is not None:
        runs = [run for run in runs if run.package_id == package_id]
    if instance_id is not None:
        runs = [run for run in runs if run.instance_id == instance_id]
    if sync_profile_id is not None:
        runs = [run for run in runs if run.sync_profile_id == sync_profile_id]
    if capability is not None:
        runs = [run for run in runs if run.capability == capability]
    if status is not None:
        runs = [run for run in runs if run.status == status]
    return runs


async def record_integration_run(payload: IntegrationRunCreate) -> IntegrationRun:
    return await default_integration_run_store.create_run(payload)


async def finish_integration_run(
    run_id: str,
    status: str,
    result_summary: dict[str, Any] | None = None,
    error_message: str | None = None,
    item_refs: list[dict[str, Any]] | None = None,
) -> IntegrationRun | None:
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


default_integration_run_store = IntegrationRunStore()
