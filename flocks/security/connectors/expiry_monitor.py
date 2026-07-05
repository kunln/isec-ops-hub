"""Periodic credential expiry monitor for connector profiles."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flocks.security.connectors.operations import (
    get_connector_operations_settings,
    mark_expiry_monitor_run,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class ConnectorCredentialExpiryMonitorScheduler:
    """In-process periodic worker for credential expiry pre-warning scans."""

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._poll_interval = 60
        self._operations_registry_path: Path | None = None
        self._last_tick: dict[str, Any] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self, *, poll_interval: int = 60, operations_registry_path: Path | None = None) -> None:
        if self.running:
            return
        self._poll_interval = max(5, int(poll_interval))
        self._operations_registry_path = operations_registry_path
        self._task = asyncio.create_task(self._loop(), name="connector-credential-expiry-monitor")

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def tick(self, *, force: bool = False) -> dict[str, Any]:
        settings = get_connector_operations_settings(self._operations_registry_path)["expiry_monitor"]
        due = force or self._is_due(settings)
        result: dict[str, Any] = {
            "checked_at": utc_now(),
            "enabled": bool(settings.get("enabled", True)),
            "due": due,
            "ran": False,
            "settings": settings,
            "result": None,
        }
        if not settings.get("enabled", True) or not due:
            self._last_tick = result
            return result

        from flocks.security.connectors.registry import connector_registry

        monitor_result = connector_registry.monitor_credential_expiry(
            days=int(settings.get("days") or 14),
            notify=bool(settings.get("notify", True)),
            actor={"type": "system", "id": "expiry-monitor", "username": "expiry-monitor", "role": "system"},
        )
        mark_expiry_monitor_run(monitor_result, path=self._operations_registry_path)
        result["ran"] = True
        result["result"] = monitor_result
        self._last_tick = result
        return result

    def status(self) -> dict[str, Any]:
        settings = get_connector_operations_settings(self._operations_registry_path)["expiry_monitor"]
        return {
            "running": self.running,
            "poll_interval_seconds": self._poll_interval,
            "settings": settings,
            "last_tick": self._last_tick,
        }

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
                pass
            await asyncio.sleep(self._poll_interval)

    @staticmethod
    def _is_due(settings: dict[str, Any]) -> bool:
        next_run_at = _parse_datetime(settings.get("next_run_at"))
        last_run_at = _parse_datetime(settings.get("last_run_at"))
        now = datetime.now(UTC)
        if next_run_at is not None:
            return next_run_at <= now
        if last_run_at is None:
            return True
        interval = max(60, int(settings.get("interval_seconds") or 86400))
        return (now - last_run_at).total_seconds() >= interval


connector_credential_expiry_monitor_scheduler = ConnectorCredentialExpiryMonitorScheduler()
