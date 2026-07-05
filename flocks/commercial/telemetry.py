"""Telemetry configuration helpers."""

from flocks.commercial.models import TelemetryConfig, TelemetryUpdate
from flocks.commercial.store import default_store


async def get_telemetry() -> TelemetryConfig:
    return await default_store.get_telemetry()


async def update_telemetry(payload: TelemetryUpdate) -> TelemetryConfig:
    return await default_store.update_telemetry(payload)
