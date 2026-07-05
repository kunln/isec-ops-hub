"""Outbound connectivity configuration helpers."""

from flocks.commercial.models import ConnectivityConfig, ConnectivityUpdate
from flocks.commercial.store import default_store


async def get_connectivity() -> ConnectivityConfig:
    return await default_store.get_connectivity()


async def update_connectivity(payload: ConnectivityUpdate) -> ConnectivityConfig:
    return await default_store.update_connectivity(payload)
