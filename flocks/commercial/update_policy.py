"""Commercial update-policy helpers."""

from flocks.commercial.models import UpdatePolicy, UpdatePolicyUpdate
from flocks.commercial.store import default_store


async def get_update_policy() -> UpdatePolicy:
    return await default_store.get_update_policy()


async def update_update_policy(payload: UpdatePolicyUpdate) -> UpdatePolicy:
    return await default_store.update_update_policy(payload)
