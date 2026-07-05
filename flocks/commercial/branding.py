"""Branding configuration helpers."""

from flocks.commercial.models import CommercialBranding, CommercialBrandingUpdate
from flocks.commercial.store import default_store


async def get_branding() -> CommercialBranding:
    return await default_store.get_branding()


async def update_branding(payload: CommercialBrandingUpdate) -> CommercialBranding:
    return await default_store.update_branding(payload)
