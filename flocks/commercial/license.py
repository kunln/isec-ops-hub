"""Local license import helpers.

Phase 1 is deliberately local-only: this module records operator-imported
license material and does not contact a remote license server.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from flocks.commercial import features
from flocks.commercial.models import LicenseImportRequest, LicenseInfo
from flocks.commercial.store import default_store, utc_now


def _manifest_from_key(license_key: str) -> dict[str, Any]:
    text = license_key.strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {}


def _features_from_manifest(manifest: dict[str, Any]) -> list[str]:
    declared = (
        manifest.get("features")
        or manifest.get("feature_flags")
        or manifest.get("featureFlags")
        or manifest.get("entitlements")
        or []
    )
    return features.normalize_license_features(declared)


async def get_license() -> LicenseInfo:
    return await default_store.get_license()


async def import_license(payload: LicenseImportRequest) -> LicenseInfo:
    manifest = dict(payload.manifest or {})
    license_key = (payload.license_key or "").strip()
    if not manifest and license_key:
        manifest = _manifest_from_key(license_key)
    if not manifest and not license_key:
        raise ValueError("license_key or manifest is required")

    key_hash = hashlib.sha256(license_key.encode("utf-8")).hexdigest() if license_key else None
    info = LicenseInfo(
        status=str(manifest.get("status") or "imported"),
        edition=str(manifest.get("edition") or manifest.get("plan") or "commercial"),
        licensed_to=manifest.get("licensed_to") or manifest.get("customer") or manifest.get("company"),
        license_id=manifest.get("license_id") or manifest.get("id") or (key_hash[:16] if key_hash else None),
        expires_at=manifest.get("expires_at") or manifest.get("expires"),
        features=_features_from_manifest(manifest),
        imported_at=utc_now(),
        source=str(manifest.get("source") or "local_import"),
        license_key_hash=key_hash,
        license_key_tail=license_key[-6:] if license_key else None,
        message=manifest.get("message"),
    )
    saved = await default_store.set_license(info)
    await features.reconcile_configs_for_license(saved)
    return saved
