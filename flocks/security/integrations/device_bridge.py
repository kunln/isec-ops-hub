"""Device Integration to Integration Runtime v2 metadata bridge.

The bridge belongs to the Integration Layer. It creates only an Integration
Instance, a reference-only Credential Profile, and one manual Sync Profile. It
does not read Device Integration credential fields, resolve credentials, call
vendor APIs or adapters, execute sync, write runs, dispatch evidence, or create
Security objects.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.credential_store import (
    CredentialProfileStore,
    default_credential_profile_store,
)
from flocks.security.integrations.credentials import (
    CredentialProfile,
    CredentialProfileCreate,
    CredentialProfileUpdate,
)
from flocks.security.integrations.instance_store import (
    PersistentIntegrationInstanceStore,
    default_integration_instance_store,
)
from flocks.security.integrations.instances import (
    IntegrationInstance,
    IntegrationInstanceCreate,
    IntegrationInstanceUpdate,
)
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.security.integrations.sync_profile_store import SyncProfileStore, default_sync_profile_store
from flocks.security.integrations.sync_profiles import SyncProfile, SyncProfileCreate
from flocks.tool.device.store import DeviceIntegrationIdentity, get_device_identity

BRIDGE_SOURCE = "device_integration_bridge"
BRIDGE_VERSION = "v2-skeleton-1"
DEVICE_CREDENTIAL_REFERENCE_SCHEME = "device-integration"
SUPPORTED_CAPABILITY = "alert.search"

BridgeResultStatus = Literal["created", "reused", "validation_failed", "not_found"]

_SAFE_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
_UNSAFE_TEXT_HINTS = (
    "api_key=",
    "apikey=",
    "secret=",
    "token=",
    "password=",
    "authorization:",
    "bearer ",
    "x-api-key",
)


class _DeviceBridgeBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class DeviceBridgeRequest(_DeviceBridgeBaseModel):
    device_integration_id: str
    capability: str = SUPPORTED_CAPABILITY
    requested_by: str | None = None


class DeviceBridgeResult(_DeviceBridgeBaseModel):
    status: BridgeResultStatus
    device_integration_id: str
    instance_id: str | None = None
    credential_profile_id: str | None = None
    sync_profile_id: str | None = None
    capability: str
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class DevicePackageMapping:
    identifiers: frozenset[str]
    package_id: str
    capabilities: tuple[str, ...]
    required_credential_fields: tuple[str, ...]


DEVICE_PACKAGE_MAPPINGS = (
    DevicePackageMapping(
        identifiers=frozenset(
            {
                "asiainfo_tda_api",
                "asiainfo_tda_api_v7_0",
                "asiainfo_xinwei_tda_v7_0",
                "asiainfo-tda-v7-0",
            }
        ),
        package_id="asiainfo.tda",
        capabilities=(SUPPORTED_CAPABILITY,),
        required_credential_fields=("api_key", "secret"),
    ),
)


class DeviceIntegrationBridge:
    """Create or reuse the three safe Runtime v2 metadata objects."""

    def __init__(
        self,
        *,
        registry: IntegrationRegistry | None = None,
        instance_store: PersistentIntegrationInstanceStore | None = None,
        credential_store: CredentialProfileStore | None = None,
        sync_profile_store: SyncProfileStore | None = None,
    ) -> None:
        self.registry = registry or create_default_integration_registry()
        self.instance_store = instance_store or default_integration_instance_store
        self.credential_store = credential_store or default_credential_profile_store
        self.sync_profile_store = sync_profile_store or default_sync_profile_store
        self._bridge_lock = asyncio.Lock()

    async def bridge_device_integration(self, request: DeviceBridgeRequest) -> DeviceBridgeResult:
        """Create or reuse reference-only Runtime metadata without executing it."""

        device_integration_id = request.device_integration_id.strip()
        capability = request.capability.strip()
        if not _SAFE_REFERENCE_PATTERN.fullmatch(device_integration_id):
            return self._result(
                status="validation_failed",
                device_integration_id="[invalid-device-integration-id]",
                capability=capability or SUPPORTED_CAPABILITY,
                errors=["device_integration_id must be a non-empty safe reference"],
            )
        if capability != SUPPORTED_CAPABILITY:
            return self._result(
                status="validation_failed",
                device_integration_id=device_integration_id,
                capability=capability or "[invalid-capability]",
                errors=[f"Only {SUPPORTED_CAPABILITY} is supported by this bridge skeleton"],
            )

        device = await get_device_identity(device_integration_id)
        if device is None:
            return self._result(
                status="not_found",
                device_integration_id=device_integration_id,
                capability=capability,
                errors=["Device Integration not found"],
            )

        mapping, mapping_error = self._resolve_mapping(device, capability)
        if mapping is None:
            return self._result(
                status="validation_failed",
                device_integration_id=device_integration_id,
                capability=capability,
                errors=[mapping_error or "No Integration Package mapping is available for this product"],
            )

        async with self._bridge_lock:
            return await self._create_or_reuse_metadata(device, mapping, capability)

    async def _create_or_reuse_metadata(
        self,
        device: DeviceIntegrationIdentity,
        mapping: DevicePackageMapping,
        capability: str,
    ) -> DeviceBridgeResult:
        device_integration_id = str(device["id"])
        expected_secret_ref = f"{DEVICE_CREDENTIAL_REFERENCE_SCHEME}:{device_integration_id}"
        created_profile = False
        created_instance = False
        created_sync_profile = False
        profile: CredentialProfile | None = None
        instance: IntegrationInstance | None = None
        sync_profile: SyncProfile | None = None

        try:
            instance = await self._find_instance(device_integration_id)
            if instance is not None and instance.package_id != mapping.package_id:
                raise ValueError("Existing bridged Integration Instance has a different package_id")

            profile = await self._resolve_existing_profile(
                device_integration_id=device_integration_id,
                package_id=mapping.package_id,
                instance=instance,
            )
            if profile is not None:
                if profile.package_id not in {None, mapping.package_id}:
                    raise ValueError("Existing bridged Credential Profile has a different package_id")
                compatible_refs = {
                    expected_secret_ref,
                    f"{DEVICE_CREDENTIAL_REFERENCE_SCHEME}://{device_integration_id}",
                }
                if profile.secret_ref not in compatible_refs:
                    raise ValueError("Existing bridged Credential Profile has an incompatible secret_ref")
            else:
                profile = await self.credential_store.create_profile(
                    CredentialProfileCreate(
                        display_name=f"{_safe_display_name(device['name'])} Credential Reference",
                        profile_type="device_integration_reference",
                        package_id=mapping.package_id,
                        secret_ref=expected_secret_ref,
                        required_fields=list(mapping.required_credential_fields),
                        configured_fields=[],
                        metadata=_bridge_metadata(device_integration_id),
                    )
                )
                created_profile = True

            if instance is None:
                instance = await self.instance_store.create_instance(
                    IntegrationInstanceCreate(
                        package_id=mapping.package_id,
                        display_name=_safe_display_name(device["name"]),
                        base_url=None,
                        credential_profile_id=profile.credential_profile_id,
                        verify_ssl=bool(device["verify_ssl"]),
                        enabled=bool(device["enabled"]),
                        metadata={
                            **_bridge_metadata(device_integration_id),
                            "device_storage_key": str(device["storage_key"]),
                            "device_service_id": str(device["service_id"]),
                            "base_url_summary": "managed_by_device_integration",
                        },
                    )
                )
                created_instance = True
            elif instance.credential_profile_id not in {None, profile.credential_profile_id}:
                raise ValueError("Existing bridged Integration Instance references a different Credential Profile")

            if profile.instance_id not in {None, instance.instance_id}:
                raise ValueError("Existing bridged Credential Profile references a different Integration Instance")

            sync_profile = await self._find_sync_profile(instance.instance_id, capability)
            if sync_profile is None:
                sync_profile = await self.sync_profile_store.create_profile(
                    SyncProfileCreate(
                        display_name=f"{_safe_display_name(device['name'])} 告警同步",
                        instance_id=instance.instance_id,
                        capability=capability,
                        mode="manual",
                        schedule="manual",
                        enabled=True,
                        params={"time_range": "last_24h", "page_size": 100},
                        deduplicate=True,
                        create_analysis_cases=False,
                        run_initial_analysis=False,
                        metadata=_bridge_metadata(device_integration_id),
                    )
                )
                created_sync_profile = True

            if instance.credential_profile_id is None:
                updated_instance = await self.instance_store.update_instance(
                    instance.instance_id,
                    IntegrationInstanceUpdate(credential_profile_id=profile.credential_profile_id),
                )
                if updated_instance is None:
                    raise RuntimeError("Integration Instance disappeared during bridge creation")
                instance = updated_instance

            profile_updates: dict[str, Any] = {}
            if profile.instance_id is None:
                profile_updates["instance_id"] = instance.instance_id
            if profile.secret_ref != expected_secret_ref:
                profile_updates["secret_ref"] = expected_secret_ref
            if profile_updates:
                updated_profile = await self.credential_store.update_profile(
                    profile.credential_profile_id,
                    CredentialProfileUpdate(**profile_updates),
                )
                if updated_profile is None:
                    raise RuntimeError("Credential Profile disappeared during bridge creation")
                profile = updated_profile
        except Exception:
            if created_sync_profile and sync_profile is not None:
                with suppress(Exception):
                    await self.sync_profile_store.delete_profile(sync_profile.sync_profile_id)
            if created_instance and instance is not None:
                with suppress(Exception):
                    await self.instance_store.delete_instance(instance.instance_id)
            if created_profile and profile is not None:
                with suppress(Exception):
                    await self.credential_store.delete_profile(profile.credential_profile_id)
            return self._result(
                status="validation_failed",
                device_integration_id=device_integration_id,
                capability=capability,
                errors=["Runtime v2 bridge metadata could not be created safely"],
            )

        warnings: list[str] = []
        if not bool(device["enabled"]):
            warnings.append("Device Integration is disabled; the Integration Instance remains disabled")
        if str(device["status"] or "unknown") != "ok":
            warnings.append("Device Integration is not in a healthy state; no connection test was run")
        created = created_profile or created_instance or created_sync_profile
        return self._result(
            status="created" if created else "reused",
            device_integration_id=device_integration_id,
            capability=capability,
            instance_id=instance.instance_id,
            credential_profile_id=profile.credential_profile_id,
            sync_profile_id=sync_profile.sync_profile_id,
            warnings=warnings,
        )

    async def _find_instance(self, device_integration_id: str) -> IntegrationInstance | None:
        for instance in await self.instance_store.list_instances():
            if (
                instance.metadata.get("source") == BRIDGE_SOURCE
                and _source_device_integration_id(instance.metadata) == device_integration_id
            ):
                return instance
        return None

    async def _resolve_existing_profile(
        self,
        *,
        device_integration_id: str,
        package_id: str,
        instance: IntegrationInstance | None,
    ) -> CredentialProfile | None:
        if instance is not None and instance.credential_profile_id:
            referenced = await self.credential_store.get_profile(instance.credential_profile_id)
            if referenced is None:
                raise ValueError("Existing bridged Integration Instance has a missing Credential Profile")
            return referenced
        for profile in await self.credential_store.list_profiles(package_id=package_id):
            if _source_device_integration_id(profile.metadata) == device_integration_id:
                return profile
        return None

    async def _find_sync_profile(self, instance_id: str, capability: str) -> SyncProfile | None:
        profiles = await self.sync_profile_store.list_profiles(
            instance_id=instance_id,
            capability=capability,
        )
        return profiles[0] if profiles else None

    def _resolve_mapping(
        self,
        device: DeviceIntegrationIdentity,
        capability: str,
    ) -> tuple[DevicePackageMapping | None, str | None]:
        identifiers = {
            str(device["storage_key"]).strip().lower(),
            str(device["service_id"]).strip().lower(),
        }
        mapping = next(
            (item for item in DEVICE_PACKAGE_MAPPINGS if identifiers.intersection(item.identifiers)),
            None,
        )
        if mapping is None:
            return None, "No Integration Package mapping is available for this product"
        package = self.registry.get_package(mapping.package_id)
        if package is None:
            return None, f"Mapped Integration Package is not available: {mapping.package_id}"
        if capability not in mapping.capabilities or capability not in package.capabilities:
            return None, f"Mapped Integration Package does not declare {capability}"
        return mapping, None

    @staticmethod
    def _result(
        *,
        status: BridgeResultStatus,
        device_integration_id: str,
        capability: str,
        instance_id: str | None = None,
        credential_profile_id: str | None = None,
        sync_profile_id: str | None = None,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> DeviceBridgeResult:
        return DeviceBridgeResult(
            status=status,
            device_integration_id=device_integration_id,
            instance_id=instance_id,
            credential_profile_id=credential_profile_id,
            sync_profile_id=sync_profile_id,
            capability=capability,
            warnings=warnings or [],
            errors=errors or [],
        )


def _bridge_metadata(device_integration_id: str) -> dict[str, str]:
    return {
        "source": BRIDGE_SOURCE,
        "bridge_version": BRIDGE_VERSION,
        "source_device_integration_id": device_integration_id,
    }


def _source_device_integration_id(metadata: dict[str, Any]) -> str:
    value = metadata.get("source_device_integration_id", metadata.get("device_id", ""))
    return str(value)


def _safe_display_name(value: Any) -> str:
    text = str(value or "Device Integration").strip() or "Device Integration"
    if any(hint in text.lower() for hint in _UNSAFE_TEXT_HINTS):
        return "[REDACTED DEVICE NAME]"
    return text[:256]


default_device_integration_bridge = DeviceIntegrationBridge()
