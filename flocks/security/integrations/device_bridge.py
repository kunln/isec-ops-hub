"""Device Integration to Integration Runtime v2 reference bridge.

The bridge belongs to the Integration Layer. It links existing product access
metadata to Runtime v2 Instance and Credential Profile references only. It does
not read Device Integration fields, resolve credentials, call vendor APIs or
adapters, execute sync, write runs, dispatch evidence, or create Security
objects.
"""

from __future__ import annotations

import asyncio
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
from flocks.security.integrations.instances import IntegrationInstance, IntegrationInstanceCreate
from flocks.security.integrations.registry import IntegrationRegistry, create_default_integration_registry
from flocks.tool.device.store import DeviceIntegrationIdentity, get_device_identity, list_device_identities

BRIDGE_SOURCE = "device_integration_bridge"
BRIDGE_VERSION = "v1"
DEVICE_CREDENTIAL_REFERENCE_SCHEME = "device-integration"

BridgeResultStatus = Literal[
    "planned",
    "bridged",
    "already_bridged",
    "unsupported",
    "not_found",
    "validation_failed",
    "unsafe",
]
BridgeState = Literal["unlinked", "linked", "unsupported", "unknown"]

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
_COMMON_LIMITATIONS = (
    "Bridge skeleton does not create a Sync Profile.",
    "No synchronization, preview, confirm ingest, or vendor request is performed.",
    "Credential linkage is reference-only; credential values are not read or copied.",
    "The force flag is reserved and does not change bridge behavior in this skeleton.",
)


class _DeviceBridgeBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class DeviceBridgeRequest(_DeviceBridgeBaseModel):
    device_id: str
    requested_by: str | None = None
    dry_run: bool = True
    force: bool = False


class DeviceBridgeResult(_DeviceBridgeBaseModel):
    status: BridgeResultStatus
    device_id: str
    device_name: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    credential_profile_id: str | None = None
    supported_capabilities: list[str] = Field(default_factory=list)
    bridge_summary: dict[str, Any] = Field(default_factory=dict)
    safety_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DeviceBridgeStatus(_DeviceBridgeBaseModel):
    device_id: str
    device_name: str | None = None
    bridge_state: BridgeState
    package_id: str | None = None
    instance_id: str | None = None
    credential_profile_id: str | None = None
    supported_capabilities: list[str] = Field(default_factory=list)
    message: str
    limitations: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class DevicePackageMapping:
    identifiers: frozenset[str]
    package_id: str
    supported_capabilities: tuple[str, ...]


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
        supported_capabilities=("alert.search",),
    ),
)


class DeviceIntegrationBridge:
    """Create idempotent Runtime v2 references for supported devices."""

    def __init__(
        self,
        *,
        registry: IntegrationRegistry | None = None,
        instance_store: PersistentIntegrationInstanceStore | None = None,
        credential_store: CredentialProfileStore | None = None,
    ) -> None:
        self.registry = registry or create_default_integration_registry()
        self.instance_store = instance_store or default_integration_instance_store
        self.credential_store = credential_store or default_credential_profile_store
        self._confirm_lock = asyncio.Lock()

    async def bridge_device_integration(self, request: DeviceBridgeRequest) -> DeviceBridgeResult:
        """Plan or create safe Runtime references without executing integration work."""

        device_id = request.device_id.strip()
        if not _SAFE_REFERENCE_PATTERN.fullmatch(device_id):
            return self._result(
                status="validation_failed",
                device_id="[invalid-device-id]",
                errors=["device_id must be a non-empty safe reference"],
                action="none",
                dry_run=request.dry_run,
            )

        device = await get_device_identity(device_id)
        if device is None:
            return self._result(
                status="not_found",
                device_id=device_id,
                errors=["Device Integration not found"],
                action="none",
                dry_run=request.dry_run,
            )

        mapping, mapping_error = self._resolve_mapping(device)
        existing = await self._find_instance(device_id)
        if existing is not None:
            return self._result_for_device(
                status="already_bridged",
                device=device,
                mapping=mapping,
                instance=existing,
                action="reuse_runtime_references",
                dry_run=request.dry_run,
            )
        if mapping is None:
            return self._result_for_device(
                status="unsupported",
                device=device,
                mapping=None,
                action="none",
                dry_run=request.dry_run,
                errors=[mapping_error or "No Integration Package mapping is available"],
            )

        if request.dry_run:
            return self._result_for_device(
                status="planned",
                device=device,
                mapping=mapping,
                action="create_runtime_references",
                dry_run=True,
            )

        async with self._confirm_lock:
            existing = await self._find_instance(device_id)
            if existing is not None:
                return self._result_for_device(
                    status="already_bridged",
                    device=device,
                    mapping=mapping,
                    instance=existing,
                    action="reuse_runtime_references",
                    dry_run=False,
                )
            return await self._create_references(device, mapping)

    async def list_status(self, device_id: str | None = None) -> list[DeviceBridgeStatus]:
        """Return linkage state without reading Device Integration fields."""

        requested_id = device_id.strip() if device_id is not None else None
        if device_id is not None and not _SAFE_REFERENCE_PATTERN.fullmatch(requested_id or ""):
            return [self._unknown_status("[invalid-device-id]", "device_id is not a safe reference")]

        if requested_id is None:
            devices = await list_device_identities()
        else:
            device = await get_device_identity(requested_id)
            devices = [device] if device is not None else []
        if requested_id is not None and not devices:
            return [self._unknown_status(requested_id, "Device Integration not found")]

        instances = await self.instance_store.list_instances()
        by_device_id = {
            str(instance.metadata.get("device_id")): instance
            for instance in instances
            if instance.metadata.get("source") == BRIDGE_SOURCE and instance.metadata.get("device_id")
        }
        return [self._status_for_device(device, by_device_id.get(str(device["id"]))) for device in devices]

    async def _create_references(
        self, device: DeviceIntegrationIdentity, mapping: DevicePackageMapping
    ) -> DeviceBridgeResult:
        created_profile = False
        instance: IntegrationInstance | None = None
        profile = await self._find_credential_profile(str(device["id"]), mapping.package_id)
        try:
            if profile is None:
                profile = await self.credential_store.create_profile(
                    CredentialProfileCreate(
                        display_name=f"{_safe_display_name(device['name'])} credential reference",
                        profile_type="device_integration_reference",
                        package_id=mapping.package_id,
                        secret_ref=f"{DEVICE_CREDENTIAL_REFERENCE_SCHEME}://{device['id']}",
                        metadata={
                            "source": "device_integration",
                            "device_id": str(device["id"]),
                            "bridge_version": BRIDGE_VERSION,
                            "reference_scope": "existing_device_credentials",
                        },
                    )
                )
                created_profile = True

            instance = await self.instance_store.create_instance(
                IntegrationInstanceCreate(
                    package_id=mapping.package_id,
                    display_name=_safe_display_name(device["name"]),
                    credential_profile_id=profile.credential_profile_id,
                    verify_ssl=bool(device["verify_ssl"]),
                    enabled=bool(device["enabled"]),
                    metadata={
                        "source": BRIDGE_SOURCE,
                        "device_id": str(device["id"]),
                        "device_name": _safe_display_name(device["name"]),
                        "device_storage_key": str(device["storage_key"]),
                        "device_service_id": str(device["service_id"]),
                        "package_id": mapping.package_id,
                        "bridge_version": BRIDGE_VERSION,
                    },
                )
            )
            updated_profile = await self.credential_store.update_profile(
                profile.credential_profile_id,
                CredentialProfileUpdate(instance_id=instance.instance_id),
            )
            if updated_profile is None:
                raise RuntimeError("Credential Profile reference disappeared during bridge creation")
        except Exception:
            if instance is not None:
                await self.instance_store.delete_instance(instance.instance_id)
            if created_profile and profile is not None:
                await self.credential_store.delete_profile(profile.credential_profile_id)
            return self._result_for_device(
                status="validation_failed",
                device=device,
                mapping=mapping,
                action="none",
                dry_run=False,
                errors=["Runtime reference creation failed safe validation"],
            )

        return self._result_for_device(
            status="bridged",
            device=device,
            mapping=mapping,
            instance=instance,
            action="created_runtime_references",
            dry_run=False,
        )

    async def _find_instance(self, device_id: str) -> IntegrationInstance | None:
        for instance in await self.instance_store.list_instances():
            if (
                instance.metadata.get("source") == BRIDGE_SOURCE
                and str(instance.metadata.get("device_id")) == device_id
            ):
                return instance
        return None

    async def _find_credential_profile(self, device_id: str, package_id: str) -> CredentialProfile | None:
        for profile in await self.credential_store.list_profiles(package_id=package_id):
            if (
                profile.metadata.get("source") == "device_integration"
                and str(profile.metadata.get("device_id")) == device_id
            ):
                return profile
        return None

    def _resolve_mapping(self, device: DeviceIntegrationIdentity) -> tuple[DevicePackageMapping | None, str | None]:
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
        missing = [
            capability for capability in mapping.supported_capabilities if capability not in package.capabilities
        ]
        if missing:
            return None, "Mapped Integration Package does not declare the required capability"
        return mapping, None

    def _result_for_device(
        self,
        *,
        status: BridgeResultStatus,
        device: DeviceIntegrationIdentity,
        mapping: DevicePackageMapping | None,
        action: str,
        dry_run: bool,
        instance: IntegrationInstance | None = None,
        errors: list[str] | None = None,
    ) -> DeviceBridgeResult:
        return self._result(
            status=status,
            device_id=str(device["id"]),
            device_name=_safe_display_name(device["name"]),
            package_id=instance.package_id if instance is not None else (mapping.package_id if mapping else None),
            instance_id=instance.instance_id if instance is not None else None,
            credential_profile_id=instance.credential_profile_id if instance is not None else None,
            supported_capabilities=list(mapping.supported_capabilities) if mapping else [],
            action=action,
            dry_run=dry_run,
            device_status=str(device["status"] or "unknown"),
            errors=errors,
        )

    def _result(
        self,
        *,
        status: BridgeResultStatus,
        device_id: str,
        action: str,
        dry_run: bool,
        device_name: str | None = None,
        package_id: str | None = None,
        instance_id: str | None = None,
        credential_profile_id: str | None = None,
        supported_capabilities: list[str] | None = None,
        device_status: str | None = None,
        errors: list[str] | None = None,
    ) -> DeviceBridgeResult:
        return DeviceBridgeResult(
            status=status,
            device_id=device_id,
            device_name=device_name,
            package_id=package_id,
            instance_id=instance_id,
            credential_profile_id=credential_profile_id,
            supported_capabilities=supported_capabilities or [],
            bridge_summary={
                "source": BRIDGE_SOURCE,
                "bridge_version": BRIDGE_VERSION,
                "action": action,
                "device_status": device_status,
                "force_applied": False,
            },
            safety_summary={
                "dry_run": dry_run,
                "credential_linkage": "reference_only",
                "vendor_call": False,
                "adapter_call": False,
                "sync_execution": False,
                "evidence_dispatch": False,
                "security_objects_created": False,
                "plaintext_credentials_read_or_copied": False,
            },
            limitations=list(_COMMON_LIMITATIONS),
            errors=errors or [],
        )

    def _status_for_device(
        self, device: DeviceIntegrationIdentity, instance: IntegrationInstance | None
    ) -> DeviceBridgeStatus:
        mapping, mapping_error = self._resolve_mapping(device)
        if instance is not None:
            return DeviceBridgeStatus(
                device_id=str(device["id"]),
                device_name=_safe_display_name(device["name"]),
                bridge_state="linked",
                package_id=instance.package_id,
                instance_id=instance.instance_id,
                credential_profile_id=instance.credential_profile_id,
                supported_capabilities=list(mapping.supported_capabilities) if mapping else [],
                message="Device Integration is linked to a Runtime v2 Integration Instance.",
                limitations=list(_COMMON_LIMITATIONS),
            )
        if mapping is None:
            return DeviceBridgeStatus(
                device_id=str(device["id"]),
                device_name=_safe_display_name(device["name"]),
                bridge_state="unsupported",
                message=mapping_error or "No Integration Package mapping is available.",
                limitations=list(_COMMON_LIMITATIONS),
            )
        return DeviceBridgeStatus(
            device_id=str(device["id"]),
            device_name=_safe_display_name(device["name"]),
            bridge_state="unlinked",
            package_id=mapping.package_id,
            supported_capabilities=list(mapping.supported_capabilities),
            message="Device Integration can be linked to a Runtime v2 Integration Instance.",
            limitations=list(_COMMON_LIMITATIONS),
        )

    def _unknown_status(self, device_id: str, message: str) -> DeviceBridgeStatus:
        return DeviceBridgeStatus(
            device_id=device_id,
            bridge_state="unknown",
            message=message,
            limitations=list(_COMMON_LIMITATIONS),
        )


def _safe_display_name(value: Any) -> str:
    text = str(value or "Device Integration").strip() or "Device Integration"
    if any(hint in text.lower() for hint in _UNSAFE_TEXT_HINTS):
        return "[REDACTED DEVICE NAME]"
    return text[:256]


default_device_integration_bridge = DeviceIntegrationBridge()
