"""Create Runtime v2 Sync Profile metadata from a bridged product.

This Integration Layer service only resolves the safe Device Integration
bridge projection and writes Sync Profile metadata. It does not read Device
Integration fields or credentials, auto-bridge devices, execute sync, call
connectors or adapters, create Integration Runs, dispatch evidence, or create
Security objects.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from flocks.security.integrations.device_bridge import (
    BRIDGE_SOURCE,
    BRIDGE_VERSION,
    DeviceBridgeStatus,
    DeviceIntegrationBridge,
    default_device_integration_bridge,
)
from flocks.security.integrations.instance_store import (
    PersistentIntegrationInstanceStore,
    default_integration_instance_store,
)
from flocks.security.integrations.instances import IntegrationInstance
from flocks.security.integrations.runtime import SECRET_LIKE_VALUE_HINTS, SENSITIVE_PARAM_KEYWORDS
from flocks.security.integrations.sync_profile_store import SyncProfileStore, default_sync_profile_store
from flocks.security.integrations.sync_profiles import SyncProfile, SyncProfileCreate

DEVICE_SYNC_PROFILE_SOURCE = "device_sync_profile"

DeviceSyncProfileResultStatus = Literal[
    "planned",
    "created",
    "already_exists",
    "not_found",
    "bridge_required",
    "unsupported",
    "validation_failed",
    "unsafe",
]
DeviceSyncProfileStatusValue = Literal["ready", "not_found", "bridge_required", "unsupported"]

_SAFE_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
_SAFE_CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_SAFE_SECRET_REFERENCE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_SAFE_REFERENCE_KEYS = frozenset({"secret_ref", "credential_profile_id", "has_secret"})
_SENSITIVE_TEXT_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:api[_-]?key|apikey|secret|token|password|authorization|bearer|cookie|"
    r"x-api-key|x-flocks-api-token)(?:[^a-z0-9]|$)"
)
_COMMON_LIMITATIONS = (
    "An existing Device Integration Runtime bridge is required; this operation never auto-bridges.",
    "Only Sync Profile metadata is created; synchronization, preview, and ingest are not executed.",
    "Manual mode is the only enabled mode; schedule requests are retained as intent only and are not started.",
    "No Integration Run, Evidence, Alert, Analysis Case, Incident, Notification, or remediation is created.",
)
_CAPABILITY_LIMITATIONS = (
    "Capability execution is not part of Sync Profile creation.",
    "Vendor requests and Adapter Registry resolution remain outside this operation.",
)


class _DeviceSyncProfileBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class DeviceSyncCapability(_DeviceSyncProfileBaseModel):
    capability: str
    display_name: str
    description: str | None = None
    supported: bool
    default_mode: str = "manual"
    limitations: list[str] = Field(default_factory=list)


class DeviceSyncProfileCreateRequest(_DeviceSyncProfileBaseModel):
    device_id: str
    capability: str = "alert.search"
    requested_by: str | None = None
    dry_run: bool = True
    force: bool = False
    display_name: str | None = None
    mode: str = "manual"
    params: dict[str, Any] = Field(default_factory=dict)
    schedule: dict[str, Any] | None = None


class DeviceSyncProfileConfirmRequest(_DeviceSyncProfileBaseModel):
    device_id: str
    capability: str = "alert.search"
    requested_by: str | None = None
    confirmed: bool = False
    force: bool = False
    display_name: str | None = None
    mode: str = "manual"
    params: dict[str, Any] = Field(default_factory=dict)
    schedule: dict[str, Any] | None = None


class DeviceSyncProfileCreateResult(_DeviceSyncProfileBaseModel):
    status: DeviceSyncProfileResultStatus
    device_id: str
    device_name: str | None = None
    package_id: str | None = None
    instance_id: str | None = None
    credential_profile_id: str | None = None
    sync_profile_id: str | None = None
    capability: str | None = None
    mode: str | None = None
    dry_run: bool
    plan_summary: dict[str, Any] = Field(default_factory=dict)
    safety_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class DeviceSyncProfileSummary(_DeviceSyncProfileBaseModel):
    sync_profile_id: str
    display_name: str
    package_id: str
    instance_id: str
    capability: str
    mode: str
    enabled: bool


class DeviceSyncProfileStatus(_DeviceSyncProfileBaseModel):
    status: DeviceSyncProfileStatusValue
    device_id: str
    device_name: str | None = None
    bridge_state: str
    package_id: str | None = None
    instance_id: str | None = None
    supported_capabilities: list[DeviceSyncCapability] = Field(default_factory=list)
    existing_sync_profiles: list[DeviceSyncProfileSummary] = Field(default_factory=list)
    message: str
    limitations: list[str] = Field(default_factory=list)


class DeviceSyncProfileService:
    """Plan and idempotently create Sync Profile metadata for bridged devices."""

    def __init__(
        self,
        *,
        bridge: DeviceIntegrationBridge | None = None,
        instance_store: PersistentIntegrationInstanceStore | None = None,
        sync_profile_store: SyncProfileStore | None = None,
    ) -> None:
        self.bridge = bridge or default_device_integration_bridge
        self.instance_store = instance_store or default_integration_instance_store
        self.sync_profile_store = sync_profile_store or default_sync_profile_store
        self._confirm_lock = asyncio.Lock()

    async def list_status(self, device_id: str | None = None) -> list[DeviceSyncProfileStatus]:
        """Return bridge readiness, capabilities, and safe existing profile summaries."""

        bridge_statuses = await self.bridge.list_status(device_id=device_id)
        return [await self._status_from_bridge(item) for item in bridge_statuses]

    async def plan(self, request: DeviceSyncProfileCreateRequest) -> DeviceSyncProfileCreateResult:
        """Force a read-only plan regardless of the request dry_run value."""

        return await self._create_or_plan(request, dry_run=True)

    async def confirm(self, request: DeviceSyncProfileConfirmRequest) -> DeviceSyncProfileCreateResult:
        """Create metadata only after the caller has explicitly confirmed."""

        if request.confirmed is not True:
            return self._basic_result(
                status="validation_failed",
                device_id=_safe_result_reference(request.device_id),
                dry_run=True,
                errors=["confirmed=True is required for Sync Profile creation"],
            )
        create_request = DeviceSyncProfileCreateRequest(
            device_id=request.device_id,
            capability=request.capability,
            requested_by=request.requested_by,
            dry_run=False,
            force=request.force,
            display_name=request.display_name,
            mode=request.mode,
            params=request.params,
            schedule=request.schedule,
        )
        async with self._confirm_lock:
            return await self._create_or_plan(create_request, dry_run=False)

    async def _create_or_plan(
        self, request: DeviceSyncProfileCreateRequest, *, dry_run: bool
    ) -> DeviceSyncProfileCreateResult:
        device_id = request.device_id.strip()
        capability = request.capability.strip()
        validation_errors = _validate_request(request, device_id=device_id, capability=capability)
        if validation_errors:
            return self._basic_result(
                status="validation_failed",
                device_id=_safe_result_reference(device_id),
                dry_run=dry_run,
                errors=validation_errors,
            )

        bridge_statuses = await self.bridge.list_status(device_id=device_id)
        bridge_status = bridge_statuses[0]
        if bridge_status.bridge_state == "unknown":
            return self._basic_result(
                status="not_found",
                device_id=device_id,
                dry_run=dry_run,
                errors=["Device Integration not found"],
            )
        if bridge_status.bridge_state == "unsupported":
            return self._result_for_bridge(
                status="unsupported",
                bridge_status=bridge_status,
                capability=capability,
                mode=request.mode,
                dry_run=dry_run,
                errors=["Device Integration has no supported Runtime v2 package mapping"],
            )
        if bridge_status.bridge_state != "linked" or bridge_status.instance_id is None:
            return self._result_for_bridge(
                status="bridge_required",
                bridge_status=bridge_status,
                capability=capability,
                mode=request.mode,
                dry_run=dry_run,
                errors=["Complete the Device Integration Runtime bridge before creating a Sync Profile"],
            )
        if capability not in bridge_status.supported_capabilities:
            return self._result_for_bridge(
                status="unsupported",
                bridge_status=bridge_status,
                capability=capability,
                mode=request.mode,
                dry_run=dry_run,
                errors=["Requested capability is not supported for this connected product"],
            )

        instance = await self.instance_store.get_instance(bridge_status.instance_id)
        if instance is None:
            return self._result_for_bridge(
                status="bridge_required",
                bridge_status=bridge_status,
                capability=capability,
                mode=request.mode,
                dry_run=dry_run,
                errors=["The bridged Runtime v2 Integration Instance is unavailable"],
            )

        device_name = _safe_display_text(bridge_status.device_name, fallback="Device Integration")
        display_name = (
            request.display_name.strip() if request.display_name is not None else f"{device_name} {capability} sync"
        )
        metadata = {
            "source": DEVICE_SYNC_PROFILE_SOURCE,
            "device_id": device_id,
            "device_name": device_name,
            "package_id": instance.package_id,
            "instance_id": instance.instance_id,
            "capability": capability,
            "bridge_source": BRIDGE_SOURCE,
            "bridge_version": str(instance.metadata.get("bridge_version") or BRIDGE_VERSION),
        }
        payload = SyncProfileCreate(
            display_name=display_name,
            instance_id=instance.instance_id,
            capability=capability,
            mode=request.mode,
            enabled=True,
            schedule=None,
            params=dict(request.params),
            metadata=metadata,
        )
        store_errors = await self.sync_profile_store.validate_profile_payload(payload)
        if store_errors:
            return self._result_for_instance(
                status="validation_failed",
                device_id=device_id,
                device_name=device_name,
                instance=instance,
                capability=capability,
                mode=request.mode,
                dry_run=dry_run,
                display_name=display_name,
                param_keys=sorted(str(key) for key in request.params),
                schedule_requested=request.schedule is not None,
                errors=["Sync Profile metadata failed safe validation"],
            )

        existing = await self._find_existing(device_id, instance.instance_id, capability)
        if existing is not None:
            return self._result_for_instance(
                status="already_exists",
                device_id=device_id,
                device_name=device_name,
                instance=instance,
                capability=capability,
                mode=existing.mode,
                dry_run=dry_run,
                display_name=_safe_display_text(existing.display_name, fallback="Sync Profile"),
                param_keys=[],
                schedule_requested=request.schedule is not None,
                sync_profile_id=existing.sync_profile_id,
                action="reuse_sync_profile",
            )

        if dry_run:
            return self._result_for_instance(
                status="planned",
                device_id=device_id,
                device_name=device_name,
                instance=instance,
                capability=capability,
                mode=request.mode,
                dry_run=True,
                display_name=display_name,
                param_keys=sorted(str(key) for key in request.params),
                schedule_requested=request.schedule is not None,
                action="create_sync_profile_metadata",
            )

        try:
            profile = await self.sync_profile_store.create_profile(payload)
        except ValueError:
            return self._result_for_instance(
                status="validation_failed",
                device_id=device_id,
                device_name=device_name,
                instance=instance,
                capability=capability,
                mode=request.mode,
                dry_run=False,
                display_name=display_name,
                param_keys=sorted(str(key) for key in request.params),
                schedule_requested=request.schedule is not None,
                errors=["Sync Profile metadata failed safe validation"],
            )
        return self._result_for_instance(
            status="created",
            device_id=device_id,
            device_name=device_name,
            instance=instance,
            capability=capability,
            mode=profile.mode,
            dry_run=False,
            display_name=profile.display_name,
            param_keys=sorted(str(key) for key in profile.params),
            schedule_requested=request.schedule is not None,
            sync_profile_id=profile.sync_profile_id,
            action="created_sync_profile_metadata",
        )

    async def _find_existing(self, device_id: str, instance_id: str, capability: str) -> SyncProfile | None:
        profiles = await self.sync_profile_store.list_profiles(instance_id=instance_id, capability=capability)
        return next(
            (
                profile
                for profile in profiles
                if profile.metadata.get("source") == DEVICE_SYNC_PROFILE_SOURCE
                and str(profile.metadata.get("device_id")) == device_id
                and str(profile.metadata.get("instance_id")) == instance_id
                and str(profile.metadata.get("capability")) == capability
            ),
            None,
        )

    async def _status_from_bridge(self, bridge_status: DeviceBridgeStatus) -> DeviceSyncProfileStatus:
        device_name = (
            _safe_display_text(bridge_status.device_name, fallback="Device Integration")
            if bridge_status.device_name is not None
            else None
        )
        if bridge_status.bridge_state == "unknown":
            return DeviceSyncProfileStatus(
                status="not_found",
                device_id=_safe_result_reference(bridge_status.device_id),
                device_name=device_name,
                bridge_state=bridge_status.bridge_state,
                message="Device Integration not found.",
                limitations=list(_COMMON_LIMITATIONS),
            )
        capabilities = [_capability(item) for item in bridge_status.supported_capabilities]
        if bridge_status.bridge_state == "unsupported":
            return DeviceSyncProfileStatus(
                status="unsupported",
                device_id=_safe_result_reference(bridge_status.device_id),
                device_name=device_name,
                bridge_state=bridge_status.bridge_state,
                package_id=bridge_status.package_id,
                supported_capabilities=capabilities,
                message="This connected product has no supported Runtime v2 Sync Profile capability.",
                limitations=list(_COMMON_LIMITATIONS),
            )
        if bridge_status.bridge_state != "linked" or bridge_status.instance_id is None:
            return DeviceSyncProfileStatus(
                status="bridge_required",
                device_id=_safe_result_reference(bridge_status.device_id),
                device_name=device_name,
                bridge_state=bridge_status.bridge_state,
                package_id=bridge_status.package_id,
                supported_capabilities=capabilities,
                message="Complete the Device Integration Runtime bridge before creating a Sync Profile.",
                limitations=list(_COMMON_LIMITATIONS),
            )
        profiles = await self.sync_profile_store.list_profiles(instance_id=bridge_status.instance_id)
        return DeviceSyncProfileStatus(
            status="ready",
            device_id=_safe_result_reference(bridge_status.device_id),
            device_name=device_name,
            bridge_state=bridge_status.bridge_state,
            package_id=bridge_status.package_id,
            instance_id=bridge_status.instance_id,
            supported_capabilities=capabilities,
            existing_sync_profiles=[_profile_summary(profile) for profile in profiles],
            message="The connected product is ready for Runtime v2 Sync Profile configuration.",
            limitations=list(_COMMON_LIMITATIONS),
        )

    def _result_for_bridge(
        self,
        *,
        status: DeviceSyncProfileResultStatus,
        bridge_status: DeviceBridgeStatus,
        capability: str,
        mode: str,
        dry_run: bool,
        errors: list[str],
    ) -> DeviceSyncProfileCreateResult:
        return self._basic_result(
            status=status,
            device_id=_safe_result_reference(bridge_status.device_id),
            device_name=(
                _safe_display_text(bridge_status.device_name, fallback="Device Integration")
                if bridge_status.device_name is not None
                else None
            ),
            package_id=bridge_status.package_id,
            instance_id=bridge_status.instance_id,
            capability=capability,
            mode=mode,
            dry_run=dry_run,
            errors=errors,
        )

    def _result_for_instance(
        self,
        *,
        status: DeviceSyncProfileResultStatus,
        device_id: str,
        device_name: str,
        instance: IntegrationInstance,
        capability: str,
        mode: str,
        dry_run: bool,
        display_name: str,
        param_keys: list[str],
        schedule_requested: bool,
        sync_profile_id: str | None = None,
        action: str = "none",
        errors: list[str] | None = None,
    ) -> DeviceSyncProfileCreateResult:
        return self._basic_result(
            status=status,
            device_id=device_id,
            device_name=device_name,
            package_id=instance.package_id,
            instance_id=instance.instance_id,
            credential_profile_id=instance.credential_profile_id,
            sync_profile_id=sync_profile_id,
            capability=capability,
            mode=mode,
            dry_run=dry_run,
            plan_summary={
                "source": DEVICE_SYNC_PROFILE_SOURCE,
                "action": action,
                "display_name": display_name,
                "param_keys": param_keys,
                "enabled": True,
                "schedule_requested": schedule_requested,
                "schedule_applied": False,
                "automatic_scheduling_started": False,
            },
            errors=errors or [],
        )

    def _basic_result(
        self,
        *,
        status: DeviceSyncProfileResultStatus,
        device_id: str,
        dry_run: bool,
        device_name: str | None = None,
        package_id: str | None = None,
        instance_id: str | None = None,
        credential_profile_id: str | None = None,
        sync_profile_id: str | None = None,
        capability: str | None = None,
        mode: str | None = None,
        plan_summary: dict[str, Any] | None = None,
        errors: list[str] | None = None,
    ) -> DeviceSyncProfileCreateResult:
        return DeviceSyncProfileCreateResult(
            status=status,
            device_id=device_id,
            device_name=device_name,
            package_id=package_id,
            instance_id=instance_id,
            credential_profile_id=credential_profile_id,
            sync_profile_id=sync_profile_id,
            capability=capability,
            mode=mode,
            dry_run=dry_run,
            plan_summary=plan_summary or {},
            safety_summary={
                "metadata_only": True,
                "dry_run": dry_run,
                "automatic_bridge": False,
                "credential_values_read_or_copied": False,
                "vendor_call": False,
                "connector_call": False,
                "adapter_call": False,
                "adapter_registry_call": False,
                "sync_execution": False,
                "preview": False,
                "confirm_ingest": False,
                "integration_run_created": False,
                "evidence_dispatch": False,
                "security_objects_created": False,
                "notification_created": False,
                "remediation": False,
            },
            limitations=list(_COMMON_LIMITATIONS),
            errors=errors or [],
        )


def _validate_request(request: DeviceSyncProfileCreateRequest, *, device_id: str, capability: str) -> list[str]:
    errors: list[str] = []
    if not _SAFE_REFERENCE_PATTERN.fullmatch(device_id) or _contains_sensitive_text(device_id):
        errors.append("device_id must be a non-empty safe reference")
    if not _SAFE_CAPABILITY_PATTERN.fullmatch(capability) or _contains_sensitive_text(capability):
        errors.append("capability must be a safe Runtime v2 capability identifier")
    if request.mode != "manual":
        errors.append("mode must be manual; scheduled execution is not enabled")
    if request.display_name is not None:
        display_name = request.display_name.strip()
        if not display_name or len(display_name) > 256 or _contains_sensitive_text(display_name):
            errors.append("display_name failed safe validation")
    if _contains_unsafe_data(request.params) or (
        request.schedule is not None and _contains_unsafe_data(request.schedule)
    ):
        errors.append("params or schedule contains secret-like keys or values")
    return errors


def _contains_unsafe_data(data: dict[str, Any]) -> bool:
    def visit(value: Any, key: str | None = None) -> bool:
        lowered_key = (key or "").lower()
        if lowered_key == "secret_ref":
            return not isinstance(value, str) or not _SAFE_SECRET_REFERENCE_PATTERN.fullmatch(value)
        if lowered_key == "credential_profile_id":
            return not isinstance(value, str) or not _SAFE_REFERENCE_PATTERN.fullmatch(value)
        if lowered_key == "has_secret":
            return not isinstance(value, bool)
        if lowered_key and lowered_key not in _SAFE_REFERENCE_KEYS:
            if any(keyword in lowered_key for keyword in SENSITIVE_PARAM_KEYWORDS):
                return True
        if isinstance(value, dict):
            return any(visit(item, str(item_key)) for item_key, item in value.items())
        if isinstance(value, list):
            return any(visit(item) for item in value)
        return isinstance(value, str) and _contains_sensitive_text(value)

    return visit(data)


def _contains_sensitive_text(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in SECRET_LIKE_VALUE_HINTS) or bool(_SENSITIVE_TEXT_PATTERN.search(lowered))


def _safe_display_text(value: Any, *, fallback: str) -> str:
    text = str(value or fallback).strip() or fallback
    if _contains_sensitive_text(text):
        return f"[REDACTED {fallback.upper()}]"
    return text[:256]


def _safe_result_reference(value: str) -> str:
    stripped = value.strip()
    return (
        stripped
        if _SAFE_REFERENCE_PATTERN.fullmatch(stripped) and not _contains_sensitive_text(stripped)
        else "[invalid-device-id]"
    )


def _capability(value: str) -> DeviceSyncCapability:
    if value == "alert.search":
        return DeviceSyncCapability(
            capability=value,
            display_name="Alert Search",
            description="Configure Runtime v2 metadata for alert synchronization.",
            supported=True,
            default_mode="manual",
            limitations=list(_CAPABILITY_LIMITATIONS),
        )
    return DeviceSyncCapability(
        capability=value,
        display_name=value,
        description="Configure Runtime v2 synchronization metadata for this capability.",
        supported=True,
        default_mode="manual",
        limitations=list(_CAPABILITY_LIMITATIONS),
    )


def _profile_summary(profile: SyncProfile) -> DeviceSyncProfileSummary:
    return DeviceSyncProfileSummary(
        sync_profile_id=profile.sync_profile_id,
        display_name=_safe_display_text(profile.display_name, fallback="Sync Profile"),
        package_id=profile.package_id,
        instance_id=profile.instance_id,
        capability=profile.capability,
        mode=profile.mode,
        enabled=profile.enabled,
    )


default_device_sync_profile_service = DeviceSyncProfileService()
