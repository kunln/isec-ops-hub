"""Device Integration-backed adapter for the Runtime v2 TDA alert capability.

The adapter resolves only credential-free Integration Instance and Device
Integration identity metadata.  Credential activation remains inside
``ToolRegistry.execute(..., device_id=...)`` and exists only for the duration of
the outbound device call.  Vendor responses are mapped immediately to bounded,
normalized Evidence Event-like items; the original response is never returned
or persisted by this adapter.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from flocks.security.integrations.adapter import (
    IntegrationAdapter,
    IntegrationAdapterRequest,
    IntegrationAdapterResult,
    build_adapter_item_refs,
    validate_adapter_request,
)
from flocks.security.integrations.builtin_mappings import TDA_ALERT_MAPPING
from flocks.security.integrations.device_bridge import BRIDGE_SOURCE
from flocks.security.integrations.instance_store import default_integration_instance_store
from flocks.security.integrations.mapping import apply_mapping, first_of
from flocks.tool.device.store import get_device_identity

TDA_PACKAGE_ID = "asiainfo.tda"
TDA_ALERT_CAPABILITY = "alert.search"
TDA_ALERT_TOOL = "asiainfo_tda_alerts"

MAX_PREVIEW_ITEMS = 200
_SAFE_QUERY_KEYS = frozenset(
    {
        "time_type",
        "time_limit",
        "src",
        "dst",
        "attacker_addr",
        "victim_addr",
        "threat_desc",
        "severity",
        "page",
        "limit",
        "page_size",
    }
)
_ITEM_PATHS = (
    "alarm_list",
    "data.alarm_list",
    "result",
    "data.result",
    "list",
    "rows",
    "items",
    "records",
    "alerts",
)

DeviceIdentityGetter = Callable[[str], Awaitable[Mapping[str, Any] | None] | Mapping[str, Any] | None]
ToolExecutor = Callable[..., Awaitable[Any] | Any]


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _safe_query_params(params: Mapping[str, Any], cursor: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return only the declared read-only TDA alert query parameters."""

    warnings: list[str] = []
    safe: dict[str, Any] = {}
    for key in _SAFE_QUERY_KEYS:
        if key in params and params[key] not in (None, "", [], {}):
            safe[key] = params[key]

    if "page" not in safe and cursor.get("page") not in (None, ""):
        safe["page"] = cursor.get("page")
    if "limit" not in safe and "page_size" in safe:
        safe["limit"] = safe.pop("page_size")
    else:
        safe.pop("page_size", None)

    safe["time_type"] = _bounded_int(safe.get("time_type"), 2, 1, 5)
    safe["page"] = _bounded_int(safe.get("page"), 1, 1, 1_000_000)
    requested_limit = _bounded_int(safe.get("limit"), 100, 1, 500)
    if requested_limit > MAX_PREVIEW_ITEMS:
        warnings.append(f"limit capped at {MAX_PREVIEW_ITEMS} for bounded preview storage")
    safe["limit"] = min(requested_limit, MAX_PREVIEW_ITEMS)

    severity = safe.get("severity")
    if severity is not None and not isinstance(severity, list):
        safe["severity"] = [str(severity)]

    ignored = sorted(str(key) for key in params if str(key) not in _SAFE_QUERY_KEYS)
    if ignored:
        warnings.append("unsupported query parameters were ignored")
    return safe, warnings


def _get_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _extract_alerts(output: Any) -> tuple[list[dict[str, Any]] | None, int | None]:
    if isinstance(output, list):
        return [item for item in output if isinstance(item, dict)], len(output)
    if not isinstance(output, Mapping):
        return None, None

    for path in _ITEM_PATHS:
        value = _get_path(output, path)
        if isinstance(value, list):
            total_value = first_of(output, ("total", "data.total", "count", "data.count"))
            try:
                total = int(total_value) if total_value is not None else len(value)
            except (TypeError, ValueError):
                total = len(value)
            return [item for item in value if isinstance(item, dict)], total
    return None, None


def _first_reference(value: Any) -> str | None:
    values = value if isinstance(value, list) else [value]
    for item in values:
        if item not in (None, "", [], {}):
            return str(item)
    return None


def _map_alert(alert: Mapping[str, Any], *, instance_id: str, device_id: str) -> tuple[dict[str, Any], list[str]]:
    mapped = apply_mapping(alert, TDA_ALERT_MAPPING)
    event = mapped.event
    external_event_id = str(event["external_event_id"])
    ioc_refs = event.get("ioc_refs") if isinstance(event.get("ioc_refs"), list) else []
    asset_refs = event.get("asset_refs") if isinstance(event.get("asset_refs"), list) else []
    alert_type = first_of(
        alert,
        ("threat_class", "threat_tag", "sub_threat_type", "attack_tac", "attack_tec", "rule_source"),
    )
    source = first_of(alert, ("source",), "ndr")
    description = event.get("description") or event.get("title") or ""
    query_hint = f"device_id={device_id} external_event_id={external_event_id}"

    item = {
        "external_event_id": external_event_id,
        "external_id": external_event_id,
        "title": event.get("title"),
        "description": description,
        "severity": event.get("severity"),
        "source": str(source),
        "source_type": event.get("source_type") or "integration_event",
        "asset_id": _first_reference(asset_refs),
        "ioc": [str(value) for value in ioc_refs[:20]],
        "occurred_at": event.get("occurred_at") or None,
        "alert_type": str(alert_type) if alert_type not in (None, "") else TDA_ALERT_CAPABILITY,
        "key_fields": event.get("key_fields") or {},
        "payload_hash": event.get("payload_hash"),
        "query_hint": query_hint,
        "metadata": {
            "package_id": TDA_PACKAGE_ID,
            "instance_id": instance_id,
            "capability": TDA_ALERT_CAPABILITY,
            "mapping": "tda_alert_v2",
        },
    }
    warnings = list(mapped.warnings)
    if mapped.dropped_sensitive_fields:
        warnings.append("sensitive or raw vendor fields were omitted")
    return item, warnings


def _classify_tool_error(error: Any) -> tuple[str, str]:
    """Classify an unsafe vendor/tool error and return a stable safe message."""

    text = str(error or "").lower()
    if any(marker in text for marker in ("已禁用", "disabled")):
        return "device_disabled", "Referenced Device Integration is disabled"
    if any(marker in text for marker in ("未找到", "not found")):
        return "device_not_found", "Referenced Device Integration was not found"
    if any(marker in text for marker in ("未配置", "missing credential", "api key", "secret required")):
        return "missing_credentials", "Required Device Integration credentials are not configured"
    if any(marker in text for marker in ("401", "403", "unauthorized", "forbidden", "拒绝", "鉴权", "认证")):
        return "device_auth_failed", "TDA rejected the configured device credentials"
    if any(marker in text for marker in ("timeout", "timed out", "超时")):
        return "device_timeout", "TDA request timed out"
    if any(marker in text for marker in ("invalid response", "invalid json", "响应格式", "response shape")):
        return "vendor_response_invalid", "TDA returned an unsupported response shape"
    if any(marker in text for marker in ("返回失败", "vendor response")):
        return "vendor_response_invalid", "TDA returned a rejected or invalid vendor response"
    return "device_connection_failed", "TDA device request failed"


async def _execute_tda_tool(*, device_id: str, params: dict[str, Any]) -> Any:
    from flocks.tool import ToolContext, ToolRegistry

    ToolRegistry.init()
    return await ToolRegistry.execute(
        TDA_ALERT_TOOL,
        ctx=ToolContext(
            session_id="integration-runtime-v2",
            message_id="integration-runtime-v2:asiainfo.tda:alert.search",
        ),
        device_id=device_id,
        **params,
    )


class DeviceIntegrationRuntimeAdapter(IntegrationAdapter):
    """Runtime v2 adapter for ``asiainfo.tda + alert.search`` only."""

    adapter_id = "asiainfo.tda.device-integration.adapter"
    package_id = TDA_PACKAGE_ID
    supported_capabilities = {TDA_ALERT_CAPABILITY}

    def __init__(
        self,
        *,
        instance_store: Any = None,
        device_identity_getter: DeviceIdentityGetter | None = None,
        tool_executor: ToolExecutor | None = None,
    ) -> None:
        self.instance_store = instance_store or default_integration_instance_store
        self.device_identity_getter = device_identity_getter or get_device_identity
        self.tool_executor = tool_executor or _execute_tda_tool

    def _result(
        self,
        request: IntegrationAdapterRequest,
        *,
        status: str,
        items: list[dict[str, Any]] | None = None,
        cursor: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IntegrationAdapterResult:
        safe_items = items or []
        return IntegrationAdapterResult(
            status=status,
            dry_run=True,
            package_id=request.package_id,
            instance_id=request.instance_id,
            capability=request.capability,
            item_count=len(safe_items),
            items=safe_items,
            item_refs=build_adapter_item_refs(safe_items),
            cursor=cursor or {},
            summary=summary or {},
            warnings=warnings or [],
            errors=errors or [],
            metadata=metadata or {},
        )

    async def run_capability(self, request: IntegrationAdapterRequest) -> IntegrationAdapterResult:
        validate_adapter_request(request)
        if request.package_id != TDA_PACKAGE_ID or request.capability != TDA_ALERT_CAPABILITY:
            return self._result(
                request,
                status="unsupported_capability",
                errors=["Only asiainfo.tda + alert.search is supported"],
            )
        if not request.instance_id:
            return self._result(request, status="bridge_metadata_invalid", errors=["Integration instance_id is required"])

        instance = await _maybe_await(self.instance_store.get_instance(request.instance_id))
        if instance is None:
            return self._result(request, status="bridge_metadata_invalid", errors=["Integration instance was not found"])
        if getattr(instance, "package_id", None) != request.package_id:
            return self._result(request, status="bridge_metadata_invalid", errors=["Integration package reference mismatch"])
        if not bool(getattr(instance, "enabled", False)):
            return self._result(request, status="device_disabled", errors=["Integration instance is disabled"])

        metadata = getattr(instance, "metadata", None)
        if not isinstance(metadata, Mapping) or metadata.get("source") != BRIDGE_SOURCE:
            return self._result(request, status="bridge_metadata_invalid", errors=["Integration instance is not Device Integration-backed"])
        device_id = str(metadata.get("device_id") or "").strip()
        if not device_id:
            return self._result(request, status="bridge_metadata_invalid", errors=["Device Integration reference is missing"])

        device = await _maybe_await(self.device_identity_getter(device_id))
        if device is None:
            return self._result(request, status="device_not_found", errors=["Referenced Device Integration was not found"])
        if not bool(device.get("enabled")):
            return self._result(request, status="device_disabled", errors=["Referenced Device Integration is disabled"])
        if str(device.get("status") or "unknown").lower() not in {"ok", "healthy", "connected"}:
            return self._result(
                request,
                status="device_connection_failed",
                errors=["Device Integration requires a successful connection test before preview"],
            )

        params, warnings = _safe_query_params(request.params, request.cursor)
        try:
            result = await _maybe_await(self.tool_executor(device_id=device_id, params=params))
        except (asyncio.TimeoutError, TimeoutError):
            return self._result(request, status="device_timeout", errors=["TDA request timed out"])
        except Exception as exc:  # exception text is classified, never exported
            code, message = _classify_tool_error(exc)
            return self._result(request, status=code, errors=[message])

        success = bool(getattr(result, "success", False)) if not isinstance(result, Mapping) else bool(result.get("success"))
        if not success:
            error = getattr(result, "error", None) if not isinstance(result, Mapping) else result.get("error")
            code, message = _classify_tool_error(error)
            return self._result(request, status=code, warnings=warnings, errors=[message])

        output = getattr(result, "output", None) if not isinstance(result, Mapping) else result.get("output")
        alerts, total = _extract_alerts(output)
        if alerts is None:
            return self._result(
                request,
                status="vendor_response_invalid",
                warnings=warnings,
                errors=["TDA returned an unsupported response shape"],
            )

        mapped_items: list[dict[str, Any]] = []
        mapping_warning_count = 0
        for alert in alerts[:MAX_PREVIEW_ITEMS]:
            item, item_warnings = _map_alert(alert, instance_id=request.instance_id, device_id=device_id)
            mapped_items.append(item)
            mapping_warning_count += len(item_warnings)
        if len(alerts) > MAX_PREVIEW_ITEMS:
            warnings.append(f"vendor result truncated to {MAX_PREVIEW_ITEMS} normalized preview items")
        if mapping_warning_count:
            warnings.append(f"{mapping_warning_count} mapping safety warning(s) were recorded")

        page = int(params["page"])
        limit = int(params["limit"])
        return self._result(
            request,
            status="success",
            items=mapped_items,
            cursor={"page": page + 1, "limit": limit},
            summary={
                "tool": TDA_ALERT_TOOL,
                "device_id": device_id,
                "returned_count": len(mapped_items),
                "vendor_total": total,
                "page": page,
                "limit": limit,
            },
            warnings=warnings,
            metadata={
                "source": BRIDGE_SOURCE,
                "device_id": device_id,
                "normalized_only": True,
                "raw_response_persisted": False,
            },
        )


__all__ = [
    "DeviceIntegrationRuntimeAdapter",
    "TDA_ALERT_CAPABILITY",
    "TDA_ALERT_TOOL",
    "TDA_PACKAGE_ID",
]
