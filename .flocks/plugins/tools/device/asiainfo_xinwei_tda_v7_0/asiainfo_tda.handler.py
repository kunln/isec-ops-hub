from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any
from urllib.parse import urljoin

import aiohttp

from flocks import security
from flocks.config.config_writer import ConfigWriter
from flocks.tool.registry import ToolContext, ToolResult


SERVICE_ID = "asiainfo_tda_api"
DEFAULT_TIMEOUT = 30
DEFAULT_ASSET_LIMIT = 100
MAX_ASSET_LIMIT = 500
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 500


def _get_raw_service() -> dict[str, Any]:
    raw = ConfigWriter.get_api_service_raw(SERVICE_ID)
    return raw if isinstance(raw, dict) else {}


def _get_custom_setting(raw_service: dict[str, Any], key: str, default: Any = None) -> Any:
    custom_settings = raw_service.get("custom_settings", {})
    if not isinstance(custom_settings, dict):
        return default
    return custom_settings.get(key, default)


def _ensure_scheme(url: str) -> str:
    if url and not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _resolve_base_url(raw_service: dict[str, Any]) -> str:
    raw_value = raw_service.get("base_url") or raw_service.get("baseUrl") or _get_custom_setting(raw_service, "base_url")
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return _ensure_scheme(resolved.strip()).rstrip("/")

    secret_manager = security.get_secret_manager()
    host = (
        secret_manager.get("asiainfo_tda_host")
        or secret_manager.get("tda_host")
        or security.resolve_value("{env:ASIAINFO_TDA_HOST}")
        or security.resolve_value("{env:TDA_HOST}")
    )
    if isinstance(host, str) and host.strip():
        return _ensure_scheme(host.strip()).rstrip("/")

    env_base = os.getenv("ASIAINFO_TDA_BASE_URL") or os.getenv("TDA_BASE_URL")
    if env_base:
        return _ensure_scheme(env_base.strip()).rstrip("/")
    return ""


def _resolve_api_key(raw_service: dict[str, Any]) -> str:
    raw_value = (
        raw_service.get("apiKey")
        or raw_service.get("api_key")
        or raw_service.get("apikey")
        or raw_service.get("server_guid")
        or raw_service.get("guid")
        or _get_custom_setting(raw_service, "apiKey")
        or _get_custom_setting(raw_service, "api_key")
    )
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()

    secret_manager = security.get_secret_manager()
    for secret_name in ("asiainfo_tda_api_key", "tda_api_key", "tda_server_guid"):
        value = secret_manager.get(secret_name)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for env_name in ("ASIAINFO_TDA_API_KEY", "TDA_API_KEY", "TDA_SERVER_GUID"):
        value = security.resolve_value(f"{{env:{env_name}}}")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _resolve_secret(raw_service: dict[str, Any]) -> str:
    raw_value = (
        raw_service.get("secret")
        or raw_service.get("apiSecret")
        or raw_service.get("api_secret")
        or raw_service.get("secretKey")
        or raw_service.get("secret_key")
        or _get_custom_setting(raw_service, "secret")
        or _get_custom_setting(raw_service, "apiSecret")
        or _get_custom_setting(raw_service, "api_secret")
    )
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()

    secret_manager = security.get_secret_manager()
    for secret_name in ("asiainfo_tda_secret", "tda_secret", "asiainfo_tda_api_secret", "tda_api_secret"):
        value = secret_manager.get(secret_name)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for env_name in ("ASIAINFO_TDA_SECRET", "TDA_SECRET", "ASIAINFO_TDA_API_SECRET", "TDA_API_SECRET"):
        value = security.resolve_value(f"{{env:{env_name}}}")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _verify_ssl(raw_service: dict[str, Any]) -> bool:
    raw_value = raw_service.get("verify_ssl")
    if raw_value is None:
        raw_value = raw_service.get("ssl_verify")
    if raw_value is None:
        raw_value = _get_custom_setting(raw_service, "verify_ssl", True)
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, str):
        return raw_value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(raw_value)


def _resolve_timeout(raw_service: dict[str, Any]) -> int:
    raw_value = raw_service.get("timeout") or _get_custom_setting(raw_service, "timeout", DEFAULT_TIMEOUT)
    try:
        timeout = int(raw_value)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    return max(1, timeout)


def _clean_mapping(values: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        cleaned[key] = value
    return cleaned


def _require_fields(values: dict[str, Any], fields: list[str]) -> str | None:
    missing: list[str] = []
    for field in fields:
        value = values.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(field)
        elif isinstance(value, (list, dict)) and not value:
            missing.append(field)
    if missing:
        return "缺少必要参数：" + ", ".join(missing)
    return None


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return min(max(number, minimum), maximum)


def _tda_filter(value: Any, op: str = "default") -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    if isinstance(value, (list, dict)) and not value:
        return None
    return {"value": value, "op": op}


def _auth_params(api_key: str, secret: str, raw_service: dict[str, Any]) -> dict[str, Any]:
    timestamp = str(int(time.time()))
    sign_data = f"{timestamp}{api_key}".encode("utf-8")
    secret_bytes = secret.encode("utf-8")
    mode = str(_get_custom_setting(raw_service, "signature_mode", raw_service.get("signature_mode") or "hex_digest")).lower()
    digest = hmac.new(secret_bytes, sign_data, hashlib.sha256).digest()
    if mode in {"raw", "raw_digest", "digest"}:
        sign_bytes = digest
    else:
        sign_bytes = hmac.new(secret_bytes, sign_data, hashlib.sha256).hexdigest().encode("ascii")
    sign = base64.urlsafe_b64encode(sign_bytes).decode("ascii")
    if not bool(_get_custom_setting(raw_service, "signature_padding", raw_service.get("signature_padding", True))):
        sign = sign.rstrip("=")
    return {"api_key": api_key, "auth_timestamp": timestamp, "sign": sign}


def _payload_error(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None

    res = payload.get("res")
    if res is False or (isinstance(res, str) and res.lower() == "false"):
        return f"TDA API 返回失败：{payload.get('message') or '未提供失败原因'}"

    code = payload.get("code") or payload.get("error_code")
    if code not in (None, 0, 200, "0", "200"):
        return f"TDA API 返回失败（code={code}）：{payload.get('message') or payload.get('msg') or '未提供失败原因'}"
    return None


def _pick_output(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _http_error_message(status: int, text: str) -> str:
    if status in {401, 403}:
        return "TDA 拒绝了本次连接。请确认 API Key、Secret 有效，设备时间同步正常，且当前账号具备对外 API 权限。"
    if status == 404:
        return "TDA 未找到该 API 路径，请确认设备版本为 7.0 或兼容版本，且 Base URL 未包含 /ngtda。"
    return f"TDA API 请求失败：HTTP {status}，响应片段：{text[:300]}"


async def _request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    api_name: str,
) -> ToolResult:
    raw_service = _get_raw_service()
    base_url = _resolve_base_url(raw_service)
    api_key = _resolve_api_key(raw_service)
    secret = _resolve_secret(raw_service)
    if not base_url:
        return ToolResult(success=False, error="TDA Base URL 未配置，请在 Device Integration 中填写设备地址。")
    if not api_key:
        return ToolResult(success=False, error="TDA API Key 未配置，请在 Device Integration 中更新凭据。")
    if not secret:
        return ToolResult(success=False, error="TDA Secret 未配置，请在 Device Integration 中更新凭据。")

    url = urljoin(f"{base_url}/", path.lstrip("/"))
    request_params = {**_clean_mapping(params or {}), **_auth_params(api_key, secret, raw_service)}
    request_body = _clean_mapping(json_body or {})
    method_upper = method.upper()

    timeout = aiohttp.ClientTimeout(total=_resolve_timeout(raw_service))
    connector = aiohttp.TCPConnector(ssl=_verify_ssl(raw_service))
    metadata = {"source": "AsiaInfo Security Xinwei TDA", "api": api_name, "path": path}

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            kwargs: dict[str, Any] = {}
            if request_params:
                kwargs["params"] = request_params
            if method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
                kwargs["json"] = request_body
                kwargs["headers"] = {"Content-Type": "application/json"}

            async with session.request(method_upper, url, **kwargs) as response:
                text = await response.text()
                if response.status >= 400:
                    return ToolResult(success=False, error=_http_error_message(response.status, text), metadata=metadata)
                try:
                    payload = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return ToolResult(success=True, output=text, metadata=metadata)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"无法连接 TDA：{exc}", metadata=metadata)
    except Exception as exc:
        return ToolResult(success=False, error=f"调用 TDA API 时发生异常：{exc}", metadata=metadata)

    error = _payload_error(payload)
    if error:
        return ToolResult(success=False, error=error, output=payload, metadata=metadata)
    return ToolResult(success=True, output=_pick_output(payload), metadata=metadata)


async def health(ctx: ToolContext) -> ToolResult:
    del ctx
    result = await _request(
        "GET",
        "/ngtda/dashboard/system_resource_overview",
        api_name="health.system_resource_overview",
    )
    if not result.success:
        return result
    output = result.output if isinstance(result.output, dict) else {}
    return ToolResult(
        success=True,
        output={
            "connected": True,
            "probe": "system_resource_overview",
            "cpu_average": (output.get("cpu") or {}).get("average") if isinstance(output.get("cpu"), dict) else None,
            "memory_percent": (output.get("memory") or {}).get("percent") if isinstance(output.get("memory"), dict) else None,
        },
        metadata={**(result.metadata or {}), "api": "health"},
    )


async def assets(
    ctx: ToolContext,
    time_type: int = 2,
    time_limit: str | None = None,
    asset_classification: str | None = None,
    asset_ip: str | None = None,
    asset_name: str | None = None,
    page: int = 1,
    limit: int = DEFAULT_ASSET_LIMIT,
) -> ToolResult:
    del ctx
    body = _clean_mapping(
        {
            "time_type": _bounded_int(time_type, 2, 1, 5),
            "time_limit": time_limit,
            "asset_classification": asset_classification,
            "asset_ip": _tda_filter(asset_ip),
            "asset_name": _tda_filter(asset_name),
            "order_key": "active_time",
            "order_direction": 0,
            "page": _bounded_int(page, 1, 1, 1_000_000),
            "limit": _bounded_int(limit, DEFAULT_ASSET_LIMIT, 1, MAX_ASSET_LIMIT),
        }
    )
    return await _request("POST", "/ngtda/asset/assetlist", json_body=body, api_name="asset.assetlist")


async def alerts(
    ctx: ToolContext,
    time_type: int = 2,
    time_limit: str | None = None,
    src: str | None = None,
    dst: str | None = None,
    attacker_addr: str | None = None,
    victim_addr: str | None = None,
    threat_desc: str | None = None,
    severity: list[str] | None = None,
    page: int = 1,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> ToolResult:
    del ctx
    body = _clean_mapping(
        {
            "time_type": _bounded_int(time_type, 2, 1, 5),
            "time_limit": time_limit,
            "src": _tda_filter([src] if src else None),
            "dst": _tda_filter([dst] if dst else None),
            "attacker_addr": _tda_filter([attacker_addr] if attacker_addr else None),
            "victim_addr": _tda_filter([victim_addr] if victim_addr else None),
            "threat_desc": _tda_filter([threat_desc] if threat_desc else None),
            "severity": _tda_filter(severity),
            "order": "event_time",
            "order_direction": "desc",
            "page": _bounded_int(page, 1, 1, 1_000_000),
            "limit": _bounded_int(limit, DEFAULT_QUERY_LIMIT, 1, MAX_QUERY_LIMIT),
        }
    )
    return await _request("POST", "/ngtda/diagnosis/alert_list", json_body=body, api_name="diagnosis.alert_list")


async def raw_events(
    ctx: ToolContext,
    time_type: int = 2,
    time_limit: str | None = None,
    flow_id: str | None = None,
    attacker_addr: str | None = None,
    victim_addr: str | None = None,
    threat_desc: str | None = None,
    page: int = 1,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> ToolResult:
    del ctx
    body = _clean_mapping(
        {
            "time_type": _bounded_int(time_type, 2, 1, 5),
            "time_limit": time_limit,
            "flow_id": _tda_filter(flow_id),
            "attacker_addr": _tda_filter(attacker_addr),
            "victim_addr": _tda_filter(victim_addr),
            "threat_desc": _tda_filter(threat_desc),
            "order": "event_time",
            "order_direction": "desc",
            "page": _bounded_int(page, 1, 1, 1_000_000),
            "limit": _bounded_int(limit, DEFAULT_QUERY_LIMIT, 1, MAX_QUERY_LIMIT),
        }
    )
    return await _request("POST", "/ngtda/diagnosis/event_list", json_body=body, api_name="diagnosis.event_list")


async def asset_risks(
    ctx: ToolContext,
    time_type: int = 2,
    time_limit: str | None = None,
    asset_addr: str | None = None,
    page: int = 1,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> ToolResult:
    del ctx
    body = _clean_mapping(
        {
            "time_type": _bounded_int(time_type, 2, 1, 5),
            "time_limit": time_limit,
            "asset_addr": asset_addr,
            "order": "latest_time",
            "order_direction": "desc",
            "page": _bounded_int(page, 1, 1, 1_000_000),
            "limit": _bounded_int(limit, DEFAULT_QUERY_LIMIT, 1, MAX_QUERY_LIMIT),
        }
    )
    return await _request("POST", "/ngtda/asset_rating_v3/list", json_body=body, api_name="asset_rating_v3.list")


async def attackers(
    ctx: ToolContext,
    time_type: int = 2,
    time_limit: str | None = None,
    asset_addr: str | None = None,
    page: int = 1,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> ToolResult:
    del ctx
    body = _clean_mapping(
        {
            "time_type": _bounded_int(time_type, 2, 1, 5),
            "time_limit": time_limit,
            "asset_addr": asset_addr,
            "order": "latest_time",
            "order_direction": "desc",
            "page": _bounded_int(page, 1, 1, 1_000_000),
            "limit": _bounded_int(limit, DEFAULT_QUERY_LIMIT, 1, MAX_QUERY_LIMIT),
        }
    )
    return await _request("POST", "/ngtda/attacker/list", json_body=body, api_name="attacker.list")


async def sandbox_results(
    ctx: ToolContext,
    start_ts: int | None = None,
    end_ts: int | None = None,
    file_md5: str | None = None,
    file_sha1: str | None = None,
    page: int = 1,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> ToolResult:
    del ctx
    body = _clean_mapping(
        {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "file_md5": file_md5,
            "file_sha1": file_sha1,
            "order": 1,
            "order_key": "report_ts",
            "page": _bounded_int(page, 1, 1, 1_000_000),
            "limit": _bounded_int(limit, DEFAULT_QUERY_LIMIT, 1, MAX_QUERY_LIMIT),
        }
    )
    return await _request("POST", "/ngtda/sandbox/internal/va_result", json_body=body, api_name="sandbox.va_result")


async def system_resource(ctx: ToolContext) -> ToolResult:
    del ctx
    return await _request("GET", "/ngtda/dashboard/system_resource_overview", api_name="dashboard.system_resource_overview")


async def alarm_pcap_detail(ctx: ToolContext, flow_id: int | str) -> ToolResult:
    del ctx
    params = {"flow_id": flow_id}
    err = _require_fields(params, ["flow_id"])
    if err:
        return ToolResult(success=False, error=err)
    return await _request("POST", "/ngtda/alarm/pcap_detail", json_body=params, api_name="alarm.pcap_detail")


async def ioc(
    ctx: ToolContext,
    sid: str | None = None,
    content: str | None = None,
) -> ToolResult:
    del ctx
    params = _clean_mapping({"sid": sid, "content": content})
    return await _request("GET", "/ngtda/rule/cus_ioc_md5_list", params=params, api_name="rule.cus_ioc_md5_list")
