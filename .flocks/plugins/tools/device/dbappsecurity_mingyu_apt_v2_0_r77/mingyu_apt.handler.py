from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin

import aiohttp

from flocks import security
from flocks.config.config_writer import ConfigWriter
from flocks.tool.registry import ToolContext, ToolResult


SERVICE_ID = "dbappsecurity_mingyu_apt_api"
DEFAULT_TIMEOUT = 30
DEFAULT_DAYS = 7

NAVIGATION_ACTIONS = {
    "latest_hours": "/openapi/navigator/latestHours",
    "risk_trend": "/openapi/navigate/getRiskTrend",
    # The product API keeps this spelling in V2.0R77.
    "risk_category": "/openapi/navigate/getRiskCtaegory",
    "map_list": "/openapi/navigate/getMapList",
    "attack_region": "/openapi/navigate/getAttackRegion",
    "event_list": "/openapi/navigate/getEventList",
}

SAFE_EVENT_GET_ACTIONS = {
    "incident_map": "/openapi/analyse/safe-event/incident/map",
    "sip_top30": "/openapi/analyse/safe-event/sip/top30",
    "event_top": "/openapi/analyse/safe-event/event/top",
    "sip_pop": "/openapi/analyse/safe-event/sip/pop",
    "dip_pop": "/openapi/analyse/safe-event/dip/pop",
    "event_pop": "/openapi/analyse/safe-event/event/pop",
    "second_eventlist": "/openapi/analyse/safe-event/second/eventlist",
    "second_trend_safeevent": "/openapi/analyse/safe-event/second/trend/safeevent",
    "second_trend_attackstatus": "/openapi/analyse/safe-event/second/trend/attackstatus",
    "second_singlebasic": "/openapi/analyse/safe-event/second/singlebasic",
}


def _get_raw_service() -> dict[str, Any]:
    raw = ConfigWriter.get_api_service_raw(SERVICE_ID)
    return raw if isinstance(raw, dict) else {}


def _get_custom_setting(raw_service: dict[str, Any], key: str, default: Any = None) -> Any:
    custom_settings = raw_service.get("custom_settings", {})
    if not isinstance(custom_settings, dict):
        return default
    return custom_settings.get(key, default)


def _resolve_base_url(raw_service: dict[str, Any]) -> str:
    raw_value = raw_service.get("base_url") or _get_custom_setting(raw_service, "base_url")
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip().rstrip("/")

    secret_manager = security.get_secret_manager()
    host = (
        secret_manager.get("dbappsecurity_mingyu_apt_host")
        or secret_manager.get("mingyu_apt_host")
        or security.resolve_value("{env:DBAPPSECURITY_MINGYU_APT_HOST}")
        or security.resolve_value("{env:MINGYU_APT_HOST}")
    )
    if isinstance(host, str) and host.strip():
        host = host.strip().rstrip("/")
        if host.startswith(("http://", "https://")):
            return host
        return f"https://{host}:443"
    return ""


def _resolve_api_key(raw_service: dict[str, Any]) -> str:
    raw_value = (
        raw_service.get("apiKey")
        or raw_service.get("api_key")
        or raw_service.get("token")
        or _get_custom_setting(raw_service, "apiKey")
        or _get_custom_setting(raw_service, "api_key")
    )
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()

    secret_manager = security.get_secret_manager()
    for secret_name in (
        "dbappsecurity_mingyu_apt_api_key",
        "mingyu_apt_api_key",
        "mingyu_apt_token",
    ):
        value = secret_manager.get(secret_name)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for env_name in ("DBAPPSECURITY_MINGYU_APT_API_KEY", "MINGYU_APT_API_KEY", "MINGYU_APT_TOKEN"):
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


def _time_range(begin: str | None = None, end: str | None = None, days: int = DEFAULT_DAYS) -> tuple[str, str]:
    if begin and end:
        return begin, end
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(days=days)
    return (
        begin or start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        end or end_dt.strftime("%Y-%m-%d %H:%M:%S"),
    )


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
    missing = []
    for field in fields:
        value = values.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(field)
        elif isinstance(value, (list, dict)) and not value:
            missing.append(field)
    if missing:
        return "缺少必要参数：" + ", ".join(missing)
    return None


def _payload_error(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None

    code = payload.get("error_code", payload.get("code"))
    if code not in (None, 0, 200, "0", "200"):
        message = payload.get("message") or payload.get("msg") or payload.get("error")
        return f"明御 APT API 返回失败（code={code}）：{message or '未提供失败原因'}"

    data = payload.get("data")
    if isinstance(data, dict):
        nested_code = data.get("code")
        if nested_code not in (None, 0, 200, "0", "200"):
            message = data.get("message") or payload.get("message") or data.get("msg")
            return f"明御 APT API 返回失败（data.code={nested_code}）：{message or '未提供失败原因'}"

    return None


def _pick_output(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _http_error_message(status: int, text: str) -> str:
    if status in {401, 403}:
        return (
            "明御 APT 拒绝了本次连接。请确认 API Key/APPSecret 有效，且 APT 授权中登记的访问 IP/MAC "
            "与当前请求来源一致。"
        )
    if status == 404:
        return "明御 APT 未找到该 OpenAPI 路径，请确认设备版本为 V2.0R77 或兼容版本。"
    return f"明御 APT API 请求失败：HTTP {status}，响应片段：{text[:300]}"


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
    if not base_url:
        return ToolResult(success=False, error="明御 APT Base URL 未配置，请在 Device Integration 中填写设备地址。")
    if not api_key:
        return ToolResult(success=False, error="明御 APT API Key/APPSecret 未配置，请在 Device Integration 中更新凭据。")

    url = urljoin(f"{base_url}/", path.lstrip("/"))
    headers = {"apikey": api_key}
    request_params = _clean_mapping(params or {})
    request_body = _clean_mapping(json_body or {})
    timeout = aiohttp.ClientTimeout(total=_resolve_timeout(raw_service))
    connector = aiohttp.TCPConnector(ssl=_verify_ssl(raw_service))
    metadata = {"source": "DBAPPSecurity Mingyu APT", "api": api_name, "path": path}

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            kwargs: dict[str, Any] = {"headers": headers}
            if request_params:
                kwargs["params"] = request_params
            if method.upper() in {"POST", "PUT", "PATCH"}:
                kwargs["json"] = request_body
                headers["Content-Type"] = "application/json"

            async with session.request(method.upper(), url, **kwargs) as response:
                text = await response.text()
                if response.status >= 400:
                    return ToolResult(success=False, error=_http_error_message(response.status, text), metadata=metadata)
                try:
                    payload = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return ToolResult(success=True, output=text, metadata=metadata)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"无法连接明御 APT：{exc}", metadata=metadata)
    except Exception as exc:
        return ToolResult(success=False, error=f"调用明御 APT API 时发生异常：{exc}", metadata=metadata)

    error = _payload_error(payload)
    if error:
        return ToolResult(success=False, error=error, output=payload, metadata=metadata)
    return ToolResult(success=True, output=_pick_output(payload), metadata=metadata)


async def health(ctx: ToolContext) -> ToolResult:
    return await _request("GET", "/openapi/about", api_name="about")


async def navigation(
    ctx: ToolContext,
    action: str = "latest_hours",
    time_ago: str = "d7",
) -> ToolResult:
    path = NAVIGATION_ACTIONS.get(action)
    if not path:
        return ToolResult(success=False, error=f"不支持的导航动作：{action}。可选：{', '.join(NAVIGATION_ACTIONS)}")
    return await _request("GET", path, params={"timeAgo": time_ago}, api_name=f"navigation.{action}")


async def platform_status(
    ctx: ToolContext,
    action: str = "detector_list",
    poid: int | None = None,
    time_ago: str | None = "h24",
    begin: str | None = None,
    end: str | None = None,
) -> ToolResult:
    if action == "detector_list":
        return await _request("GET", "/openapi/protect/object/list", api_name="platform.detector_list")
    if action == "system_status_line":
        params = _clean_mapping({"poid": poid, "timeAgo": time_ago, "begin": begin, "end": end})
        if "poid" not in params:
            return ToolResult(success=False, error="缺少必要参数：poid")
        return await _request("GET", "/openapi/system/status/line", params=params, api_name="platform.system_status_line")
    return ToolResult(success=False, error="不支持的平台状态动作：请选择 detector_list 或 system_status_line")


async def risk(
    ctx: ToolContext,
    action: str = "list",
    begin: str | None = None,
    end: str | None = None,
    days: int = DEFAULT_DAYS,
    combined: int = 1,
    flags: list[int] | None = None,
    sips: list[str] | None = None,
    dips: list[str] | None = None,
    siprange: str | None = None,
    diprange: str | None = None,
    sip_reverse: bool | None = None,
    dip_reverse: bool | None = None,
    attackstatuss: list[int] | None = None,
    eventypes: list[int] | None = None,
    offset: int = 0,
    limit: int = 20,
    second_max_accessid: int | None = None,
    accessid: str | None = None,
    accessids: list[str] | None = None,
    poid: int | None = None,
    sensorip: str | None = None,
    flag: int | None = None,
    aptfamily: int | None = None,
    ruleid: int | None = None,
    accesssubtype: int | None = None,
) -> ToolResult:
    if action == "enum":
        return await _request("GET", "/openapi/risk/getEnum", api_name="risk.enum")

    if action == "list":
        begin_value, end_value = _time_range(begin, end, days)
        body = {
            "begin": begin_value,
            "end": end_value,
            "combined": combined,
            "flags": flags or [-1],
            "sips": sips or [],
            "dips": dips or [],
            "siprange": siprange,
            "diprange": diprange,
            "sipReverse": sip_reverse,
            "dipReverse": dip_reverse,
            "attackstatuss": attackstatuss,
            "eventypes": eventypes,
            "offset": offset,
            "limit": limit,
            "secondMaxAccessid": second_max_accessid,
        }
        return await _request("POST", "/openapi/risk/getList", json_body=body, api_name="risk.list")

    if action == "detail":
        params = {"accessid": accessid, "poid": poid}
        error = _require_fields(params, ["accessid", "poid"])
        if error:
            return ToolResult(success=False, error=error)
        return await _request("GET", "/openapi/risk/detail", params=params, api_name="risk.detail")

    if action == "details":
        body = {"accessids": accessids}
        error = _require_fields(body, ["accessids"])
        if error:
            return ToolResult(success=False, error=error)
        return await _request("POST", "/openapi/risk/details", json_body=body, api_name="risk.details")

    if action == "analysis_suggest":
        params = {"flag": flag, "aptfamily": aptfamily, "ruleid": ruleid, "accesssubtype": accesssubtype}
        error = _require_fields(params, ["flag", "aptfamily", "ruleid", "accesssubtype"])
        if error:
            return ToolResult(success=False, error=error)
        return await _request("GET", "/openapi/risk/getAnalysisSuggest", params=params, api_name="risk.analysis_suggest")

    if action == "sigtype":
        params = {"flag": flag, "ruleid": ruleid, "accesssubtype": accesssubtype}
        error = _require_fields(params, ["flag", "ruleid", "accesssubtype"])
        if error:
            return ToolResult(success=False, error=error)
        return await _request("GET", "/openapi/risk/getSigtype", params=params, api_name="risk.sigtype")

    if action == "comb_info":
        params = {
            "accessid": accessid,
            "poid": poid,
            "sensorip": sensorip,
            "combined": 0,
            "offset": offset,
            "limit": limit,
        }
        error = _require_fields(params, ["accessid", "poid", "sensorip"])
        if error:
            return ToolResult(success=False, error=error)
        return await _request("GET", "/openapi/risk/getCombInfoList", params=params, api_name="risk.comb_info")

    if action == "trend":
        begin_value, end_value = _time_range(begin, end, days)
        return await _request("GET", "/openapi/risk/trend", params={"begin": begin_value, "end": end_value}, api_name="risk.trend")

    return ToolResult(
        success=False,
        error="不支持的风险动作。可选：enum, list, detail, details, analysis_suggest, sigtype, comb_info, trend",
    )


async def safe_event(
    ctx: ToolContext,
    action: str = "list",
    begin: str | None = None,
    end: str | None = None,
    days: int = DEFAULT_DAYS,
    offset: int = 0,
    limit: int = 20,
    sips: list[str] | None = None,
    dips: list[str] | None = None,
    siprange: str | None = None,
    diprange: str | None = None,
    incidentid: int | None = None,
    sip: str | None = None,
    dip: str | None = None,
    order: str = "count",
    order_type: str = "desc",
) -> ToolResult:
    begin_value, end_value = _time_range(begin, end, days)
    if action == "list":
        body = {
            "limit": limit,
            "offset": offset,
            "begin": begin_value,
            "end": end_value,
            "sips": sips or [],
            "dips": dips or [],
            "siprange": siprange,
            "diprange": diprange,
            "incidentid": incidentid,
        }
        return await _request("POST", "/openapi/analyse/safe-event/list", json_body=body, api_name="safe_event.list")

    path = SAFE_EVENT_GET_ACTIONS.get(action)
    if not path:
        return ToolResult(success=False, error=f"不支持的安全事件动作：{action}")

    params = {"begin": begin_value, "end": end_value}
    required: list[str] = []
    if action == "incident_map":
        params = {}
    elif action == "sip_top30":
        pass
    elif action == "event_top":
        pass
    elif action == "sip_pop":
        params["sip"] = sip
        required = ["sip"]
    elif action == "dip_pop":
        params["dip"] = dip
        required = ["dip"]
    elif action == "event_pop":
        params.update({"incidentid": incidentid, "order": order, "orderType": order_type})
        required = ["incidentid"]
    elif action in {"second_eventlist", "second_trend_safeevent"}:
        params.update({"sip": sip, "dip": dip})
        if action == "second_eventlist":
            params.update({"offset": offset, "limit": limit})
        required = ["sip", "dip"]
    elif action == "second_trend_attackstatus":
        params.update({"sip": sip, "dip": dip, "incidentid": incidentid})
        required = ["sip", "dip"]
    elif action == "second_singlebasic":
        params.update({"sip": sip, "dip": dip, "incidentid": incidentid})
        required = ["sip", "dip", "incidentid"]

    error = _require_fields(params, required)
    if error:
        return ToolResult(success=False, error=error)
    return await _request("GET", path, params=params, api_name=f"safe_event.{action}")


async def asset(
    ctx: ToolContext,
    action: str = "list",
    offset: int = 0,
    limit: int = 100,
    start_time: str | None = None,
    end_time: str | None = None,
    keyword: str | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    if action == "list":
        request_body = dict(body or {})
        request_body.setdefault("offset", offset)
        request_body.setdefault("limit", limit)
        if start_time:
            request_body.setdefault("startTime", start_time)
        if end_time:
            request_body.setdefault("endTime", end_time)
        return await _request("POST", "/openapi/asset/list", json_body=request_body, api_name="asset.list")

    if action == "countries":
        return await _request("GET", "/openapi/common/getCountrys", api_name="asset.countries")
    if action == "cities":
        return await _request("GET", "/openapi/common/getCity", api_name="asset.cities")
    if action == "groups":
        return await _request(
            "GET",
            "/openapi/asset/assetOrganize/getList",
            params={"keyWord": keyword},
            api_name="asset.groups",
        )

    return ToolResult(success=False, error="不支持的资产动作。可选：list, countries, cities, groups")
