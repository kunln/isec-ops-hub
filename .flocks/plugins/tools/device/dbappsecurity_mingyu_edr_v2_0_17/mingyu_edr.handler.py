from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import aiohttp

from flocks import security
from flocks.config.config_writer import ConfigWriter
from flocks.tool.registry import ToolContext, ToolResult


SERVICE_ID = "dbappsecurity_edr_api"
STORAGE_KEY = "dbappsecurity_edr_api_v2_0_17"
DEFAULT_TIMEOUT = 30
DEFAULT_LIMIT = 50

ASSET_ACTIONS = {
    "list": "/node/list",
    "details": "/node/details",
    "ports": "/node/ports",
    "process": "/node/process",
    "account": "/node/account",
    "software": "/node/software",
    "monitor_cpu": "/node/monitor/cpu",
    "monitor_memory": "/node/monitor/memory",
    "monitor_net": "/node/monitor/net",
    "monitor_disk": "/node/monitor/disk",
}

SECURITY_ACTIONS = {
    "horse_scan_status": "/horse/scan/status",
    "horse_scan_list": "/horse/scan/list",
    "horse_current_scan": "/horse/scan/get_scanning_info",
    "horse_last_scan": "/horse/scan/get_last_scan_result",
    "horse_read_scan_file": "/horse/scan/read_page_scan_file",
    "horse_get_sub_item": "/horse/scan/get_sub_item",
    "antivirus_scan_setting": "/antivirus/scan/virus_scan_setting",
    "antivirus_virus_list": "/antivirus/virus/list",
    "antivirus_isolation_list": "/antivirus/isolation/list",
    "antivirus_scan_detail": "/antivirus/scan/get_detail",
    "win_vuln_list": "/vulnerability/win/listWindows",
    "win_vuln_nodes": "/vulnerability/win/nodesWindows",
    "win_vuln_level": "/vulnerability/win/level",
    "linux_vuln_list": "/vulnerability/linux/list",
    "linux_vuln_nodes": "/vulnerability/linux/nodes",
    "linux_vuln_level": "/vulnerability/linux/level",
}

POLICY_ACTIONS = {
    "template_list": "/rule/template/list",
    "template_detail": "/rule/template/detail",
    "template_bound_nodes": "/rule/template/bindNodes",
    "template_unbound_nodes": "/rule/template/unbindNodes",
    "microisolation_list": "/rule/microisolation/list",
}

LOG_ACTIONS = {
    "protection_list": "/log/list",
    "protection_top_type": "/log/topType",
    "protection_type": "/log/type",
    "operation_list": "/operationlog/list",
    "operation_event": "/operationlog/get_log_event",
    "operation_type": "/operationlog/get_log_type",
}

REPORT_ACTIONS = {
    "edr_event_trend": "/report/count_edr_report",
    "virus_top": "/report/count_edr_virus_top",
    "ransom_asset_top": "/report/count_edr_black_mail_asset",
    "risk_asset_top": "/report/count_edr_top_risk_asset",
    "overall_risk_level": "/report/count_edr_all_risk_level",
}

INFO_SEARCH_ACTIONS = {
    "time": "/info_search/time",
    "count": "/info_search/counttabletable",
    "listens": "/info_search/listens",
    "listens_details": "/info_search/listens_details",
    "process": "/info_search/process",
    "process_details": "/info_search/process_details",
    "account": "/info_search/account",
    "account_details": "/info_search/account_details",
    "software": "/info_search/software",
    "software_details": "/info_search/software_details",
    "startup": "/info_search/startup",
    "startup_details": "/info_search/startup_details",
}

RISK_BASELINE_ACTIONS = {
    "risk_assets": "/risk/list_node",
    "risk_detail": "/risk/get_detail",
    "baseline_policy": "/base_line/get_ploy",
    "baseline_task_list": "/base_line/get_task_list",
    "baseline_task_info": "/base_line/get_task_info_list",
    "baseline_task_nodes": "/base_line/get_task_node_info_list",
    "baseline_task_node_risks": "/base_line/get_task_node_risk_info_lis",
    "baseline_item_info": "/base_line/get_item_info",
    "baseline_levels": "/base_line/get_level",
    "baseline_unbound_nodes": "/base_line/find_node",
    "baseline_bound_nodes": "/base_line/find_node_by_task_id",
}


def _get_raw_service() -> dict[str, Any]:
    for key in (STORAGE_KEY, SERVICE_ID):
        raw = ConfigWriter.get_api_service_raw(key)
        if isinstance(raw, dict) and raw:
            return raw
    return {}


def _get_custom_setting(raw_service: dict[str, Any], key: str, default: Any = None) -> Any:
    if key in raw_service:
        return raw_service.get(key)
    custom_settings = raw_service.get("custom_settings", {})
    if isinstance(custom_settings, dict) and key in custom_settings:
        return custom_settings.get(key)
    return default


def _resolve_base_url(raw_service: dict[str, Any]) -> str:
    raw_value = raw_service.get("base_url") or _get_custom_setting(raw_service, "base_url")
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip().rstrip("/")

    secret_manager = security.get_secret_manager()
    host = (
        secret_manager.get("dbappsecurity_edr_host")
        or secret_manager.get("mingyu_edr_host")
        or security.resolve_value("{env:DBAPPSECURITY_EDR_HOST}")
        or security.resolve_value("{env:MINGYU_EDR_HOST}")
    )
    if isinstance(host, str) and host.strip():
        host = host.strip().rstrip("/")
        if host.startswith(("http://", "https://")):
            return host
        return f"https://{host}"
    return ""


def _secret_or_setting(raw_service: dict[str, Any], key: str, secret_names: tuple[str, ...], env_names: tuple[str, ...]) -> str:
    raw_value = (
        raw_service.get(key)
        or raw_service.get(key.replace("_", ""))
        or _get_custom_setting(raw_service, key)
        or _get_custom_setting(raw_service, key.replace("_", ""))
    )
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()

    secret_manager = security.get_secret_manager()
    for secret_name in secret_names:
        value = secret_manager.get(secret_name)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for env_name in env_names:
        value = security.resolve_value(f"{{env:{env_name}}}")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _resolve_auth(raw_service: dict[str, Any]) -> tuple[str, str]:
    session_cookie = _secret_or_setting(
        raw_service,
        "session_cookie",
        ("dbappsecurity_edr_session_cookie", "mingyu_edr_session_cookie"),
        ("DBAPPSECURITY_EDR_SESSION_COOKIE", "MINGYU_EDR_SESSION_COOKIE"),
    )
    auth_token = _secret_or_setting(
        raw_service,
        "auth_token",
        ("dbappsecurity_edr_auth_token", "mingyu_edr_auth_token", "dbappsecurity_edr_token", "mingyu_edr_token"),
        ("DBAPPSECURITY_EDR_AUTH_TOKEN", "MINGYU_EDR_AUTH_TOKEN", "DBAPPSECURITY_EDR_TOKEN", "MINGYU_EDR_TOKEN"),
    )
    return session_cookie, auth_token


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


def _api_prefix(raw_service: dict[str, Any]) -> str:
    value = _get_custom_setting(raw_service, "api_prefix", "")
    if not isinstance(value, str):
        return ""
    return value.strip().strip("/")


def _read_method(raw_service: dict[str, Any]) -> str:
    value = str(_get_custom_setting(raw_service, "read_method", "POST") or "POST").upper()
    return value if value in {"GET", "POST"} else "POST"


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


def _bounded_limit(value: int | None) -> int | None:
    if value is None:
        return None
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    return min(max(limit, 1), 500)


def _common_payload(
    *,
    page: int | None = None,
    limit: int | None = None,
    node_id: str | None = None,
    keyword: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if params:
        payload.update(params)
    if body:
        payload.update(body)
    if page is not None:
        payload.setdefault("page", page)
    bounded_limit = _bounded_limit(limit)
    if bounded_limit is not None:
        payload.setdefault("limit", bounded_limit)
    if node_id:
        payload.setdefault("node_id", node_id)
    if keyword:
        payload.setdefault("keyword", keyword)
    if start_time:
        payload.setdefault("start_time", start_time)
    if end_time:
        payload.setdefault("end_time", end_time)
    return _clean_mapping(payload)


def _payload_error(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None

    if payload.get("success") is False:
        message = payload.get("message") or payload.get("msg") or payload.get("error")
        return f"明御 EDR API 返回失败：{message or '未提供失败原因'}"

    code = payload.get("code", payload.get("error_code", payload.get("statusCode")))
    if code not in (None, 0, 1, 200, "0", "1", "200", "success", "SUCCESS"):
        message = payload.get("message") or payload.get("msg") or payload.get("error")
        return f"明御 EDR API 返回失败（code={code}）：{message or '未提供失败原因'}"

    return None


def _pick_output(payload: Any) -> Any:
    if isinstance(payload, dict):
        for key in ("data", "result", "rows"):
            if key in payload:
                return payload[key]
    return payload


def _http_error_message(status: int, text: str) -> str:
    if status in {401, 403}:
        return "明御 EDR 拒绝了本次连接。请确认会话 Cookie 或 Token 有效，且账号具备对应页面的租户/admin 权限。"
    if status == 404:
        return "明御 EDR 未找到该接口路径，请确认设备版本为 V2.0.17 或在配置中填写正确 api_prefix。"
    if status == 405:
        return "明御 EDR 不接受当前请求方法。请在设备配置中将 read_method 调整为 GET 或 POST 后重试。"
    return f"明御 EDR API 请求失败：HTTP {status}，响应片段：{text[:300]}"


async def _request_read(
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    api_name: str,
    method: str | None = None,
) -> ToolResult:
    raw_service = _get_raw_service()
    base_url = _resolve_base_url(raw_service)
    session_cookie, auth_token = _resolve_auth(raw_service)
    if not base_url:
        return ToolResult(success=False, error="明御 EDR Base URL 未配置，请在 Device Integration 中填写设备地址。")
    if not session_cookie and not auth_token:
        return ToolResult(success=False, error="明御 EDR 会话 Cookie 或 Token 未配置，请在 Device Integration 中更新凭据。")

    prefix = _api_prefix(raw_service)
    full_path = f"/{prefix}/{path.lstrip('/')}" if prefix else path
    url = urljoin(f"{base_url}/", full_path.lstrip("/"))
    request_method = (method or _read_method(raw_service)).upper()
    request_payload = _clean_mapping(payload or {})
    headers = {"Accept": "application/json"}
    if session_cookie:
        headers["Cookie"] = session_cookie
    if auth_token:
        token_header = str(_get_custom_setting(raw_service, "token_header", "Authorization") or "Authorization")
        token_value = auth_token
        if token_header.lower() == "authorization" and not auth_token.lower().startswith(("bearer ", "basic ")):
            token_value = f"Bearer {auth_token}"
        headers[token_header] = token_value

    timeout = aiohttp.ClientTimeout(total=_resolve_timeout(raw_service))
    connector = aiohttp.TCPConnector(ssl=_verify_ssl(raw_service))
    metadata = {"source": "DBAPPSecurity Mingyu EDR", "api": api_name, "path": full_path, "method": request_method}

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            kwargs: dict[str, Any] = {"headers": headers}
            if request_method == "GET":
                if request_payload:
                    kwargs["params"] = request_payload
            else:
                kwargs["json"] = request_payload
                headers["Content-Type"] = "application/json"

            async with session.request(request_method, url, **kwargs) as response:
                text = await response.text()
                if response.status >= 400:
                    return ToolResult(success=False, error=_http_error_message(response.status, text), metadata=metadata)
                try:
                    payload_obj = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return ToolResult(success=True, output=text, metadata=metadata)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"无法连接明御 EDR：{exc}", metadata=metadata)
    except Exception as exc:
        return ToolResult(success=False, error=f"调用明御 EDR API 时发生异常：{exc}", metadata=metadata)

    error = _payload_error(payload_obj)
    if error:
        return ToolResult(success=False, error=error, output=payload_obj, metadata=metadata)
    return ToolResult(success=True, output=_pick_output(payload_obj), metadata=metadata)


def _path_for(action: str, actions: dict[str, str], label: str) -> str | None:
    path = actions.get(action)
    if path:
        return path
    return None


async def health(ctx: ToolContext) -> ToolResult:
    payload = {"page": 1, "limit": 1}
    return await _request_read("/node/list", payload=payload, api_name="health.node_list")


async def assets(
    ctx: ToolContext,
    action: str = "list",
    page: int | None = 1,
    limit: int | None = DEFAULT_LIMIT,
    node_id: str | None = None,
    keyword: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, ASSET_ACTIONS, "资产")
    if not path:
        return ToolResult(success=False, error=f"不支持的资产动作：{action}。可选：{', '.join(ASSET_ACTIONS)}")
    payload = _common_payload(page=page, limit=limit, node_id=node_id, keyword=keyword, params=params, body=body)
    return await _request_read(path, payload=payload, api_name=f"assets.{action}")


async def security_findings(
    ctx: ToolContext,
    action: str = "antivirus_virus_list",
    page: int | None = 1,
    limit: int | None = DEFAULT_LIMIT,
    node_id: str | None = None,
    keyword: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, SECURITY_ACTIONS, "安全结果")
    if not path:
        return ToolResult(success=False, error=f"不支持的安全结果动作：{action}。可选：{', '.join(SECURITY_ACTIONS)}")
    payload = _common_payload(
        page=page,
        limit=limit,
        node_id=node_id,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
        params=params,
        body=body,
    )
    return await _request_read(path, payload=payload, api_name=f"security_findings.{action}")


async def policy(
    ctx: ToolContext,
    action: str = "template_list",
    page: int | None = 1,
    limit: int | None = DEFAULT_LIMIT,
    keyword: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, POLICY_ACTIONS, "策略")
    if not path:
        return ToolResult(success=False, error=f"不支持的策略动作：{action}。可选：{', '.join(POLICY_ACTIONS)}")
    payload = _common_payload(page=page, limit=limit, keyword=keyword, params=params, body=body)
    return await _request_read(path, payload=payload, api_name=f"policy.{action}")


async def logs(
    ctx: ToolContext,
    action: str = "protection_list",
    page: int | None = 1,
    limit: int | None = DEFAULT_LIMIT,
    keyword: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, LOG_ACTIONS, "日志")
    if not path:
        return ToolResult(success=False, error=f"不支持的日志动作：{action}。可选：{', '.join(LOG_ACTIONS)}")
    payload = _common_payload(
        page=page,
        limit=limit,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
        params=params,
        body=body,
    )
    return await _request_read(path, payload=payload, api_name=f"logs.{action}")


async def reports(
    ctx: ToolContext,
    action: str = "edr_event_trend",
    start_time: str | None = None,
    end_time: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, REPORT_ACTIONS, "报表")
    if not path:
        return ToolResult(success=False, error=f"不支持的报表动作：{action}。可选：{', '.join(REPORT_ACTIONS)}")
    payload = _common_payload(start_time=start_time, end_time=end_time, params=params, body=body)
    return await _request_read(path, payload=payload, api_name=f"reports.{action}")


async def info_search(
    ctx: ToolContext,
    action: str = "time",
    page: int | None = 1,
    limit: int | None = DEFAULT_LIMIT,
    keyword: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, INFO_SEARCH_ACTIONS, "信息搜索")
    if not path:
        return ToolResult(success=False, error=f"不支持的信息搜索动作：{action}。可选：{', '.join(INFO_SEARCH_ACTIONS)}")
    payload = _common_payload(page=page, limit=limit, keyword=keyword, params=params, body=body)
    return await _request_read(path, payload=payload, api_name=f"info_search.{action}")


async def risk_baseline(
    ctx: ToolContext,
    action: str = "risk_assets",
    page: int | None = 1,
    limit: int | None = DEFAULT_LIMIT,
    node_id: str | None = None,
    keyword: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    path = _path_for(action, RISK_BASELINE_ACTIONS, "风险/基线")
    if not path:
        return ToolResult(success=False, error=f"不支持的风险/基线动作：{action}。可选：{', '.join(RISK_BASELINE_ACTIONS)}")
    payload = _common_payload(page=page, limit=limit, node_id=node_id, keyword=keyword, params=params, body=body)
    return await _request_read(path, payload=payload, api_name=f"risk_baseline.{action}")
