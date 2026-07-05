from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import aiohttp

from flocks import security
from flocks.config.config_writer import ConfigWriter
from flocks.tool.registry import ToolContext, ToolResult


SERVICE_ID = "dbappsecurity_mingjian_vuln_scanner_api"
STORAGE_KEY = "dbappsecurity_mingjian_vuln_scanner_api_v5_0"
DEFAULT_TIMEOUT = 30
DEFAULT_LIMIT = 50
MAX_LIMIT = 100
DEFAULT_TASK_LIMIT = 10
DEFAULT_ASSET_SYNC_MODULES = (0, 1, 5, 8)
DEFAULT_VULNERABILITY_SYNC_MODULES = (0, 1, 5, 8, 11)
MODULE_NAMES = {
    0: "website",
    1: "database",
    5: "baseline",
    8: "host",
    9: "asset_detection",
    11: "weak_password",
    100: "coordinator",
}
ITEM_LIST_PATHS = (
    "data.list",
    "data.rows",
    "data.items",
    "data.assetList",
    "data.vulList",
    "data.vulnerabilityList",
    "data.records",
    "result.list",
    "result.rows",
    "result.items",
    "assetList",
    "vulList",
    "vulnerabilityList",
    "vulnerabilities",
    "assets",
    "list",
    "rows",
    "items",
    "records",
)
TASK_ID_KEYS = ("taskId", "task_id", "taskid", "id", "taskNo", "task_no", "uuid")

ENGINE_ACTIONS = {
    "engines": {"method": "GET", "path": "/api/normal/getEngines"},
    "engines_v5": {"method": "GET", "path": "/api/normal/getEngines/v5"},
}

TASK_ACTIONS = {
    "progress": {"method": "POST", "path": "/api/normal/task/progress"},
    "list": {"method": "GET", "path": "/api/normal/task/list"},
    "list_v2": {"method": "GET", "path": "/api/normal/task/list/V2"},
    "count": {"method": "GET", "path": "/api/normal/task/count"},
    "status": {"method": "GET", "path": "/api/normal/task/getTaskStatus"},
}

RESULT_ACTIONS = {
    "scan_result": {"method": "GET", "path": "/api/normal/task/result"},
    "vulnerability_count": {"method": "GET", "path": "/api/normal/task/countResult"},
    "website_info": {"method": "GET", "path": "/api/normal/task/getWebsiteInfo"},
}

ASSET_ACTIONS = {
    "get": {"method": "GET", "path": "/api/normal/asset/get"},
    "get_v2": {"method": "GET", "path": "/api/v2/normal/asset/get"},
    "count": {"method": "POST", "path": "/api/normal/asset/count"},
}

POLICY_ACTIONS = {
    "policies": {"method": "GET", "path": "/api/normal/policy/get"},
    "templates": {"method": "GET", "path": "/api/normal/policy/getPolicyTemplates"},
}

SYSTEM_ACTIONS = {
    "license": {"method": "GET", "path": "/api/normal/system/license"},
    "license_v5": {"method": "GET", "path": "/api/normal/system//license/v5"},
    "version": {"method": "GET", "path": "/api/normal/system/version"},
    "resource_usage": {"method": "GET", "path": "/api/normal/system/resouceuasge"},
}


def _get_raw_service() -> dict[str, Any]:
    for key in (SERVICE_ID, STORAGE_KEY):
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
        secret_manager.get("dbappsecurity_mingjian_host")
        or secret_manager.get("mingjian_vuln_scanner_host")
        or secret_manager.get("das_ras_host")
        or security.resolve_value("{env:DBAPPSECURITY_MINGJIAN_HOST}")
        or security.resolve_value("{env:MINGJIAN_VULN_SCANNER_HOST}")
        or security.resolve_value("{env:DAS_RAS_HOST}")
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


def _resolve_credentials(raw_service: dict[str, Any]) -> tuple[str, str]:
    username = _secret_or_setting(
        raw_service,
        "username",
        ("dbappsecurity_mingjian_username", "mingjian_vuln_scanner_username", "das_ras_username"),
        ("DBAPPSECURITY_MINGJIAN_USERNAME", "MINGJIAN_VULN_SCANNER_USERNAME", "DAS_RAS_USERNAME"),
    )
    user_code = _secret_or_setting(
        raw_service,
        "user_code",
        ("dbappsecurity_mingjian_user_code", "mingjian_vuln_scanner_user_code", "das_ras_user_code"),
        ("DBAPPSECURITY_MINGJIAN_USER_CODE", "MINGJIAN_VULN_SCANNER_USER_CODE", "DAS_RAS_USER_CODE"),
    )
    return username, user_code


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


def _full_path(path: str, raw_service: dict[str, Any]) -> str:
    prefix = _api_prefix(raw_service)
    return f"/{prefix}/{path.lstrip('/')}" if prefix else path


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
    return min(max(limit, 1), MAX_LIMIT)


def _bounded_count(value: int | None, *, default: int = DEFAULT_TASK_LIMIT) -> int:
    try:
        count = int(value) if value is not None else default
    except (TypeError, ValueError):
        count = default
    return min(max(count, 1), MAX_LIMIT)


def _coerce_modules(value: Any, default: tuple[int, ...]) -> list[int | str]:
    raw_values: list[Any]
    if value is None:
        raw_values = list(default)
    elif isinstance(value, str):
        raw_values = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        raw_values = list(value)
    else:
        raw_values = [value]

    modules: list[int | str] = []
    for raw in raw_values:
        if raw in (None, ""):
            continue
        if isinstance(raw, int):
            candidate: int | str = raw
        else:
            raw_text = str(raw).strip()
            try:
                candidate = int(raw_text)
            except ValueError:
                candidate = raw_text
        if candidate not in modules:
            modules.append(candidate)
    return modules or list(default)


def _module_name(module: int | str) -> str:
    if isinstance(module, int):
        return MODULE_NAMES.get(module, str(module))
    return str(module)


def _get_nested_value(root: Any, path: str) -> Any:
    current = root
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return None
            current = current[index]
            continue
        return None
    return current


def _extract_items(output: Any) -> list[Any]:
    if isinstance(output, list):
        return output
    if not isinstance(output, dict):
        return []
    for path in ITEM_LIST_PATHS:
        value = _get_nested_value(output, path)
        if isinstance(value, list):
            return value
    return []


def _annotate_item(item: Any, **metadata: Any) -> dict[str, Any]:
    output = dict(item) if isinstance(item, dict) else {"value": item}
    for key, value in metadata.items():
        output.setdefault(key, value)
    return output


def _task_identifier(task: Any) -> Any:
    if not isinstance(task, dict):
        return None
    for key in TASK_ID_KEYS:
        value = task.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _task_name(task: Any) -> str | None:
    if not isinstance(task, dict):
        return None
    for key in ("name", "taskName", "task_name", "title"):
        value = task.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _add_task_ids(payload: dict[str, Any], task_id: str | int | None, task_ids: list[str] | list[int] | None) -> None:
    if task_id is not None and "taskId" not in payload:
        payload["taskId"] = task_id
    if task_ids and "taskIds[]" not in payload:
        payload["taskIds[]"] = task_ids


def _common_payload(
    *,
    module: str | int | None = None,
    offset: int | None = None,
    limit: int | None = None,
    task_id: str | int | None = None,
    task_ids: list[str] | list[int] | None = None,
    asset_id: str | int | None = None,
    vul_type: str | int | None = None,
    state: str | int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    policy_no: str | int | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if params:
        payload.update(params)
    if body:
        payload.update(body)
    if module is not None:
        payload.setdefault("module", module)
    if offset is not None:
        payload.setdefault("offset", offset)
    bounded_limit = _bounded_limit(limit)
    if bounded_limit is not None:
        payload.setdefault("limit", bounded_limit)
    _add_task_ids(payload, task_id, task_ids)
    if asset_id is not None:
        payload.setdefault("assetId", asset_id)
    if vul_type is not None:
        payload.setdefault("vulType", vul_type)
    if state is not None:
        payload.setdefault("state", state)
    if start_time:
        payload.setdefault("startTime", start_time)
    if end_time:
        payload.setdefault("endTime", end_time)
    if policy_no is not None:
        payload.setdefault("policyNo", policy_no)
    return _clean_mapping(payload)


def _payload_error(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("success") is False:
        message = payload.get("message") or payload.get("msg") or payload.get("error")
        return f"明鉴漏洞扫描系统 API 返回失败：{message or '未提供失败原因'}"

    code = payload.get("code", payload.get("error_code", payload.get("statusCode")))
    if code not in (None, 0, 1, 200, "0", "1", "200", "success", "SUCCESS"):
        message = payload.get("message") or payload.get("msg") or payload.get("error")
        return f"明鉴漏洞扫描系统 API 返回失败（code={code}）：{message or '未提供失败原因'}"
    return None


def _pick_output(payload: Any) -> Any:
    if isinstance(payload, dict):
        for key in ("data", "result", "rows"):
            if key in payload:
                return payload[key]
    return payload


def _http_error_message(status: int, text: str, *, stage: str) -> str:
    if status in {401, 403}:
        if stage == "token":
            return "明鉴漏洞扫描系统拒绝获取 token。请确认 Base URL、userName、userCode（32 位 MD5 密文）有效，且账号具备 API 权限。"
        return "明鉴漏洞扫描系统拒绝本次查询。请确认 token 未过期，账号具备该只读接口权限。"
    if status == 404:
        return "明鉴漏洞扫描系统未找到该接口路径。请确认设备版本为 DAS-RAS V5.0，或在配置中填写正确 api_prefix。"
    if status == 405:
        return "明鉴漏洞扫描系统不接受当前请求方法，请确认现场 API 与 V5.0 手册一致。"
    return f"明鉴漏洞扫描系统 API 请求失败：HTTP {status}，响应片段：{text[:300]}"


async def _get_token(session: aiohttp.ClientSession, raw_service: dict[str, Any], base_url: str, metadata: dict[str, Any]) -> tuple[str | None, ToolResult | None]:
    username, user_code = _resolve_credentials(raw_service)
    if not username or not user_code:
        return None, ToolResult(
            success=False,
            error="明鉴漏洞扫描系统 userName 或 userCode 未配置，请在 Device Integration 中更新凭据。userCode 应为账号密码的 32 位 MD5 密文。",
            metadata=metadata,
        )

    full_path = _full_path("/api/normal/token", raw_service)
    token_url = urljoin(f"{base_url}/", full_path.lstrip("/"))
    params = {"userName": username, "userCode": user_code}
    try:
        async with session.request("GET", token_url, params=params, headers={"Accept": "application/json"}) as response:
            text = await response.text()
            if response.status >= 400:
                return None, ToolResult(success=False, error=_http_error_message(response.status, text, stage="token"), metadata=metadata)
            try:
                payload_obj = json.loads(text) if text else {}
            except json.JSONDecodeError:
                return None, ToolResult(success=False, error=f"明鉴漏洞扫描系统 token 响应不是 JSON：{text[:300]}", metadata=metadata)
    except aiohttp.ClientError as exc:
        return None, ToolResult(success=False, error=f"无法连接明鉴漏洞扫描系统：{exc}", metadata=metadata)
    except Exception as exc:
        return None, ToolResult(success=False, error=f"调用明鉴漏洞扫描系统 token 接口时发生异常：{exc}", metadata=metadata)

    error = _payload_error(payload_obj)
    if error:
        return None, ToolResult(success=False, error=error, output=payload_obj, metadata=metadata)
    data = payload_obj.get("data") if isinstance(payload_obj, dict) else None
    token = data.get("Authorization") if isinstance(data, dict) else None
    if not isinstance(token, str) or not token.strip():
        return None, ToolResult(success=False, error="明鉴漏洞扫描系统 token 响应缺少 data.Authorization。", output=payload_obj, metadata=metadata)
    return token.strip(), None


async def _request_api(
    *,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    api_name: str,
) -> ToolResult:
    raw_service = _get_raw_service()
    base_url = _resolve_base_url(raw_service)
    if not base_url:
        return ToolResult(success=False, error="明鉴漏洞扫描系统 Base URL 未配置，请在 Device Integration 中填写设备地址。")

    full_path = _full_path(path, raw_service)
    url = urljoin(f"{base_url}/", full_path.lstrip("/"))
    request_payload = _clean_mapping(payload or {})
    request_method = method.upper()
    timeout = aiohttp.ClientTimeout(total=_resolve_timeout(raw_service))
    connector = aiohttp.TCPConnector(ssl=_verify_ssl(raw_service))
    metadata = {"source": "DBAPPSecurity Mingjian Vulnerability Scanner", "api": api_name, "path": full_path, "method": request_method}

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            token, token_error = await _get_token(session, raw_service, base_url, metadata)
            if token_error:
                return token_error

            headers = {"Accept": "application/json", "Authorization": token or ""}
            kwargs: dict[str, Any] = {"headers": headers}
            if request_method == "GET":
                if request_payload:
                    kwargs["params"] = request_payload
            else:
                kwargs["data"] = request_payload
                headers["Content-Type"] = "application/x-www-form-urlencoded"

            async with session.request(request_method, url, **kwargs) as response:
                text = await response.text()
                if response.status >= 400:
                    return ToolResult(success=False, error=_http_error_message(response.status, text, stage="query"), metadata=metadata)
                try:
                    payload_obj = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return ToolResult(success=True, output=text, metadata=metadata)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"无法连接明鉴漏洞扫描系统：{exc}", metadata=metadata)
    except Exception as exc:
        return ToolResult(success=False, error=f"调用明鉴漏洞扫描系统 API 时发生异常：{exc}", metadata=metadata)

    error = _payload_error(payload_obj)
    if error:
        return ToolResult(success=False, error=error, output=payload_obj, metadata=metadata)
    return ToolResult(success=True, output=_pick_output(payload_obj), metadata=metadata)


async def _sync_assets(
    *,
    modules: Any = None,
    offset: int | None = 0,
    limit: int | None = DEFAULT_LIMIT,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    bounded_limit = _bounded_limit(limit) or DEFAULT_LIMIT
    items: list[dict[str, Any]] = []
    module_summaries: list[dict[str, Any]] = []
    warnings: list[str] = []
    failures: list[str] = []
    spec = ASSET_ACTIONS["get_v2"]

    for module in _coerce_modules(modules, DEFAULT_ASSET_SYNC_MODULES):
        if len(items) >= bounded_limit:
            break
        payload = _common_payload(module=module, offset=offset, limit=bounded_limit, params=params, body=body)
        result = await _request_api(method=spec["method"], path=spec["path"], payload=payload, api_name=f"assets.sync.{module}")
        if not result.success:
            message = result.error or "unknown error"
            failures.append(f"module {module}: {message}")
            warnings.append(f"资产模块 {module} 同步失败：{message}")
            module_summaries.append({"module": module, "name": _module_name(module), "status": "failed", "count": 0})
            continue
        module_items = _extract_items(result.output)
        items.extend(
            _annotate_item(item, mingjian_module=module, mingjian_module_name=_module_name(module))
            for item in module_items[: max(0, bounded_limit - len(items))]
        )
        module_summaries.append({"module": module, "name": _module_name(module), "status": "ok", "count": len(module_items)})

    if not module_summaries:
        return ToolResult(success=False, error="明鉴漏洞扫描系统资产同步未配置有效模块。")
    if not items and failures and len(failures) == len(module_summaries):
        return ToolResult(success=False, error="明鉴漏洞扫描系统资产同步失败：" + "；".join(failures))
    return ToolResult(
        success=True,
        output={"items": items, "count": len(items), "modules": module_summaries, "warnings": warnings},
        metadata={"source": "DBAPPSecurity Mingjian Vulnerability Scanner", "api": "assets.sync"},
    )


async def _sync_vulnerabilities(
    *,
    modules: Any = None,
    offset: int | None = 0,
    limit: int | None = DEFAULT_LIMIT,
    task_limit: int | None = DEFAULT_TASK_LIMIT,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    bounded_limit = _bounded_limit(limit) or DEFAULT_LIMIT
    bounded_task_limit = _bounded_count(task_limit)
    task_spec = TASK_ACTIONS["list_v2"]
    result_spec = RESULT_ACTIONS["scan_result"]
    items: list[dict[str, Any]] = []
    task_summaries: list[dict[str, Any]] = []
    warnings: list[str] = []
    failures: list[str] = []

    for module in _coerce_modules(modules, DEFAULT_VULNERABILITY_SYNC_MODULES):
        if len(items) >= bounded_limit:
            break
        task_payload = _common_payload(module=module, offset=0, limit=bounded_task_limit)
        task_result = await _request_api(
            method=task_spec["method"],
            path=task_spec["path"],
            payload=task_payload,
            api_name=f"tasks.sync_list.{module}",
        )
        if not task_result.success:
            message = task_result.error or "unknown error"
            failures.append(f"module {module}: {message}")
            warnings.append(f"任务模块 {module} 查询失败：{message}")
            task_summaries.append({"module": module, "name": _module_name(module), "status": "failed", "task_count": 0})
            continue

        tasks_for_module = _extract_items(task_result.output)[:bounded_task_limit]
        module_result_count = 0
        for task in tasks_for_module:
            if len(items) >= bounded_limit:
                break
            task_id = _task_identifier(task)
            if task_id in (None, ""):
                warnings.append(f"任务模块 {module} 存在缺少 taskId 的任务，已跳过。")
                continue
            result_payload = _common_payload(
                module=module,
                offset=offset,
                limit=bounded_limit,
                task_id=task_id,
                params=params,
                body=body,
            )
            result = await _request_api(
                method=result_spec["method"],
                path=result_spec["path"],
                payload=result_payload,
                api_name=f"results.sync.{module}.{task_id}",
            )
            if not result.success:
                message = result.error or "unknown error"
                warnings.append(f"任务 {task_id} 漏洞结果查询失败：{message}")
                task_summaries.append(
                    {
                        "module": module,
                        "name": _module_name(module),
                        "task_id": task_id,
                        "task_name": _task_name(task),
                        "status": "failed",
                        "count": 0,
                    }
                )
                continue
            result_items = _extract_items(result.output)
            module_result_count += len(result_items)
            items.extend(
                _annotate_item(
                    item,
                    taskId=task_id,
                    taskName=_task_name(task),
                    mingjian_module=module,
                    mingjian_module_name=_module_name(module),
                )
                for item in result_items[: max(0, bounded_limit - len(items))]
            )
            task_summaries.append(
                {
                    "module": module,
                    "name": _module_name(module),
                    "task_id": task_id,
                    "task_name": _task_name(task),
                    "status": "ok",
                    "count": len(result_items),
                }
            )
        if not tasks_for_module:
            task_summaries.append({"module": module, "name": _module_name(module), "status": "ok", "task_count": 0, "count": 0})
        elif module_result_count == 0:
            warnings.append(f"任务模块 {module} 暂未返回漏洞结果。")

    if not task_summaries:
        return ToolResult(success=False, error="明鉴漏洞扫描系统漏洞同步未配置有效模块。")
    if not items and failures and len(failures) == len([summary for summary in task_summaries if summary.get("task_count", 1) != 0]):
        return ToolResult(success=False, error="明鉴漏洞扫描系统漏洞同步失败：" + "；".join(failures))
    return ToolResult(
        success=True,
        output={"items": items, "count": len(items), "tasks": task_summaries, "warnings": warnings},
        metadata={"source": "DBAPPSecurity Mingjian Vulnerability Scanner", "api": "results.sync"},
    )


def _spec_for(action: str, actions: dict[str, dict[str, str]], label: str) -> dict[str, str] | None:
    spec = actions.get(action)
    if spec:
        return spec
    return None


async def health(ctx: ToolContext) -> ToolResult:
    spec = ENGINE_ACTIONS["engines_v5"]
    return await _request_api(method=spec["method"], path=spec["path"], api_name="health.engines_v5")


async def engines(ctx: ToolContext, action: str = "engines_v5", params: dict[str, Any] | None = None) -> ToolResult:
    spec = _spec_for(action, ENGINE_ACTIONS, "扫描引擎")
    if not spec:
        return ToolResult(success=False, error=f"不支持的扫描引擎动作：{action}。可选：{', '.join(ENGINE_ACTIONS)}")
    return await _request_api(method=spec["method"], path=spec["path"], payload=params, api_name=f"engines.{action}")


async def tasks(
    ctx: ToolContext,
    action: str = "list_v2",
    module: str | int | None = None,
    offset: int | None = 0,
    limit: int | None = DEFAULT_LIMIT,
    task_id: str | int | None = None,
    task_ids: list[str] | list[int] | None = None,
    state: str | int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    spec = _spec_for(action, TASK_ACTIONS, "任务")
    if not spec:
        return ToolResult(success=False, error=f"不支持的任务动作：{action}。可选：{', '.join(TASK_ACTIONS)}")
    payload = _common_payload(
        module=module,
        offset=offset,
        limit=limit,
        task_id=task_id,
        task_ids=task_ids,
        state=state,
        start_time=start_time,
        end_time=end_time,
        params=params,
        body=body,
    )
    return await _request_api(method=spec["method"], path=spec["path"], payload=payload, api_name=f"tasks.{action}")


async def results(
    ctx: ToolContext,
    action: str = "scan_result",
    module: str | int | None = None,
    modules: Any = None,
    offset: int | None = 0,
    limit: int | None = DEFAULT_LIMIT,
    task_limit: int | None = DEFAULT_TASK_LIMIT,
    task_id: str | int | None = None,
    task_ids: list[str] | list[int] | None = None,
    asset_id: str | int | None = None,
    vul_type: str | int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    if action == "sync":
        return await _sync_vulnerabilities(modules=modules or module, offset=offset, limit=limit, task_limit=task_limit, params=params, body=body)
    spec = _spec_for(action, RESULT_ACTIONS, "漏洞结果")
    if not spec:
        return ToolResult(success=False, error=f"不支持的漏洞结果动作：{action}。可选：{', '.join([*RESULT_ACTIONS, 'sync'])}")
    payload = _common_payload(
        module=module,
        offset=offset,
        limit=limit,
        task_id=task_id,
        task_ids=task_ids,
        asset_id=asset_id,
        vul_type=vul_type,
        start_time=start_time,
        end_time=end_time,
        params=params,
        body=body,
    )
    return await _request_api(method=spec["method"], path=spec["path"], payload=payload, api_name=f"results.{action}")


async def assets(
    ctx: ToolContext,
    action: str = "get_v2",
    module: str | int | None = None,
    modules: Any = None,
    offset: int | None = 0,
    limit: int | None = DEFAULT_LIMIT,
    asset_id: str | int | None = None,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> ToolResult:
    if action == "sync":
        return await _sync_assets(modules=modules or module, offset=offset, limit=limit, params=params, body=body)
    spec = _spec_for(action, ASSET_ACTIONS, "资产")
    if not spec:
        return ToolResult(success=False, error=f"不支持的资产动作：{action}。可选：{', '.join([*ASSET_ACTIONS, 'sync'])}")
    payload = _common_payload(module=module, offset=offset, limit=limit, asset_id=asset_id, params=params, body=body)
    return await _request_api(method=spec["method"], path=spec["path"], payload=payload, api_name=f"assets.{action}")


async def policies(
    ctx: ToolContext,
    action: str = "templates",
    module: str | int | None = None,
    offset: int | None = 0,
    limit: int | None = DEFAULT_LIMIT,
    policy_no: str | int | None = None,
    params: dict[str, Any] | None = None,
) -> ToolResult:
    spec = _spec_for(action, POLICY_ACTIONS, "策略")
    if not spec:
        return ToolResult(success=False, error=f"不支持的策略动作：{action}。可选：{', '.join(POLICY_ACTIONS)}")
    payload = _common_payload(module=module, offset=offset, limit=limit, policy_no=policy_no, params=params)
    return await _request_api(method=spec["method"], path=spec["path"], payload=payload, api_name=f"policies.{action}")


async def system(ctx: ToolContext, action: str = "version", params: dict[str, Any] | None = None) -> ToolResult:
    spec = _spec_for(action, SYSTEM_ACTIONS, "系统")
    if not spec:
        return ToolResult(success=False, error=f"不支持的系统动作：{action}。可选：{', '.join(SYSTEM_ACTIONS)}")
    return await _request_api(method=spec["method"], path=spec["path"], payload=params, api_name=f"system.{action}")
