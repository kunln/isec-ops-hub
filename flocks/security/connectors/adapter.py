"""Connector Adapter Runtime v1.

Adapters fetch compact vendor/raw payloads; mapping contracts normalize them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from time import perf_counter
from typing import Any
from urllib.parse import urljoin

from flocks.security.connectors.mapping import apply_mapping_contract, load_mapping_contract
from flocks.security.connectors.models import ConnectorCapability, ConnectorPreviewResult


ADAPTER_CONTRACT_VERSION = "connector.adapter.v1"
_TRUNCATED_TOOL_OUTPUT_RE = re.compile(r"Full output saved to:\s*(?P<path>[^\n\r]+)")


@dataclass
class AdapterExecutionResult:
    capability: str
    source: str
    raw_response: dict[str, Any]
    adapter_contract: dict[str, Any]
    request_summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    latency_ms: int | None = None


def load_adapter_contract(path: Path) -> dict[str, Any]:
    contract = json.loads(path.read_text(encoding="utf-8"))
    validate_adapter_contract(contract, source=str(path))
    return contract


def validate_adapter_contract(contract: dict[str, Any], *, source: str = "adapter contract") -> None:
    version = contract.get("version")
    if version != ADAPTER_CONTRACT_VERSION:
        raise ValueError(f"{source} uses unsupported adapter version: {version}")
    if not contract.get("capability"):
        raise ValueError(f"{source} is missing capability")
    if not contract.get("mapping"):
        raise ValueError(f"{source} is missing mapping")
    transport = contract.get("transport")
    if transport not in {"fixture", "http", "tool"}:
        raise ValueError(f"{source} uses unsupported transport: {transport}")
    if transport == "fixture":
        fixture = contract.get("fixture")
        if not isinstance(fixture, dict) or not fixture.get("path"):
            raise ValueError(f"{source} fixture transport requires fixture.path")
    if transport == "http":
        request = contract.get("request")
        if not isinstance(request, dict):
            raise ValueError(f"{source} http transport requires request")
        if not request.get("method"):
            raise ValueError(f"{source} http request is missing method")
        if not request.get("url") and not (request.get("base_url") or request.get("base_url_env")):
            raise ValueError(f"{source} http request is missing url or base_url")
    if transport == "tool":
        tool = contract.get("tool")
        if not isinstance(tool, dict) or not tool.get("name"):
            raise ValueError(f"{source} tool transport requires tool.name")


def adapter_contract_summary(contract: dict[str, Any], *, file: str | None = None) -> dict[str, Any]:
    request = contract.get("request") if isinstance(contract.get("request"), dict) else {}
    auth = request.get("auth") if isinstance(request.get("auth"), dict) else {}
    summary: dict[str, Any] = {
        "version": contract.get("version"),
        "capability": contract.get("capability"),
        "transport": contract.get("transport"),
        "mapping": contract.get("mapping"),
        "pagination": contract.get("pagination", {}),
        "request": {
            "method": request.get("method"),
            "url": request.get("url"),
            "base_url": request.get("base_url"),
            "base_url_env": request.get("base_url_env"),
            "path": request.get("path"),
            "auth_type": auth.get("type", "none"),
            "header_names": sorted((request.get("headers") or {}).keys()),
            "query_keys": sorted((request.get("query") or {}).keys()),
            "body_keys": sorted((request.get("body") or {}).keys()) if isinstance(request.get("body"), dict) else [],
        },
    }
    if file:
        summary["file"] = file
    if contract.get("transport") == "fixture":
        summary["fixture"] = {"path": (contract.get("fixture") or {}).get("path")}
    if contract.get("transport") == "tool":
        tool = contract.get("tool") if isinstance(contract.get("tool"), dict) else {}
        output = tool.get("output") if isinstance(tool.get("output"), dict) else {}
        summary["tool"] = {
            "name": tool.get("name"),
            "params_keys": sorted((tool.get("params") or {}).keys()) if isinstance(tool.get("params"), dict) else [],
            "output_items_path": output.get("items_path"),
            "wrap_items_as": output.get("wrap_items_as", "items"),
        }
    return summary


async def execute_adapter_contract(
    contract: dict[str, Any],
    *,
    base_dir: Path,
    http_client: Any | None = None,
    env: dict[str, str] | None = None,
) -> AdapterExecutionResult:
    validate_adapter_contract(contract)
    started = perf_counter()
    transport = str(contract["transport"])
    if transport == "fixture":
        result = _execute_fixture_adapter(contract, base_dir)
    elif transport == "http":
        result = await _execute_http_adapter(contract, http_client=http_client, env=env)
    else:
        result = await _execute_tool_adapter(contract, env=env)
    result.latency_ms = max(0, round((perf_counter() - started) * 1000))
    return result


async def preview_adapter_contract(
    connector_id: str,
    contract: dict[str, Any],
    *,
    base_dir: Path,
    contract_file: Path | None = None,
    http_client: Any | None = None,
    env: dict[str, str] | None = None,
) -> ConnectorPreviewResult:
    adapter = await execute_adapter_contract(contract, base_dir=base_dir, http_client=http_client, env=env)
    mapping_path = resolve_mapping_path(contract, base_dir)
    mapping_contract = load_mapping_contract(mapping_path)
    mapped = apply_mapping_contract(adapter.raw_response, mapping_contract, connector_id)
    warnings = [*adapter.warnings, *mapped.warnings]
    return ConnectorPreviewResult(
        connector_id=connector_id,
        capability=ConnectorCapability(str(contract["capability"])),
        success=True,
        source=adapter.source,
        raw_response=adapter.raw_response,
        normalized_data=mapped.mapping_result,
        mapping_result=mapped.mapping_result,
        adapter_contract=adapter_contract_summary(contract, file=str(contract_file) if contract_file else None),
        adapter_request=adapter.request_summary,
        mapping_contract={
            "version": mapping_contract["version"],
            "capability": mapping_contract["capability"],
            "target": mapping_contract["target"],
            "source": mapping_contract.get("source", {}),
            "required_fields": [
                field["target"]
                for field in mapping_contract.get("fields", [])
                if isinstance(field, dict) and field.get("required") is True
            ],
            "field_count": len(mapping_contract.get("fields", [])),
            "file": str(mapping_path),
        },
        warnings=warnings,
        missing_fields=mapped.missing_required_fields,
        missing_required_fields=mapped.missing_required_fields,
        unmapped_fields=mapped.unmapped_fields,
        transform_warnings=mapped.transform_warnings,
    )


def resolve_mapping_path(contract: dict[str, Any], base_dir: Path) -> Path:
    mapping = str(contract["mapping"])
    path = Path(mapping)
    if not path.is_absolute():
        path = base_dir / path
    if not path.is_file():
        raise ValueError(f"Mapping contract file not found: {path}")
    return path


def _execute_fixture_adapter(contract: dict[str, Any], base_dir: Path) -> AdapterExecutionResult:
    fixture = contract["fixture"]
    path = Path(str(fixture["path"]))
    if not path.is_absolute():
        path = base_dir / path
    if not path.is_file():
        raise ValueError(f"Fixture file not found: {path}")
    raw_response = json.loads(path.read_text(encoding="utf-8"))
    return AdapterExecutionResult(
        capability=str(contract["capability"]),
        source=f"fixture:{path.name}",
        raw_response=raw_response,
        adapter_contract=adapter_contract_summary(contract),
        request_summary={"transport": "fixture", "fixture": str(path)},
    )


async def _execute_http_adapter(
    contract: dict[str, Any],
    *,
    http_client: Any | None,
    env: dict[str, str] | None,
) -> AdapterExecutionResult:
    request = contract["request"]
    env_values = env if env is not None else os.environ
    method = str(request["method"]).upper()
    url = _build_url(request, env_values)
    headers = _resolve_dynamic(request.get("headers", {}), env_values)
    query = _resolve_dynamic(request.get("query", {}), env_values)
    body = _resolve_dynamic(request.get("body"), env_values)
    auth = request.get("auth") if isinstance(request.get("auth"), dict) else {"type": "none"}
    headers = _apply_auth(headers if isinstance(headers, dict) else {}, auth, env_values)
    request_kwargs = {"method": method, "url": url, "headers": headers}
    if isinstance(query, dict) and query:
        request_kwargs["params"] = query
    if body is not None:
        request_kwargs["json"] = body

    close_client = False
    client = http_client
    if client is None:
        import httpx

        client = httpx.AsyncClient(timeout=float(request.get("timeout_seconds", 30)))
        close_client = True
    try:
        response = await client.request(**request_kwargs)
        if hasattr(response, "raise_for_status"):
            response.raise_for_status()
        raw_response = response.json() if hasattr(response, "json") else json.loads(response.text)
    finally:
        if close_client and hasattr(client, "aclose"):
            await client.aclose()
    if not isinstance(raw_response, dict):
        raise ValueError("Adapter HTTP response JSON must be an object")
    return AdapterExecutionResult(
        capability=str(contract["capability"]),
        source=f"http:{method}:{url}",
        raw_response=raw_response,
        adapter_contract=adapter_contract_summary(contract),
        request_summary={
            "transport": "http",
            "method": method,
            "url": url,
            "auth_type": auth.get("type", "none"),
            "header_names": sorted(headers.keys()),
            "query_keys": sorted(query.keys()) if isinstance(query, dict) else [],
            "body_keys": sorted(body.keys()) if isinstance(body, dict) else [],
        },
    )


async def _execute_tool_adapter(
    contract: dict[str, Any],
    *,
    env: dict[str, str] | None,
) -> AdapterExecutionResult:
    tool_contract = contract["tool"]
    name = str(tool_contract["name"])
    env_values = env if env is not None else os.environ
    params = _resolve_dynamic(tool_contract.get("params", {}), env_values)
    if not isinstance(params, dict):
        raise ValueError("Tool adapter params must resolve to an object")

    from flocks.tool import ToolContext, ToolRegistry

    ToolRegistry.init()
    result = await ToolRegistry.execute(
        name,
        ctx=ToolContext(session_id="connector-sync", message_id=f"connector:{contract['capability']}"),
        **params,
    )
    if not result.success:
        raise ValueError(result.error or f"Tool adapter execution failed: {name}")
    output = _parse_tool_output(result.output)
    raw_response = _normalize_tool_output(output, tool_contract)
    return AdapterExecutionResult(
        capability=str(contract["capability"]),
        source=f"tool:{name}",
        raw_response=raw_response,
        adapter_contract=adapter_contract_summary(contract),
        request_summary={
            "transport": "tool",
            "tool": name,
            "param_keys": sorted(params.keys()),
            "metadata": result.metadata or {},
        },
    )


def _parse_tool_output(output: Any) -> Any:
    if isinstance(output, str):
        stripped = output.strip()
        if not stripped:
            return {}
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            restored = _read_truncated_tool_output(stripped)
            if restored is not None:
                return _parse_tool_output(restored)
            return {"text": output}
    return output


def _read_truncated_tool_output(text: str) -> str | None:
    """Load full ToolRegistry output when truncation stored it in workspace/tool-output."""
    match = _TRUNCATED_TOOL_OUTPUT_RE.search(text)
    if not match:
        return None

    try:
        from flocks.workspace.manager import WorkspaceManager

        output_dir = (WorkspaceManager.get_instance().get_workspace_dir() / "tool-output").resolve()
        output_path = Path(match.group("path").strip()).expanduser().resolve()
        output_path.relative_to(output_dir)
    except Exception:
        return None

    if not output_path.name.startswith("tool_") or not output_path.is_file():
        return None
    try:
        return output_path.read_text(encoding="utf-8")
    except OSError:
        return None


def _normalize_tool_output(output: Any, tool_contract: dict[str, Any]) -> dict[str, Any]:
    response = output if isinstance(output, dict) else {"items": output if isinstance(output, list) else [], "value": output}
    output_contract = tool_contract.get("output") if isinstance(tool_contract.get("output"), dict) else {}
    wrap_key = str(output_contract.get("wrap_items_as") or "items")
    item_paths = output_contract.get("items_path")
    if isinstance(item_paths, str):
        item_paths = [item_paths]
    if isinstance(item_paths, list):
        for item_path in item_paths:
            items = _get_path(response, str(item_path))
            if isinstance(items, list):
                return {wrap_key: items, "response": response}
    if isinstance(response.get(wrap_key), list):
        return response
    if isinstance(response.get("items"), list) and wrap_key != "items":
        return {wrap_key: response["items"], "response": response}
    return response


def _get_path(root: Any, path: str) -> Any:
    if path in ("", "$"):
        return root
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


def _build_url(request: dict[str, Any], env: dict[str, str]) -> str:
    if request.get("url"):
        return str(_resolve_dynamic(request["url"], env))
    base_url = request.get("base_url")
    if not base_url and request.get("base_url_env"):
        base_url = env.get(str(request["base_url_env"]))
    if not base_url:
        raise ValueError("HTTP adapter request base_url is empty")
    path = str(_resolve_dynamic(request.get("path", ""), env))
    return urljoin(str(base_url).rstrip("/") + "/", path.lstrip("/"))


def _apply_auth(headers: dict[str, Any], auth: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    auth_type = auth.get("type", "none")
    if auth_type in (None, "", "none"):
        return {str(key): str(value) for key, value in headers.items()}
    if auth_type == "bearer":
        token = _secret_value(auth, env, value_key="token", env_key="token_env")
        if not token:
            raise ValueError("HTTP adapter bearer auth token is missing")
        return {**{str(key): str(value) for key, value in headers.items()}, "Authorization": f"Bearer {token}"}
    if auth_type == "api_key_header":
        header = str(auth.get("header") or "X-API-Key")
        value = _secret_value(auth, env, value_key="value", env_key="value_env")
        if not value:
            raise ValueError(f"HTTP adapter API key header {header} is missing")
        return {**{str(key): str(value) for key, value in headers.items()}, header: value}
    raise ValueError(f"Unsupported HTTP adapter auth type: {auth_type}")


def _secret_value(auth: dict[str, Any], env: dict[str, str], *, value_key: str, env_key: str) -> str | None:
    if auth.get(value_key):
        return str(auth[value_key])
    if auth.get(env_key):
        return env.get(str(auth[env_key]))
    return None


def _resolve_dynamic(value: Any, env: dict[str, str]) -> Any:
    if isinstance(value, str):
        if value.startswith("${ENV:") and value.endswith("}"):
            return env.get(value[6:-1], "")
        return value
    if isinstance(value, list):
        return [_resolve_dynamic(item, env) for item in value]
    if isinstance(value, dict):
        return {str(key): _resolve_dynamic(nested, env) for key, nested in value.items()}
    return value
