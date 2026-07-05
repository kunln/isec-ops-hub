import base64
import os
from pathlib import Path
from typing import Any, Tuple

import aiohttp

from flocks.config.config_writer import ConfigWriter
from flocks.security import get_secret_manager
from flocks.tool.registry import ToolContext, ToolResult


_BASE_URL = "https://www.virustotal.com/api/v3"
_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)


def _resolve_api_key() -> str:
    raw_service = ConfigWriter.get_api_service_raw("virustotal") or {}
    api_key_ref = raw_service.get("apiKey") or raw_service.get("authentication", {}).get("key")

    if isinstance(api_key_ref, str):
        if api_key_ref.startswith("{secret:") and api_key_ref.endswith("}"):
            secret_id = api_key_ref[len("{secret:"):-1]
            secret_value = get_secret_manager().get(secret_id)
            if secret_value:
                return secret_value
        elif api_key_ref.startswith("{env:") and api_key_ref.endswith("}"):
            env_name = api_key_ref[len("{env:"):-1]
            env_value = os.getenv(env_name)
            if env_value:
                return env_value
        elif api_key_ref:
            return api_key_ref

    secret_value = get_secret_manager().get("virustotal_api_key")
    if secret_value:
        return secret_value

    env_value = os.getenv("VIRUSTOTAL_API_KEY")
    if env_value:
        return env_value

    raise ValueError(
        "VirusTotal API key not found. Configure it in API service credentials "
        "or set VIRUSTOTAL_API_KEY."
    )


def _headers() -> dict[str, str]:
    return {"x-apikey": _resolve_api_key(), "Accept": "application/json"}


def _url_to_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


async def _api_get(path: str, api_name: str) -> Tuple[bool, Any, str | None]:
    try:
        headers = _headers()
    except ValueError as exc:
        return False, None, str(exc)

    try:
        async with aiohttp.ClientSession(timeout=_DEFAULT_TIMEOUT) as session:
            async with session.get(f"{_BASE_URL}{path}", headers=headers) as resp:
                data = await resp.json(content_type=None)
                if resp.status == 404:
                    return True, data, None
                resp.raise_for_status()
    except aiohttp.ClientError as exc:
        return False, None, f"Request failed: {exc}"
    except Exception as exc:
        return False, None, f"Unexpected error: {exc}"

    return True, data, None


async def ip_query(ctx: ToolContext, ip: str) -> ToolResult:
    ok, data, err = await _api_get(f"/ip_addresses/{ip}", "ip_addresses")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "VirusTotal", "api": "ip_addresses"},
    )


async def domain_query(ctx: ToolContext, domain: str) -> ToolResult:
    ok, data, err = await _api_get(f"/domains/{domain}", "domains")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "VirusTotal", "api": "domains"},
    )


async def file_query(ctx: ToolContext, file_hash: str) -> ToolResult:
    ok, data, err = await _api_get(f"/files/{file_hash}", "files")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "VirusTotal", "api": "files"},
    )


async def url_query(ctx: ToolContext, url: str) -> ToolResult:
    ok, data, err = await _api_get(f"/urls/{_url_to_id(url)}", "urls")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "VirusTotal", "api": "urls"},
    )


async def url_scan(ctx: ToolContext, url: str) -> ToolResult:
    try:
        headers = {
            "x-apikey": _resolve_api_key(),
            "Content-Type": "application/x-www-form-urlencoded",
        }
    except ValueError as exc:
        return ToolResult(success=False, error=str(exc))

    try:
        async with aiohttp.ClientSession(timeout=_DEFAULT_TIMEOUT) as session:
            async with session.post(f"{_BASE_URL}/urls", headers=headers, data={"url": url}) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"Request failed: {exc}")
    except Exception as exc:
        return ToolResult(success=False, error=f"Unexpected error: {exc}")

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "VirusTotal", "api": "urls-scan"},
    )


async def file_scan(ctx: ToolContext, file_path: str) -> ToolResult:
    try:
        api_key = _resolve_api_key()
    except ValueError as exc:
        return ToolResult(success=False, error=str(exc))

    path = Path(file_path)
    if not path.exists():
        return ToolResult(success=False, error=f"File not found: {file_path}")

    if path.stat().st_size > 32 * 1024 * 1024:
        return ToolResult(success=False, error="File too large. Maximum 32MB allowed.")

    try:
        async with aiohttp.ClientSession(timeout=_DEFAULT_TIMEOUT) as session:
            with path.open("rb") as file_handle:
                data = aiohttp.FormData()
                data.add_field("file", file_handle, filename=path.name)
                async with session.post(f"{_BASE_URL}/files", headers={"x-apikey": api_key}, data=data) as resp:
                    resp.raise_for_status()
                    result = await resp.json(content_type=None)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"Request failed: {exc}")
    except Exception as exc:
        return ToolResult(success=False, error=f"Unexpected error: {exc}")

    return ToolResult(
        success=True,
        output=result,
        metadata={"source": "VirusTotal", "api": "files-scan"},
    )


async def analysis_status(ctx: ToolContext, analysis_id: str) -> ToolResult:
    ok, data, err = await _api_get(f"/analyses/{analysis_id}", "analyses")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "VirusTotal", "api": "analyses"},
    )
