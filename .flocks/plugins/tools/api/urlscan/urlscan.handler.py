import base64
import os
from typing import Any, Tuple

import aiohttp

from flocks.config.config_writer import ConfigWriter
from flocks.security import get_secret_manager
from flocks.tool.registry import ToolContext, ToolResult


_BASE_URL = "https://urlscan.io"
_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)


def _resolve_api_key() -> str:
    raw_service = ConfigWriter.get_api_service_raw("urlscan") or {}
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

    secret_value = get_secret_manager().get("urlscan_api_key")
    if secret_value:
        return secret_value

    env_value = os.getenv("URLSCAN_API_KEY")
    if env_value:
        return env_value

    raise ValueError(
        "URLScan API key not found. Configure it in API service credentials "
        "or set URLSCAN_API_KEY."
    )


def _headers() -> dict[str, str]:
    return {"API-Key": _resolve_api_key()}


async def _fetch_bytes(path: str) -> Tuple[bool, dict[str, Any] | None, str | None]:
    try:
        headers = _headers()
    except ValueError as exc:
        return False, None, str(exc)

    try:
        async with aiohttp.ClientSession(timeout=_DEFAULT_TIMEOUT) as session:
            async with session.get(f"{_BASE_URL}{path}", headers=headers) as resp:
                resp.raise_for_status()
                content = await resp.read()
                content_type = resp.headers.get("Content-Type", "application/octet-stream")
    except aiohttp.ClientError as exc:
        return False, None, f"Request failed: {exc}"
    except Exception as exc:
        return False, None, f"Unexpected error: {exc}"

    payload: dict[str, Any] = {"content_type": content_type}
    try:
        payload["content"] = content.decode("utf-8")
        payload["encoding"] = "utf-8"
    except UnicodeDecodeError:
        payload["content_base64"] = base64.b64encode(content).decode("ascii")
        payload["encoding"] = "base64"

    return True, payload, None


async def screenshot(ctx: ToolContext, scan_id: str) -> ToolResult:
    ok, data, err = await _fetch_bytes(f"/screenshots/{scan_id}.png")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "urlscan", "api": "screenshots"},
    )


async def dom(ctx: ToolContext, scan_id: str) -> ToolResult:
    ok, data, err = await _fetch_bytes(f"/dom/{scan_id}/")
    if not ok:
        return ToolResult(success=False, error=err)

    return ToolResult(
        success=True,
        output=data,
        metadata={"source": "urlscan", "api": "dom"},
    )
