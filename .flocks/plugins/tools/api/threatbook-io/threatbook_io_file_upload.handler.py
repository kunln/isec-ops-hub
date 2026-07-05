import os
from pathlib import Path

import aiohttp

from flocks.security import get_secret_manager
from flocks.tool.registry import ToolContext, ToolResult

async def file_upload(
    ctx: ToolContext,
    file_path: str,
    sandbox_type: str = "win7_sp1_enx86_office2013",
    run_time: int = 60
) -> ToolResult:
    file_path_obj = Path(file_path).expanduser()
    if not file_path_obj.exists():
        return ToolResult(success=False, error=f"File not found: {file_path_obj}")

    file_size = os.path.getsize(file_path_obj)
    if file_size > 100 * 1024 * 1024:
        return ToolResult(success=False, error="File size exceeds 100MB limit")

    sm = get_secret_manager()
    api_key = sm.get("threatbook_io_api_key")

    if not api_key:
        return ToolResult(success=False, error="API key not configured. Please set threatbook_io_api_key.")

    base_url = "https://api.threatbook.io"

    try:
        async with aiohttp.ClientSession() as session:
            url = f"{base_url}/v2/file/upload"
            params = {"apikey": api_key, "sandbox_type": sandbox_type, "run_time": run_time}
            data = aiohttp.FormData()
            with file_path_obj.open("rb") as fp:
                data.add_field("file", fp, filename=file_path_obj.name)

                async with session.post(url, params=params, data=data) as resp:
                    result = await resp.json()
                    response_code = result.get("response_code")

                    if response_code == 200:
                        return ToolResult(success=True, output=result.get("data", {}))
                    if response_code == 202:
                        return ToolResult(success=True, output={"status": "in_progress", "msg": result.get("msg")})
                    if response_code == 206:
                        return ToolResult(success=True, output={"status": "partial", "msg": result.get("msg")})
                    return ToolResult(success=False, error=f"API error: {result.get('msg')}")
    except Exception as e:
        return ToolResult(success=False, error=str(e))
