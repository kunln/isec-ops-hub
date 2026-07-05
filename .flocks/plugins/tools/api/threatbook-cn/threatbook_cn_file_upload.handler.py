import os
import aiohttp
import asyncio
from pathlib import Path
from flocks.tool.registry import ToolContext, ToolResult
from flocks.security import get_secret_manager


async def file_upload(ctx: ToolContext, file_path: str, sandbox_type: str = "win7_sp1_enx86_office2013", run_time: int = 60) -> ToolResult:
    """
    Upload a file to ThreatBook sandbox for analysis.
    """
    sm = get_secret_manager()
    api_key = sm.get("threatbook_cn_api_key")
    
    if not api_key:
        return ToolResult(success=False, error="API key not configured. Please set threatbook_cn_api_key.")
    
    file_path = Path(file_path).expanduser()
    if not file_path.exists():
        return ToolResult(success=False, error=f"File not found: {file_path}")
    
    file_size = os.path.getsize(file_path)
    if file_size > 100 * 1024 * 1024:
        return ToolResult(success=False, error="File size exceeds 100MB limit")
    
    url = "https://api.threatbook.cn/v3/file/upload"
    
    form_data = aiohttp.FormData()
    form_data.add_field('apikey', api_key)
    form_data.add_field('sandbox_type', sandbox_type)
    form_data.add_field('run_time', str(run_time))
    form_data.add_field('file', open(file_path, 'rb'), filename=file_path.name)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                result = await resp.json()
                
                if result.get("response_code") == 0:
                    data = result.get("data", {})
                    return ToolResult(success=True, output={
                        "sha256": data.get("sha256"),
                        "permalink": data.get("permalink"),
                        "message": "File submitted successfully. Check the permalink for the full report."
                    })
                else:
                    return ToolResult(success=False, error=f"API error: {result.get('verbose_msg', 'Unknown error')}")
    except Exception as e:
        return ToolResult(success=False, error=f"Upload failed: {str(e)}")
