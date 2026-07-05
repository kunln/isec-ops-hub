"""
Invalid Tool - Handles invalid tool calls

This tool is called when a tool call fails to parse or has invalid arguments.
It returns an error message to the LLM so it can retry with correct arguments.

Based on Flocks' ported src/tool/invalid.ts
"""

from flocks.tool.registry import (
    ToolRegistry, ToolCategory, ToolParameter, ParameterType, ToolResult, ToolContext
)
from flocks.utils.log import Log


log = Log.create(service="tool.invalid")


DESCRIPTION = """This tool is called internally when a tool call has invalid arguments.
Do not call this tool directly. If you see this error, please retry the original tool
with corrected arguments that satisfy the expected schema."""


@ToolRegistry.register_function(
    name="invalid",
    description=DESCRIPTION,
    category=ToolCategory.SYSTEM,
    parameters=[
        ToolParameter(
            name="tool",
            type=ParameterType.STRING,
            description="The name of the tool that was called with invalid arguments",
            required=True
        ),
        ToolParameter(
            name="error",
            type=ParameterType.STRING,
            description="The error message describing why the arguments are invalid",
            required=True
        ),
        ToolParameter(
            name="arguments_preview",
            type=ParameterType.STRING,
            description="Preview of the malformed arguments that failed to parse",
            required=False
        ),
    ]
)
async def invalid_tool(
    ctx: ToolContext,
    tool: str,
    error: str,
    arguments_preview: str = "",
) -> ToolResult:
    """
    Handle invalid tool calls
    
    This tool is called when:
    1. Tool call JSON arguments fail to parse
    2. Tool call has schema validation errors
    3. Tool name is not recognized
    
    Args:
        ctx: Tool context
        tool: Name of the original tool
        error: Error message
        arguments_preview: Preview of the malformed arguments
        
    Returns:
        ToolResult with error message for LLM to retry
    """
    log.warn("invalid_tool.called", {
        "original_tool": tool,
        "error": error,
        "has_preview": bool(arguments_preview),
        "preview_length": len(arguments_preview) if arguments_preview else 0,
    })
    
    # Detect truncation-related errors (set by runner when finish_reason is "length")
    is_truncation = "truncated" in error.lower() or "finish_reason" in error.lower()

    if is_truncation:
        error_message = f"""The tool call for '{tool}' failed because the model output was truncated before the tool arguments were complete.

Error: {error}

**How to fix this:**
1. REDUCE content size — do NOT repeat the same large content. Write a shorter / simplified version.
2. SPLIT into multiple calls — e.g. write the file in sections using several write calls with append mode, or break the task into smaller steps.
3. SIMPLIFY — if the content is generated JSON/code, produce a minimal working version first, then extend incrementally.

Do NOT simply retry with the same content — it will be truncated again."""
    else:
        error_message = f"""The arguments provided to the tool '{tool}' are invalid.

Error: {error}

Please rewrite the input so it satisfies the expected schema and try again.
Use the correct tool name and ensure all required parameters are provided with valid values."""

    # Add arguments preview if available
    if arguments_preview:
        error_message += f"""

Arguments Preview (first 500 chars):
{arguments_preview[:500]}

Common issues:
1. Unterminated strings - Check if all quotes are properly closed
2. Unclosed braces/brackets - Ensure {{ }} and [ ] are balanced
3. Invalid JSON syntax - Verify commas, colons, and structure
4. Incorrect parameter names - Check the tool's schema for required parameters"""

    return ToolResult(
        success=False,
        title="Invalid Tool Call",
        output=error_message,
        error=f"Invalid arguments for tool '{tool}': {error}",
        metadata={
            "original_tool": tool,
            "error": error,
            "arguments_preview": arguments_preview[:200] if arguments_preview else None,
        }
    )
