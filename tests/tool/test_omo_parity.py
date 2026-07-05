"""
Parity checks for Oh-My-Flocks integration.
"""

import pytest

from flocks.tool import ToolRegistry


class TestOmoToolParity:
    """Minimal parity checks for background tools."""

    def test_background_tools_registered(self):
        tools = ToolRegistry.all_tool_ids()
        assert "background_output" in tools
        assert "background_cancel" in tools
