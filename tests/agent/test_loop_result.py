"""
测试 LoopResult 结构
"""

import pytest
from flocks.session.session_loop import LoopResult


def test_loop_result_attributes():
    """验证 LoopResult 有正确的属性"""
    result = LoopResult(
        action="stop",
        last_message=None,
        error=None,
    )
    
    # 应该有这些属性
    assert hasattr(result, 'action')
    assert hasattr(result, 'last_message')
    assert hasattr(result, 'error')
    assert hasattr(result, 'metadata')
    
    # 不应该有 message 属性
    assert not hasattr(result, 'message')
    
    # 验证值
    assert result.action == "stop"
    assert result.last_message is None
    assert result.error is None


def test_loop_result_with_message():
    """验证 LoopResult 可以接受 last_message"""
    from unittest.mock import MagicMock
    
    mock_message = MagicMock()
    mock_message.id = "test_123"
    
    result = LoopResult(
        action="stop",
        last_message=mock_message,
    )
    
    assert result.last_message is not None
    assert result.last_message.id == "test_123"
