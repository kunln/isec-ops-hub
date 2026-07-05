"""
测试 CLI 错误处理和诊断

验证 CLI 在各种错误情况下能正确显示错误信息
"""

import pytest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from rich.console import Console

from flocks.cli.session_runner import CLISessionRunner
from flocks.agent import Agent


@pytest.mark.asyncio
async def test_cli_shows_provider_not_configured_warning():
    """
    测试：Provider 未配置时，CLI 应该显示警告
    
    这是之前缺失的功能，导致用户看不到为什么没有响应
    """
    # 临时清除 API key
    original_key = os.environ.pop("ANTHROPIC_API_KEY", None)
    
    try:
        runner = CLISessionRunner(
            console=Console(),
            directory=Path("/tmp/test"),
            agent="rex",
            model="claude-sonnet-4",
            auto_confirm=True,
        )
        
        # Mock session
        runner._session = MagicMock()
        runner._session.id = "test_session"
        
        # Mock console to capture output
        console_prints = []
        original_print = runner.console.print
        runner.console.print = lambda *args, **kwargs: console_prints.append((args, kwargs))
        
        # Process message with unconfigured provider
        with patch('flocks.provider.provider.Provider.get') as mock_provider_get:
            mock_provider = MagicMock()
            mock_provider.is_configured.return_value = False
            mock_provider_get.return_value = mock_provider
            
            with patch('flocks.session.message.Message.create'):
                with patch('flocks.session.session_loop.SessionLoop.run') as mock_run:
                    mock_run.return_value = MagicMock(action="stop", message="OK")
                    
                    await runner._process_message("test message")
        
        # Verify warning was printed
        warning_found = False
        for args, kwargs in console_prints:
            if args and "not configured" in str(args[0]).lower():
                warning_found = True
                break
        
        assert warning_found, "Should show provider not configured warning"
        
    finally:
        # Restore API key
        if original_key:
            os.environ["ANTHROPIC_API_KEY"] = original_key


@pytest.mark.asyncio
async def test_cli_shows_session_loop_error():
    """
    测试：SessionLoop 返回错误时，CLI 应该显示错误信息
    """
    runner = CLISessionRunner(
        console=Console(),
        directory=Path("/tmp/test"),
        agent="rex",
        model="claude-sonnet-4",
        auto_confirm=True,
    )
    
    # Mock session
    runner._session = MagicMock()
    runner._session.id = "test_session"
    
    # Mock console to capture output
    console_prints = []
    runner.console.print = lambda *args, **kwargs: console_prints.append((args, kwargs))
    
    # Mock SessionLoop to return error
    with patch('flocks.provider.provider.Provider.get') as mock_provider_get:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = True
        mock_provider_get.return_value = mock_provider
        
        with patch('flocks.session.message.Message.create'):
            with patch('flocks.session.session_loop.SessionLoop.run') as mock_run:
                # Return error result
                mock_run.return_value = MagicMock(
                    action="error",
                    message="API call failed: 401 Unauthorized"
                )
                
                await runner._process_message("test message")
    
    # Verify error was printed
    error_found = False
    for args, kwargs in console_prints:
        if args and "error" in str(args[0]).lower():
            error_found = True
            break
    
    assert error_found, "Should show session loop error"


@pytest.mark.asyncio
async def test_cli_handles_exception():
    """
    测试：处理消息时抛出异常，CLI 应该捕获并显示
    """
    runner = CLISessionRunner(
        console=Console(),
        directory=Path("/tmp/test"),
        agent="rex",
        model="claude-sonnet-4",
        auto_confirm=True,
    )
    
    # Mock session
    runner._session = MagicMock()
    runner._session.id = "test_session"
    
    # Mock console to capture output
    console_prints = []
    runner.console.print = lambda *args, **kwargs: console_prints.append((args, kwargs))
    
    # Mock SessionLoop to raise exception
    with patch('flocks.provider.provider.Provider.get') as mock_provider_get:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = True
        mock_provider_get.return_value = mock_provider
        
        with patch('flocks.session.message.Message.create'):
            with patch('flocks.session.session_loop.SessionLoop.run') as mock_run:
                # Raise exception
                mock_run.side_effect = Exception("Network timeout")
                
                # Should not raise, should catch and display
                await runner._process_message("test message")
    
    # Verify exception was displayed
    exception_found = False
    for args, kwargs in console_prints:
        if args and ("error" in str(args[0]).lower() or "timeout" in str(args[0]).lower()):
            exception_found = True
            break
    
    assert exception_found, "Should show exception message"


@pytest.mark.asyncio
async def test_provider_configuration_check():
    """
    测试：验证不同 provider 的配置状态
    """
    from flocks.provider.provider import Provider
    
    # Test anthropic
    anthropic = Provider.get("anthropic")
    assert anthropic is not None
    
    # Check if configured (depends on env)
    is_configured = anthropic.is_configured()
    print(f"Anthropic configured: {is_configured}")
    
    # Test custom provider
    custom = Provider.get("custom-threatbook-internal")
    if custom:
        print(f"Custom provider configured: {custom.is_configured()}")
