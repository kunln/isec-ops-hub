"""
测试 Provider 未配置场景

这是一个改进的测试，能够发现真实的配置问题
"""

import pytest
from flocks.provider.provider import Provider


@pytest.mark.asyncio
async def test_all_configured_providers():
    """
    测试：检查所有 provider 的配置状态
    
    这个测试会失败如果有 provider 未配置但被使用
    """
    # List of providers that might be used
    providers_to_check = [
        "anthropic",
        "volcengine",
        "openai",
        "custom-threatbook-internal",
    ]
    
    configured_providers = []
    unconfigured_providers = []
    
    for name in providers_to_check:
        provider = Provider.get(name)
        if provider:
            if provider.is_configured():
                configured_providers.append(name)
            else:
                unconfigured_providers.append(name)
    
    print(f"\n✅ Configured providers: {configured_providers}")
    print(f"❌ Unconfigured providers: {unconfigured_providers}")
    
    # Check default provider from flocks.json
    from flocks.config.config import Config
    config = await Config.get()
    
    if hasattr(config, 'model') and config.model:
        print(f"\nDefault model from flocks.json: {config.model}")
        
        # Parse provider from model string
        if "/" in config.model:
            provider_part = config.model.split("/")[0]
            print(f"Provider part: {provider_part}")
            
            # Check if this provider is configured
            provider = Provider.get(provider_part)
            if provider:
                is_configured = provider.is_configured()
                print(f"Default provider '{provider_part}' is configured: {is_configured}")
                
                if not is_configured:
                    pytest.fail(
                        f"Default provider '{provider_part}' is NOT configured! "
                        f"This will cause CLI to have no response. "
                        f"Please configure the provider or change the default model."
                    )


@pytest.mark.asyncio
async def test_cli_will_show_warning_for_unconfigured_provider():
    """
    测试：验证 CLI 在 provider 未配置时会显示警告
    
    这确保用户能看到错误信息，而不是空响应
    """
    from pathlib import Path
    from rich.console import Console
    from flocks.cli.session_runner import CLISessionRunner
    from unittest.mock import patch, MagicMock
    
    console = Console()
    runner = CLISessionRunner(
        console=console,
        directory=Path("/tmp/test"),
        model="volcengine/glm-4",  # Use unconfigured provider
        agent="rex",
        auto_confirm=True,
    )
    
    # Mock session
    runner._session = MagicMock()
    runner._session.id = "test_session"
    
    # Track console output
    console_output = []
    original_print = runner.console.print
    runner.console.print = lambda *args, **kwargs: console_output.append(str(args[0]) if args else "")
    
    # Mock message creation and SessionLoop
    with patch('flocks.session.message.Message.create'):
        with patch('flocks.session.session_loop.SessionLoop.run') as mock_run:
            mock_run.return_value = MagicMock(action="stop", message="OK")
            
            await runner._process_message("test query")
    
    # Check if warning was displayed
    all_output = " ".join(console_output).lower()
    
    print(f"\nConsole output:\n{'='*60}")
    for line in console_output:
        print(line)
    print("="*60)
    
    has_warning = any(
        "not configured" in line.lower() or 
        "warning" in line.lower() 
        for line in console_output
    )
    
    assert has_warning, (
        "CLI should show warning when provider is not configured. "
        "Without this warning, users see empty responses and don't know why."
    )


@pytest.mark.asyncio
async def test_cli_will_show_error_on_api_failure():
    """
    测试：验证 CLI 在 API 调用失败时会显示错误
    
    模拟 LLM API 调用失败的场景
    """
    from pathlib import Path
    from rich.console import Console
    from flocks.cli.session_runner import CLISessionRunner
    from unittest.mock import patch, MagicMock
    
    console = Console()
    runner = CLISessionRunner(
        console=console,
        directory=Path("/tmp/test"),
        model="volcengine/glm-4",
        agent="rex",
        auto_confirm=True,
    )
    
    # Mock session
    runner._session = MagicMock()
    runner._session.id = "test_session"
    
    # Track console output
    console_output = []
    runner.console.print = lambda *args, **kwargs: console_output.append(str(args[0]) if args else "")
    
    # Mock SessionLoop to raise exception (simulating API failure)
    with patch('flocks.session.message.Message.create'):
        with patch('flocks.session.session_loop.SessionLoop.run') as mock_run:
            mock_run.side_effect = Exception("Provider API call failed: 401 Unauthorized")
            
            # Should not raise - error should be caught and displayed
            await runner._process_message("test query")
    
    # Check if error was displayed
    all_output = " ".join(console_output).lower()
    
    print(f"\nConsole output:\n{'='*60}")
    for line in console_output:
        print(line)
    print("="*60)
    
    has_error = any(
        "error" in line.lower() or 
        "fail" in line.lower() or
        "401" in line
        for line in console_output
    )
    
    assert has_error, (
        "CLI should show error when API call fails. "
        "Without error display, users see empty responses and don't know what went wrong."
    )


if __name__ == "__main__":
    # Run tests
    import asyncio
    asyncio.run(test_all_configured_providers())
    asyncio.run(test_cli_will_show_warning_for_unconfigured_provider())
    asyncio.run(test_cli_will_show_error_on_api_failure())
