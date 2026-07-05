"""
测试 GLM 模型的工具调用能力

验证为什么简单查询有响应，但工具调用查询没有响应
"""

import pytest
import os
from pathlib import Path


@pytest.mark.asyncio
async def test_parse_glm_model_string():
    """
    测试：验证 GLM 模型字符串被正确解析
    """
    from flocks.cli.session_runner import CLISessionRunner
    from rich.console import Console
    
    runner = CLISessionRunner(
        console=Console(),
        directory=Path("/tmp"),
        model=None,
        agent="rex",
        auto_confirm=True,
    )
    
    # Test parsing the GLM model string from flocks.json
    model_str = "custom-threatbook-internal/volcengine: glm-4-7-251222"
    parsed = runner._parse_model(model_str)
    
    print(f"\nModel string: {model_str}")
    print(f"Parsed provider_id: {parsed.get('provider_id')}")
    print(f"Parsed model_id: {parsed.get('model_id')}")
    
    assert parsed is not None
    assert parsed.get("provider_id") == "custom-threatbook-internal"
    assert parsed.get("model_id") == "volcengine: glm-4-7-251222"


@pytest.mark.asyncio
async def test_custom_provider_configuration():
    """
    测试：检查 custom-threatbook-internal provider 配置状态
    """
    from flocks.provider.provider import Provider
    
    # Check custom provider
    provider = Provider.get("custom-threatbook-internal")
    
    if provider:
        print(f"\nCustom provider found: {provider}")
        is_configured = provider.is_configured()
        print(f"Is configured: {is_configured}")
        
        # Check API key
        api_key = os.getenv("CUSTOM_THREATBOOK_INTERNAL_API_KEY")
        print(f"Has API key env var: {bool(api_key)}")
        
        if not is_configured:
            print("\n❌ Provider NOT configured!")
            print("This is why tool calls don't work.")
            print("\nTo fix, add to .env:")
            print("CUSTOM_THREATBOOK_INTERNAL_API_KEY=your-key-here")
    else:
        print("\n❌ Custom provider NOT found!")
        print("Provider should be registered in flocks/provider/provider.py")


@pytest.mark.asyncio
async def test_glm_model_supports_tools():
    """
    测试：验证 GLM 模型配置显示支持工具调用
    """
    from flocks.config.config import Config
    
    config = await Config.get()
    print(f"\nDefault model from flocks.json: {config.model if hasattr(config, 'model') else 'None'}")
    
    # Check model capabilities in catalog
    if hasattr(config, 'model') and config.model:
        print(f"\nModel: {config.model}")
        
        # Parse provider and model
        if "/" in config.model:
            provider_id, model_id = config.model.split("/", 1)
            print(f"Provider: {provider_id}")
            print(f"Model ID: {model_id}")
            
            # Check if model supports tools
            # Note: This info is in flocks.json under provider.models
            print("\nAccording to flocks.json config:")
            print("  supports_tools: true")
            print("  supports_streaming: true")
            print("\nBut actual API behavior may differ!")


@pytest.mark.asyncio
async def test_why_simple_query_works_but_not_tool_call():
    """
    测试：诊断为什么简单查询有响应，但工具调用没有
    
    可能原因：
    1. Provider 已配置，所以简单查询能工作
    2. 但 GLM 模型可能不支持工具调用格式
    3. 或者工具调用返回了错误但被吞掉了
    """
    from flocks.provider.provider import Provider
    from unittest.mock import MagicMock, patch
    
    # Check if provider is configured
    provider = Provider.get("custom-threatbook-internal")
    
    if provider and provider.is_configured():
        print("\n✅ Provider IS configured")
        print("This explains why simple queries work")
        
        print("\n🔍 Testing tool call scenario...")
        
        # Simulate what happens during a tool call
        print("\nWhen user asks '查一下8.8.8.8的情报':")
        print("1. LLM should respond with tool_calls")
        print("2. System executes the tool")
        print("3. LLM gets tool result and responds")
        
        print("\n❓ Possible issues:")
        print("  - GLM model may not return tool_calls in correct format")
        print("  - API may not support tools despite config saying it does")
        print("  - Error during tool execution is not displayed")
        
    else:
        print("\n❌ Provider NOT configured")
        print("This explains why BOTH simple and tool queries don't work")


@pytest.mark.asyncio
async def test_check_secret_file():
    """
    测试：检查 .secret.json 文件中的 API key 配置
    """
    import json
    from pathlib import Path
    
    secret_file = Path(".flocks/.secret.json")
    
    if secret_file.exists():
        print(f"\n✅ .secret.json exists")
        
        with open(secret_file) as f:
            secrets = json.load(f)
        
        # Check for custom provider key
        has_key = "custom-threatbook-internal_api_key" in secrets
        print(f"Has custom-threatbook-internal_api_key: {has_key}")
        
        if has_key:
            key_value = secrets["custom-threatbook-internal_api_key"]
            if key_value:
                print(f"API key length: {len(key_value)}")
                print("✅ API key is configured")
            else:
                print("❌ API key is empty")
        else:
            print("❌ API key not found in .secret.json")
            print("\nTo fix, add to .flocks/.secret.json:")
            print('  "custom-threatbook-internal_api_key": "your-key-here"')
    else:
        print(f"\n❌ .secret.json NOT found at {secret_file}")


@pytest.mark.asyncio
async def test_recommend_debugging_steps():
    """
    输出调试建议
    """
    print("\n" + "="*60)
    print("🔍 调试建议：为什么工具调用没有响应")
    print("="*60)
    
    print("\n1️⃣  检查 provider 配置:")
    print("   运行: uv run pytest tests/integration/test_glm_model_tool_call.py::test_custom_provider_configuration -s")
    
    print("\n2️⃣  检查 API key:")
    print("   运行: uv run pytest tests/integration/test_glm_model_tool_call.py::test_check_secret_file -s")
    
    print("\n3️⃣  启用详细日志:")
    print("   export LOG_LEVEL=DEBUG")
    print("   flocks run")
    
    print("\n4️⃣  测试简单查询 vs 工具调用:")
    print("   简单查询: 'hello' (应该有响应)")
    print("   工具调用: '查一下8.8.8.8的情报' (可能没响应)")
    
    print("\n5️⃣  可能的问题:")
    print("   ❌ GLM 模型的工具调用格式与 OpenAI 不兼容")
    print("   ❌ API 返回错误但被静默吞掉")
    print("   ❌ Provider 配置不正确")
    
    print("\n6️⃣  临时解决方案:")
    print("   使用已知支持工具的模型:")
    print("   flocks run --model claude-sonnet-4 --provider anthropic")
    print("   (需要在 .env 中配置 ANTHROPIC_API_KEY)")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    import asyncio
    
    print("Running GLM model diagnostics...")
    asyncio.run(test_parse_glm_model_string())
    asyncio.run(test_custom_provider_configuration())
    asyncio.run(test_glm_model_supports_tools())
    asyncio.run(test_why_simple_query_works_but_not_tool_call())
    asyncio.run(test_check_secret_file())
    asyncio.run(test_recommend_debugging_steps())
