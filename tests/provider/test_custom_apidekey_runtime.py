"""
测试 custom-apidekey provider 在运行时是否正确加载
"""

import pytest
from flocks.provider.provider import Provider
from flocks.server.routes.custom_provider import load_custom_providers_on_startup


@pytest.mark.asyncio
@pytest.mark.skip(reason="Environment-specific: custom-apidekey is not in the current flocks.json config")
async def test_load_custom_apidekey_provider():
    """测试加载 custom-apidekey provider"""
    # 初始化内置 providers
    await Provider.init()
    
    # 加载自定义 providers
    await load_custom_providers_on_startup()
    
    # 验证 custom-apidekey 已注册
    provider = Provider.get("custom-apidekey")
    assert provider is not None, "custom-apidekey provider should be registered"
    
    print(f"✅ Provider loaded: {provider.id}")
    print(f"✅ Provider name: {provider.name}")
    
    # 验证 provider 配置
    is_configured = provider.is_configured()
    print(f"✅ Provider configured: {is_configured}")
    
    # 获取模型列表
    models = provider.get_models()
    assert len(models) > 0, "Should have at least one model"
    
    model_ids = [m.id for m in models]
    print(f"✅ Available models: {model_ids}")
    
    # 验证 claude-sonnet-4-20250514 模型存在
    assert "claude-sonnet-4-20250514" in model_ids, "claude-sonnet-4-20250514 should be available"
    print(f"✅ Claude Sonnet 4 model is available")


@pytest.mark.asyncio
@pytest.mark.skip(reason="Environment-specific: custom-apidekey is not in the current flocks.json config")
async def test_custom_apidekey_ready_for_use():
    """测试 custom-apidekey provider 可以实际使用"""
    await Provider.init()
    await load_custom_providers_on_startup()
    
    provider = Provider.get("custom-apidekey")
    assert provider is not None
    
    # 测试是否配置正确
    assert provider.is_configured(), "Provider must be configured to use"
    
    # 获取模型
    models = provider.get_models()
    model = next((m for m in models if m.id == "claude-sonnet-4-20250514"), None)
    assert model is not None, "Target model should exist"
    
    # 验证模型能力
    assert model.capabilities.supports_tools is True, "Should support tools"
    assert model.capabilities.supports_streaming is True, "Should support streaming"
    
    print(f"✅ Provider: {provider.name}")
    print(f"✅ Model: {model.name}")
    print(f"✅ Supports tools: {model.capabilities.supports_tools}")
    print(f"✅ Supports streaming: {model.capabilities.supports_streaming}")
    print(f"✅ Context window: {model.capabilities.context_window}")
    print("✅ Ready for production use!")
