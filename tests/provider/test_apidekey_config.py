"""
测试 apidekey provider 配置
"""

import pytest
from flocks.config.config import Config
from flocks.agent.registry import Agent


@pytest.mark.asyncio
@pytest.mark.skip(reason="Environment-specific: custom-apidekey is not the current default provider")
async def test_apidekey_provider_configured():
    """验证 custom-apidekey provider 已正确配置"""
    config = await Config.get()
    
    # 验证默认模型已改为 custom-apidekey
    assert config.model is not None
    assert "custom-apidekey" in config.model.lower(), f"Expected custom-apidekey in model, got {config.model}"
    
    # 验证 provider 配置存在
    assert hasattr(config, 'provider')
    providers = config.provider if hasattr(config, 'provider') else {}
    assert 'custom-apidekey' in providers, f"custom-apidekey provider not found, available: {list(providers.keys())}"
    
    # 验证 custom-apidekey provider 配置正确
    apidekey_config = providers['custom-apidekey']
    assert hasattr(apidekey_config, 'options')
    assert apidekey_config.options.base_url == "https://apidekey.xyz"
    
    print(f"✅ Default model: {config.model}")
    print(f"✅ Provider baseURL: {apidekey_config.options.base_url}")


@pytest.mark.asyncio
@pytest.mark.skip(reason="Environment-specific: custom-apidekey is not the current default provider")
async def test_rex_uses_apidekey_by_default():
    """验证 Rex agent 使用 custom-apidekey 作为默认模型"""
    config = await Config.get()
    rex = await Agent.get("rex")
    
    assert rex is not None
    print(f"✅ Rex agent found: {rex.name}")
    
    # Rex 没有特定的 model 配置时，会使用系统默认模型
    # 系统默认模型应该是 custom-apidekey/claude-sonnet-4-20250514
    assert config.model == "custom-apidekey/claude-sonnet-4-20250514"
    print(f"✅ System default model (used by Rex): {config.model}")


@pytest.mark.asyncio
@pytest.mark.skip(reason="Environment-specific: custom-apidekey is not the current default provider")
async def test_apidekey_model_metadata():
    """验证 custom-apidekey 模型的元数据配置"""
    config = await Config.get()
    providers = config.provider if hasattr(config, 'provider') else {}
    
    apidekey_config = providers['custom-apidekey']
    models = apidekey_config.models
    
    assert 'claude-sonnet-4-20250514' in models
    model_config = models['claude-sonnet-4-20250514']
    
    # 验证关键配置
    assert model_config.context_window == 200000
    assert model_config.supports_tools is True
    assert model_config.supports_streaming is True
    
    print(f"✅ Model name: {model_config.name}")
    print(f"✅ Context window: {model_config.context_window}")
    print(f"✅ Supports tools: {model_config.supports_tools}")
    print(f"✅ Supports streaming: {model_config.supports_streaming}")
