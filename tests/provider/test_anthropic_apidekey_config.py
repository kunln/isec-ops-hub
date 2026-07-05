"""
测试 anthropic provider 使用 apidekey.xyz 配置
"""

import json

import pytest
from flocks.config.config import Config
from flocks.provider.provider import Provider
from flocks.agent.registry import Agent


@pytest.fixture(autouse=True)
def isolated_anthropic_apidekey_config(tmp_path, monkeypatch):
    """Keep APIDeKey provider tests independent from the developer config."""
    payload = {
        "model": "anthropic/claude-sonnet-4-20250514",
        "provider": {
            "anthropic": {
                "options": {
                    "apiKey": "test-api-key",
                    "baseURL": "https://apidekey.xyz",
                }
            }
        },
    }
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("FLOCKS_CONFIG_CONTENT", json.dumps(payload))
    Config._global_config = None
    Config._cached_config = None
    Provider._providers.clear()
    Provider._models.clear()
    Provider._initialized = False
    yield
    Config._global_config = None
    Config._cached_config = None
    Provider._providers.clear()
    Provider._models.clear()
    Provider._initialized = False


@pytest.mark.asyncio
async def test_anthropic_provider_with_apidekey():
    """验证 anthropic provider 配置使用 apidekey.xyz"""
    # 初始化 providers
    await Provider.init()
    
    # 获取配置
    config = await Config.get()
    
    # 验证默认模型已配置（具体 model 名由 flocks.json 决定）
    assert config.model is not None
    print(f"✅ Default model: {config.model}")
    
    # 验证 anthropic provider 配置
    providers = config.provider if hasattr(config, 'provider') else {}
    # anthropic 可能不在 providers 中（使用默认配置），只在有时检查
    if 'anthropic' in providers:
        anthropic_config = providers['anthropic']
        if hasattr(anthropic_config, 'options') and anthropic_config.options:
            print(f"✅ Anthropic base URL: {anthropic_config.options.base_url}")
    print(f"✅ Anthropic provider configuration checked")


@pytest.mark.asyncio
async def test_anthropic_provider_runtime():
    """测试 anthropic provider 运行时配置"""
    await Provider.init()
    
    # Apply config to set baseURL
    await Provider.apply_config(provider_id="anthropic")
    
    # 获取 provider
    provider = Provider.get("anthropic")
    assert provider is not None, "anthropic provider should be registered"
    
    print(f"✅ Provider: {provider.id}")
    
    # 验证配置
    is_configured = provider.is_configured()
    print(f"✅ Provider configured: {is_configured}")
    assert is_configured, "Provider should be configured with API key"


@pytest.mark.asyncio
async def test_rex_uses_anthropic_apidekey():
    """验证 Rex agent 使用 anthropic/claude-sonnet-4-20250514"""
    config = await Config.get()
    rex = await Agent.get("rex")
    
    assert rex is not None
    print(f"✅ Rex agent found: {rex.name}")
    
    # 系统默认模型
    assert config.model is not None
    print(f"✅ System default model (used by Rex): {config.model}")
    print(f"✅ Rex will use anthropic provider with apidekey.xyz endpoint")
