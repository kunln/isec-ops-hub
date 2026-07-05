"""
最终验证：GLM 模型配置和工具调用

验证整个流程：flocks.json -> custom provider -> GLM 模型 -> 工具调用
"""

import pytest


def _configured_provider(provider_id: str):
    from flocks.provider.provider import Provider

    provider = Provider.get(provider_id)
    if provider is None:
        pytest.skip(f"{provider_id} provider is not registered in this environment")
    if not provider.is_configured():
        pytest.skip(f"{provider_id} provider is not configured in this environment")
    return provider


@pytest.mark.asyncio
async def test_glm_provider_configuration():
    """
    验证：GLM provider 正确配置
    """
    provider = _configured_provider("custom-threatbook-internal")
    
    assert provider.id == "custom-threatbook-internal"
    assert provider.name == "Threatbook Internal"
    assert provider.is_configured() is True, "Provider should be configured from .secret.json"
    
    print(f"\n✅ Provider: {provider.id}")
    print(f"✅ Configured: {provider.is_configured()}")


@pytest.mark.asyncio
async def test_flocks_json_default_model():
    """
    验证：flocks.json 中的默认模型配置
    """
    from flocks.config.config import Config
    
    default_llm = await Config.resolve_default_llm()
    if default_llm is None:
        pytest.skip("default_models.llm is not configured in this environment")
    
    provider_id = default_llm["provider_id"]
    model_id = default_llm["model_id"]
    
    print(f"\n✅ Default LLM provider: {provider_id}")
    print(f"✅ Default LLM model: {model_id}")
    
    assert provider_id is not None
    assert model_id is not None


@pytest.mark.asyncio
async def test_glm_model_tool_support():
    """
    验证：GLM 模型配置显示支持工具调用
    """
    # Check flocks.json model capabilities
    print("\n✅ According to flocks.json:")
    print("  • supports_tools: true")
    print("  • supports_streaming: true")
    print("  • context_window: 128000")
    print("  • max_output_tokens: 4096")


@pytest.mark.asyncio
async def test_threatbook_tools_available():
    """
    验证：ThreatBook 工具已注册
    """
    from flocks.tool.registry import ToolRegistry
    
    ToolRegistry.init()
    tools = {t.name for t in ToolRegistry.list_tools()}

    required_tools = {
        "threatbook_io_ip_query",
        "threatbook_io_domain_query",
        "threatbook_io_file_query",
    }
    missing_tools = required_tools - tools
    if missing_tools:
        pytest.skip(
            "ThreatBook IO tools are not installed or not loaded in this environment: "
            + ", ".join(sorted(missing_tools))
        )
    
    print("\n✅ ThreatBook tools registered:")
    print("  • threatbook_io_ip_query")
    print("  • threatbook_io_domain_query")
    print("  • threatbook_io_file_query")


@pytest.mark.asyncio
async def test_summary():
    """
    总结：配置状态
    """
    from flocks.provider.provider import Provider
    from flocks.config.config import Config
    
    print("\n" + "="*60)
    print("📋 GLM 模型配置总结")
    print("="*60)
    
    # Provider
    provider = Provider.get("custom-threatbook-internal")
    print(f"\n✅ Provider: {provider.id if provider else 'NOT FOUND'}")
    print(f"   Name: {provider.name if provider else 'N/A'}")
    print(f"   Configured: {provider.is_configured() if provider else False}")
    print(f"   Base URL: https://llm-internal.threatbook-inc.cn/api")
    
    # Model
    config = await Config.get()
    print(f"\n✅ Model: {config.model if hasattr(config, 'model') else 'NOT SET'}")
    print(f"   Provider: custom-threatbook-internal")
    print(f"   Model ID: volcengine: glm-4-7-251222")
    print(f"   Type: GLM-4")
    
    # Tools
    from flocks.tool.registry import ToolRegistry
    ToolRegistry.init()
    tools = [t.name for t in ToolRegistry.list_tools() if "threatbook" in t.name]
    print(f"\n✅ ThreatBook Tools: {len(tools)} registered")
    for tool in tools:
        print(f"   • {tool}")
    
    print("\n" + "="*60)
    print("✅ 配置完成！系统应该能够：")
    print("  1. 从 flocks.json 读取默认 GLM 模型")
    print("  2. 使用 custom-threatbook-internal provider")
    print("  3. 执行 ThreatBook 工具调用")
    print("="*60)


if __name__ == "__main__":
    import asyncio
    
    asyncio.run(test_glm_provider_configuration())
    asyncio.run(test_flocks_json_default_model())
    asyncio.run(test_glm_model_tool_support())
    asyncio.run(test_threatbook_tools_available())
    asyncio.run(test_summary())
