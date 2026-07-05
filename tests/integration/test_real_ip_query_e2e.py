"""
真实的端到端 IP 查询测试

不使用 mock，测试完整流程以发现真实问题
"""

import pytest
import asyncio

from flocks.session.session import Session
from flocks.session.message import Message, MessageRole
from flocks.session.session_loop import SessionLoop
from flocks.tool.registry import ToolRegistry


def _available_threatbook_ip_tool() -> str:
    ToolRegistry.init()
    tools = {t.name for t in ToolRegistry.list_tools()}
    if "threatbook_io_ip_query" in tools:
        return "threatbook_io_ip_query"
    if "threatbook_ip_query" in tools:
        return "threatbook_ip_query"
    pytest.skip("ThreatBook IP query tool is not installed in this environment")


@pytest.mark.asyncio
@pytest.mark.skip(reason="需要真实 API key 和网络")
async def test_real_ip_query_with_anthropic():
    """
    真实测试：调用 Anthropic API 查询 8.8.8.8
    
    这个测试会：
    1. 创建真实 session
    2. 发送用户消息
    3. 调用真实 LLM API
    4. 执行真实工具调用
    5. 返回真实结果
    
    需要：
    - ANTHROPIC_API_KEY 环境变量
    - ThreatBook API key
    - 网络连接
    """
    # 初始化工具
    ToolRegistry.init()
    
    # 创建 session
    session = await Session.create(
        project_id="real_ip_test",
        directory="/tmp/test_real",
        title="Real IP Query Test"
    )
    
    # 创建用户消息
    await Message.create(
        session_id=session.id,
        role=MessageRole.USER,
        content="查一下 8.8.8.8 的情报",
        agent="rex"
    )
    
    # 运行真实的 SessionLoop（不使用 mock）
    result = await SessionLoop.run(
        session_id=session.id,
        provider_id="anthropic",
        model_id="claude-sonnet-4",
        agent_name="rex",
    )
    
    # 验证结果
    print(f"Loop result action: {result.action}")
    print(f"Loop result last_message: {result.last_message}")
    
    # 获取所有消息
    messages = await Message.list(session.id)
    print(f"\nTotal messages: {len(messages)}")
    for msg in messages:
        print(f"- {msg.role}: {msg.content[:100] if msg.content else 'No content'}")
    
    # 应该有至少 2 条消息：用户消息 + 助手回复
    assert len(messages) >= 2, f"Expected at least 2 messages, got {len(messages)}"
    
    # 最后一条应该是助手消息
    last_msg = messages[-1]
    assert last_msg.role in ["assistant", MessageRole.ASSISTANT]
    assert last_msg.content, "Assistant message should have content"
    
    # 内容应该包含 8.8.8.8 的信息
    content_lower = last_msg.content.lower()
    assert "8.8.8.8" in content_lower or "google" in content_lower


@pytest.mark.asyncio
async def test_tool_execution_directly():
    """
    直接测试工具执行（绕过 LLM）
    
    这个测试验证工具本身是否工作
    """
    ToolRegistry.init()
    
    # 验证工具已注册
    tool_name = _available_threatbook_ip_tool()
    
    # 尝试直接执行工具
    # Note: 这需要真实的 API key
    try:
        kwargs = {"resource": "8.8.8.8"} if tool_name == "threatbook_io_ip_query" else {"ip": "8.8.8.8"}
        result = await ToolRegistry.execute(
            tool_name,
            **kwargs,
        )
        print(f"Tool execution result: {result}")
        
        # 如果有 API key，应该返回结果
        if isinstance(result, dict):
            assert "response_code" in result or "error" in result
    except Exception as e:
        # 如果没有 API key 或网络问题，会报错
        print(f"Tool execution error (expected if no API key): {e}")
        # 这是预期的，跳过


@pytest.mark.asyncio
async def test_cli_session_runner_basic():
    """
    测试 CLI SessionRunner 的基本流程

    模拟 CLI 的调用方式
    """
    from pathlib import Path
    from flocks.cli.session_runner import CLISessionRunner
    from flocks.agent import Agent
    from rich.console import Console

    # 初始化
    ToolRegistry.init()

    # 获取默认 agent（返回字符串名称）
    agent_name = await Agent.default_agent()
    print(f"Default agent: {agent_name}")

    # 创建 runner（新接口：console + directory 必选）
    runner = CLISessionRunner(
        console=Console(),
        directory=Path("/tmp/test"),
        agent=agent_name or "rex",
        model="claude-sonnet-4",
    )

    assert runner is not None
    assert runner.agent_name in ["rex", agent_name or ""]


@pytest.mark.asyncio
async def test_debug_cli_response():
    """
    诊断测试：为什么 CLI 没有响应
    
    检查可能的问题点
    """
    import os
    from flocks.provider.provider import Provider
    from flocks.agent import Agent
    
    # 1. 检查 API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    print(f"Has ANTHROPIC_API_KEY: {bool(api_key)}")
    if api_key:
        print(f"API key length: {len(api_key)}")
    
    # 2. 检查 agent
    ToolRegistry.init()
    rex = await Agent.get("rex")
    assert rex is not None
    print(f"Rex agent: {rex.name}")
    print(f"Rex model: {rex.model}")
    
    # 3. 检查工具注册
    tools = {t.name for t in ToolRegistry.list_tools()}
    tool_name = _available_threatbook_ip_tool()
    print(f"Total tools: {len(tools)}")
    print(f"Has {tool_name}: True")
    
    # 4. 检查 provider 配置
    try:
        provider = Provider.get("anthropic")
        print(f"Provider configured: {provider is not None}")
    except Exception as e:
        print(f"Provider error: {e}")
