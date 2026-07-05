"""
MCP 集成验证脚本

简化的集成测试，验证 MCP 核心功能
"""

import asyncio
import os
from flocks.mcp import MCP, McpStatus
from flocks.mcp.registry import McpToolRegistry
from flocks.tool import ToolRegistry
from flocks.tool.registry import ToolContext

# ThreatBook 配置
THREATBOOK_API_KEY = os.getenv("THREATBOOK_API_KEY")
THREATBOOK_MCP_URL = "https://mcp.threatbook.cn/mcp"


async def main():
    print("=" * 60)
    print("MCP 集成验证测试")
    print("=" * 60)
    
    # 检查 API Key
    if not THREATBOOK_API_KEY:
        print("✗ 错误: 未设置 THREATBOOK_API_KEY 环境变量")
        print("  请设置环境变量: export THREATBOOK_API_KEY=your_api_key")
        return
    
    # 1. 连接到 ThreatBook
    print("\n[1/6] 连接到 ThreatBook MCP 服务器...")
    threatbook_config = {
        "type": "remote",
        "url": THREATBOOK_MCP_URL,
        "enabled": True,
        "timeout": 30.0,
        "auth": {
            "type": "apikey",
            "location": "query",
            "param_name": "apikey",
            "value": THREATBOOK_API_KEY
        }
    }
    
    try:
        success = await MCP.connect("threatbook", threatbook_config)
        if success:
            print("✓ 连接成功")
        else:
            print("✗ 连接失败")
            return
    except Exception as e:
        print(f"✗ 连接出错: {e}")
        return
    
    # 2. 检查状态
    print("\n[2/6] 检查服务器状态...")
    try:
        status = await MCP.status()
        if "threatbook" in status:
            info = status["threatbook"]
            print(f"✓ 状态: {info.status.value}")
            print(f"  工具数: {info.tools_count}")
            print(f"  资源数: {info.resources_count}")
        else:
            print("✗ 未找到 threatbook 状态")
            return
    except Exception as e:
        print(f"✗ 状态检查出错: {e}")
        return
    
    # 3. 列出工具
    print("\n[3/6] 列出可用工具...")
    try:
        server_info = await MCP.get_server_info("threatbook")
        if server_info:
            print(f"✓ 发现 {len(server_info.tools)} 个工具:")
            for tool in server_info.tools[:5]:  # 只显示前 5 个
                print(f"  - {tool.name}")
            if len(server_info.tools) > 5:
                print(f"  ... 还有 {len(server_info.tools) - 5} 个工具")
        else:
            print("✗ 未能获取服务器信息")
            return
    except Exception as e:
        print(f"✗ 列出工具出错: {e}")
        return
    
    # 4. 检查工具注册
    print("\n[4/6] 检查工具注册到 Flocks...")
    try:
        registered_tools = McpToolRegistry.get_server_tools("threatbook")
        print(f"✓ 已注册 {len(registered_tools)} 个工具到 Flocks")
        
        # 检查特定工具
        ip_query_tool = next((t for t in registered_tools if "ip_query" in t), None)
        vuln_query_tool = next((t for t in registered_tools if "vuln_query" in t), None)
        
        if ip_query_tool:
            print(f"  ✓ 找到 IP 查询工具: {ip_query_tool}")
        if vuln_query_tool:
            print(f"  ✓ 找到漏洞查询工具: {vuln_query_tool}")
    except Exception as e:
        print(f"✗ 检查注册出错: {e}")
        return
    
    # 5. 调用工具
    print("\n[5/6] 测试工具调用...")
    try:
        if ip_query_tool:
            tool = ToolRegistry.get(ip_query_tool)
            if tool:
                print(f"  调用工具: {ip_query_tool}")
                ctx = ToolContext(session_id="test", message_id="test")
                result = await tool.handler(ctx, ip="8.8.8.8")
                
                if result.success:
                    print(f"  ✓ 调用成功")
                    print(f"    元数据: {result.metadata}")
                    # 只显示输出的前 200 个字符
                    output_str = str(result.output)[:200]
                    print(f"    输出预览: {output_str}...")
                else:
                    print(f"  ✗ 调用失败: {result.error}")
            else:
                print(f"  ✗ 未找到工具实例")
        else:
            print("  ⚠ 跳过：未找到 ip_query 工具")
    except Exception as e:
        print(f"✗ 工具调用出错: {e}")
        import traceback
        traceback.print_exc()
    
    # 6. 统计信息
    print("\n[6/6] 获取统计信息...")
    try:
        stats = MCP.get_stats()
        print(f"✓ 统计信息:")
        print(f"  总服务器数: {stats['total_servers']}")
        print(f"  总工具数: {stats['total_tools']}")
        print(f"  各服务器工具数: {stats['tools_by_server']}")
    except Exception as e:
        print(f"✗ 获取统计出错: {e}")
    
    # 清理
    print("\n[清理] 断开连接...")
    try:
        await MCP.disconnect("threatbook")
        print("✓ 已断开连接")
    except Exception as e:
        print(f"⚠ 断开连接出错: {e}")
    
    print("\n" + "=" * 60)
    print("验证完成！")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
