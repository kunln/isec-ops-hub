import asyncio
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Read API Key from environment variable
THREATBOOK_API_KEY = os.getenv("THREATBOOK_API_KEY")

async def main():
    if not THREATBOOK_API_KEY:
        print("Error: THREATBOOK_API_KEY environment variable not set")
        print("Please set environment variable: export THREATBOOK_API_KEY=your_api_key")
        return
    
    mcp_server_url = f"https://mcp.threatbook.cn/mcp?apikey={THREATBOOK_API_KEY}"
    # Connect to a streamable HTTP server
    async with streamablehttp_client(mcp_server_url) as (
        read_stream,
        write_stream,
        _,
    ):
        # Create a session using the client streams
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the connection
            await session.initialize()
            # List available tools
            tools = await session.list_tools()
            print(f"Available tools: {[tool.name for tool in tools.tools]}")

            # Call a vuln_query tool
            result = await session.call_tool(
                name="ip_query",
                arguments=  {"ip":"127.0.0.1"}
            )
            print(f"Tool result: {result}")

            # Call a vuln_query tool
            result = await session.call_tool(
                name="vuln_query",
                arguments=  {"vuln_id":"CNVD-2021-01627"}
            )
            print(f"Tool result: {result}")


if __name__ == "__main__":
    asyncio.run(main())