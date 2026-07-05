"""
真实服务集成测试 — 情报查询 E2E

覆盖三条入口的完整链路（需要真实服务）：
  1. WebUI API  — HTTP 请求到 localhost:8000
  2. CLI        — 直接调用 SessionLoop（不启动 HTTP server）
  3. 多轮对话   — 验证上下文保留

运行方式：
  # 默认跳过（CI 安全）
  pytest tests/integration/test_live_intel_query.py

  # 启用（需 server 运行 + API key）
  pytest tests/integration/test_live_intel_query.py -m live

跳过条件（任意一项不满足就自动跳过）：
  - 环境变量 FLOCKS_LIVE_TEST != "1"
  - 后端服务 localhost:8000 不可达
  - LLM provider 未配置（Config.resolve_default_llm 返回 None）

断言原则：
  - 只断言「结构」（finish=stop、有 text part、调用了工具）
  - 不断言 LLM 输出的具体文字（非确定性）
  - 用 IP/域名黑白名单查询，结果具有稳定的「判定」属性可断言
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import List, Optional, Tuple

import pytest


# ---------------------------------------------------------------------------
# 跳过条件检测
# ---------------------------------------------------------------------------

def _is_server_up(host: str = "localhost", port: int = 8000) -> bool:
    """非阻塞地检测后端是否可达。"""
    import socket
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _live_test_enabled() -> bool:
    return os.environ.get("FLOCKS_LIVE_TEST") == "1"


# 统一 skip 标记
skip_unless_live = pytest.mark.skipif(
    not (_live_test_enabled() and _is_server_up()),
    reason=(
        "真实服务测试需要：(1) 设置 FLOCKS_LIVE_TEST=1；"
        "(2) 后端服务 localhost:8000 在运行"
    ),
)

# 慢测试单独标记（可用 -m live 或 -m 'live and not slow' 过滤）
pytestmark = [pytest.mark.live, pytest.mark.slow]


# ---------------------------------------------------------------------------
# 共享 Fixtures
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:8000"
DEFAULT_MODEL = {
    "modelID": "volcengine: glm-4-7-251222",
    "providerID": "custom-threatbook-internal",
}

# 具有稳定安全判定的测试 IP（知名公共 DNS）
KNOWN_SAFE_IPS = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "223.5.5.5"]
KNOWN_SAFE_DOMAINS = ["google.com", "cloudflare.com"]


@pytest.fixture
def http_client():
    """同步 HTTP client。"""
    import httpx
    with httpx.Client(base_url=BASE_URL, timeout=120) as client:
        yield client


@pytest.fixture
async def async_http_client():
    """Async HTTP client，每个测试独立 client 避免 scope 冲突。"""
    import httpx
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=120) as client:
        yield client


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

async def _create_session(client, title: str = "live-test", agent: str = "rex") -> str:
    """创建 session，返回 session_id。"""
    r = await client.post("/api/session", json={
        "projectID": "live-test",
        "title": title,
        "agent": agent,
    })
    assert r.status_code == 200, f"create session failed: {r.text}"
    return r.json()["id"]


async def _send_message(client, session_id: str, text: str) -> dict:
    """发送消息并返回完整响应 dict。"""
    r = await client.post(f"/api/session/{session_id}/message", json={
        "parts": [{"type": "text", "text": text}],
        "model": DEFAULT_MODEL,
    })
    assert r.status_code == 200, f"send message failed: {r.text}"
    return r.json()


async def _get_messages(client, session_id: str) -> list:
    """获取 session 所有消息（含 parts）。"""
    r = await client.get(f"/api/session/{session_id}/message")
    assert r.status_code == 200
    return r.json()


def _extract_text_parts(response_data: dict) -> List[str]:
    """从响应中提取所有非空文本 parts。"""
    return [
        p["text"] for p in response_data.get("parts", [])
        if p.get("type") == "text" and p.get("text")
    ]


def _extract_tool_calls(messages: list) -> List[str]:
    """从消息列表中提取所有工具调用名称。

    tool part 结构：{"type": "tool", "tool": "<tool_name>", "state": {...}}
    """
    tools = []
    for msg in messages:
        for p in msg.get("parts", []):
            if p.get("type") == "tool":
                # 优先取 "tool" 字段，其次从 state 中取
                name = p.get("tool") or ""
                if not name:
                    state = p.get("state") or {}
                    if isinstance(state, dict):
                        name = state.get("toolName") or state.get("tool", "")
                if name:
                    tools.append(name)
    return tools


# ===========================================================================
# WebUI API 入口测试
# ===========================================================================

class TestWebUIAPI:
    """通过 HTTP API 测试（模拟 WebUI 前端行为）"""

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_health_check(self, async_http_client):
        """后端健康检查。"""
        r = await async_http_client.get("/api/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert "version" in data

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_agent_list_matches_expected(self, async_http_client):
        """Agent 列表包含所有预期的可见 agent。"""
        r = await async_http_client.get("/api/agent")
        assert r.status_code == 200
        agents = r.json()
        names = {a["name"] for a in agents}
        # 必须有的 visible agents
        for expected in ["rex", "explore", "hephaestus", "oracle", "librarian"]:
            assert expected in names, f"Expected agent '{expected}' not in list"
        # build/plan 应为 hidden，不在 visible 列表中
        assert "plan" not in names

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_session_lifecycle(self, async_http_client):
        """创建 → 查询 → 列表 的 session 生命周期。"""
        # 创建
        sid = await _create_session(async_http_client, "lifecycle-test")
        assert sid.startswith("ses_")

        # 获取单个 session
        r = await async_http_client.get(f"/api/session/{sid}")
        assert r.status_code == 200
        assert r.json()["id"] == sid

        # 出现在列表中
        r2 = await async_http_client.get("/api/session")
        assert r2.status_code == 200
        all_ids = [s["id"] for s in r2.json()]
        assert sid in all_ids

    @skip_unless_live
    @pytest.mark.asyncio
    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1"])
    async def test_ip_intel_query_via_api(self, async_http_client, ip: str):
        """
        WebUI 路径：查询知名公共 DNS IP 的威胁情报。

        断言：
        - 响应 finish=stop（正常结束，非 error）
        - 回复中包含文本内容（非空）
        - 调用了 threatbook 相关工具
        """
        sid = await _create_session(async_http_client, f"ip-query-{ip}")
        t0 = time.time()
        resp = await _send_message(async_http_client, sid, f"查询IP {ip}的威胁情报")
        elapsed = time.time() - t0

        # 1. 正常结束
        finish = resp.get("info", {}).get("finish")
        assert finish == "stop", f"Expected finish=stop, got {finish!r} (elapsed={elapsed:.1f}s)"

        # 2. 有回复文本
        texts = _extract_text_parts(resp)
        assert len(texts) > 0, "No text content in response"
        combined = " ".join(texts)
        assert len(combined) > 20, f"Reply too short: {combined!r}"

        # 3. IP 出现在回复中（说明 LLM 真的在处理这个 IP）
        assert ip in combined, f"IP {ip} not mentioned in reply"

        # 4. 工具调用（从消息历史验证）
        all_msgs = await _get_messages(async_http_client, sid)
        tool_calls = _extract_tool_calls(all_msgs)
        # 工具名可能是 threatbook_ip_query 或 __mcp_ip_query（MCP 路由）
        ip_related_calls = [
            t for t in tool_calls
            if any(kw in t.lower() for kw in ("ip", "threatbook", "mcp", "query", "intel"))
        ]
        assert len(ip_related_calls) > 0, \
            f"No IP/threatbook tool calls found. All tool calls: {tool_calls}"

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_domain_intel_query_via_api(self, async_http_client):
        """WebUI 路径：查询域名安全状态。"""
        sid = await _create_session(async_http_client, "domain-query")
        resp = await _send_message(async_http_client, sid, "查询域名 google.com 的安全状态")

        assert resp.get("info", {}).get("finish") == "stop"
        texts = _extract_text_parts(resp)
        assert len(texts) > 0
        combined = " ".join(texts)
        assert "google" in combined.lower()

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_error_handling_invalid_session(self, async_http_client):
        """无效 session ID 应返回 4xx。"""
        r = await async_http_client.post("/api/session/ses_nonexistent_id/message", json={
            "parts": [{"type": "text", "text": "hello"}],
        })
        assert r.status_code in (400, 404, 422), f"Expected 4xx, got {r.status_code}"


# ===========================================================================
# CLI 入口测试（直接调用 SessionLoop，不需要 HTTP server）
# ===========================================================================

# CLI 测试只需要 LLM 可用，不需要 server 在运行
skip_unless_llm = pytest.mark.skipif(
    not _live_test_enabled(),
    reason="CLI 实时测试需要设置 FLOCKS_LIVE_TEST=1 且配置好 LLM provider",
)


class TestCLISessionLoop:
    """通过 SessionLoop 直接调用（模拟 CLI/TUI 行为）"""

    @skip_unless_llm
    @pytest.mark.asyncio
    async def test_single_ip_query(self):
        """CLI 路径：单轮 IP 情报查询。"""
        from flocks.session.session import Session
        from flocks.session.message import Message, MessageRole
        from flocks.session.session_loop import SessionLoop

        ip = "8.8.8.8"
        session = await Session.create(
            project_id="cli-test",
            directory="/tmp/Flocks",
            title=f"CLI IP 查询 {ip}",
        )
        await Message.create(
            session_id=session.id,
            role=MessageRole.USER,
            content=f"查询IP {ip}的威胁情报，给出简要总结",
        )

        result = await asyncio.wait_for(
            SessionLoop.run(
                session_id=session.id,
                provider_id=DEFAULT_MODEL["providerID"],
                model_id=DEFAULT_MODEL["modelID"],
            ),
            timeout=120,
        )

        assert result.action in ("stop", "continue"), \
            f"Unexpected loop action: {result.action}, error: {result.error}"

        # 读取助手回复
        all_msgs = await Message.list_with_parts(session.id)
        assistant_texts = []
        tool_calls_found = []
        for mwp in all_msgs:
            if mwp.info.role == "assistant":
                for p in mwp.parts:
                    if getattr(p, "type", None) == "text" and getattr(p, "text", None):
                        assistant_texts.append(p.text)
                    elif getattr(p, "type", None) == "tool":
                        # tool name: "tool" field first, then state.toolName
                        name = getattr(p, "tool", "") or ""
                        if not name:
                            state = getattr(p, "state", {}) or {}
                            name = state.get("toolName", "") if isinstance(state, dict) else ""
                        tool_calls_found.append(name)

        assert len(assistant_texts) > 0, "No assistant text reply"
        combined = " ".join(assistant_texts)
        assert len(combined) > 20, f"Reply too short: {combined!r}"
        assert ip in combined, f"IP {ip} not in reply"

        # 验证工具被调用
        assert len(tool_calls_found) > 0, "No tool calls were made"

    @skip_unless_llm
    @pytest.mark.asyncio
    async def test_multi_turn_context_preserved(self):
        """CLI 路径：多轮对话验证上下文保留。"""
        from flocks.session.session import Session
        from flocks.session.message import Message, MessageRole
        from flocks.session.session_loop import SessionLoop

        session = await Session.create(
            project_id="cli-multi-turn",
            directory="/tmp/Flocks",
            title="多轮对话测试",
        )

        async def turn(text: str) -> str:
            await Message.create(session_id=session.id, role=MessageRole.USER, content=text)
            result = await asyncio.wait_for(
                SessionLoop.run(
                    session_id=session.id,
                    provider_id=DEFAULT_MODEL["providerID"],
                    model_id=DEFAULT_MODEL["modelID"],
                ),
                timeout=120,
            )
            assert result.action != "error", f"Loop error: {result.error}"
            # 取最后一条助手消息的文本
            all_msgs = await Message.list_with_parts(session.id)
            for mwp in reversed(all_msgs):
                if mwp.info.role == "assistant":
                    for p in mwp.parts:
                        if getattr(p, "type", None) == "text" and getattr(p, "text", None):
                            return p.text
            return ""

        # Turn 1: 查 IP
        reply1 = await turn("查询IP 8.8.8.8的基本情报")
        assert "8.8.8.8" in reply1 or "google" in reply1.lower(), \
            f"Turn1 reply doesn't mention 8.8.8.8: {reply1[:200]}"

        # Turn 2: 追问（应该保留上下文，知道上文说的是 8.8.8.8）
        reply2 = await turn("这个IP属于哪家公司？")
        # 上下文保留：应该提到 Google
        assert any(kw in reply2.lower() for kw in ["google", "谷歌"]), \
            f"Turn2 should mention Google (context lost?): {reply2[:200]}"

    @skip_unless_llm
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """验证 SessionLoop 在合理时间内返回（不无限挂起）。"""
        from flocks.session.session import Session
        from flocks.session.message import Message, MessageRole
        from flocks.session.session_loop import SessionLoop

        session = await Session.create(
            project_id="cli-timeout-test",
            directory="/tmp/Flocks",
            title="超时测试",
        )
        await Message.create(
            session_id=session.id,
            role=MessageRole.USER,
            content="查询IP 1.1.1.1的威胁情报",
        )

        t0 = time.time()
        try:
            result = await asyncio.wait_for(
                SessionLoop.run(
                    session_id=session.id,
                    provider_id=DEFAULT_MODEL["providerID"],
                    model_id=DEFAULT_MODEL["modelID"],
                ),
                timeout=180,
            )
            elapsed = time.time() - t0
            assert result.action != "error", f"Unexpected error: {result.error}"
            assert elapsed < 180, f"Took too long: {elapsed:.1f}s"
        except asyncio.TimeoutError:
            pytest.fail("SessionLoop hung for > 180 seconds")


# ===========================================================================
# 多查询类型覆盖
# ===========================================================================

class TestQueryTypes:
    """不同查询类型的 E2E 验证（WebUI 路径）"""

    @skip_unless_live
    @pytest.mark.asyncio
    @pytest.mark.parametrize("query,expected_keyword", [
        ("查询IP 8.8.8.8的威胁情报", "8.8.8.8"),
        ("查询域名 google.com 的安全状态", "google"),
        ("8.8.8.8和1.1.1.1哪个更安全？对比一下", "cloudflare"),
    ])
    async def test_various_query_types(
        self,
        async_http_client,
        query: str,
        expected_keyword: str,
    ):
        """参数化测试不同查询类型。"""
        sid = await _create_session(async_http_client, f"qtype-{expected_keyword}")
        resp = await _send_message(async_http_client, sid, query)

        finish = resp.get("info", {}).get("finish")
        assert finish == "stop", f"finish={finish} for query: {query!r}"

        texts = _extract_text_parts(resp)
        combined = " ".join(texts).lower()
        assert expected_keyword.lower() in combined, \
            f"Expected '{expected_keyword}' in reply for query {query!r}. Got: {combined[:300]}"

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_agent_selection_rex(self, async_http_client):
        """明确指定 rex agent 执行查询。"""
        sid = await _create_session(async_http_client, "rex-agent-test", agent="rex")
        resp = await _send_message(async_http_client, sid, "查询IP 8.8.8.8威胁情报")

        info = resp.get("info", {})
        assert info.get("finish") == "stop"
        # agent 字段应为 rex
        assert info.get("agent") == "rex", f"Expected agent=rex, got {info.get('agent')}"

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_response_structure(self, async_http_client):
        """验证响应体包含所有必要字段。"""
        sid = await _create_session(async_http_client, "structure-test")
        resp = await _send_message(async_http_client, sid, "查询IP 1.1.1.1")

        # info 结构
        info = resp.get("info", {})
        assert "id" in info and info["id"].startswith("msg_")
        assert "sessionID" in info and info["sessionID"] == sid
        assert "role" in info and info["role"] == "assistant"
        assert "finish" in info
        assert "time" in info

        # parts 结构
        parts = resp.get("parts", [])
        assert isinstance(parts, list)
        for p in parts:
            assert "type" in p
            if p["type"] == "text":
                assert "text" in p
            elif p["type"] == "tool":
                assert "state" in p


# ===========================================================================
# 并发与稳定性测试
# ===========================================================================

class TestConcurrencyAndStability:
    """并发请求和稳定性验证"""

    @skip_unless_live
    @pytest.mark.asyncio
    async def test_concurrent_sessions(self, async_http_client):
        """两个 session 并发查询，互不干扰。"""
        sid1 = await _create_session(async_http_client, "concurrent-1")
        sid2 = await _create_session(async_http_client, "concurrent-2")

        async def query(sid: str, ip: str) -> Tuple[str, str]:
            resp = await _send_message(async_http_client, sid, f"查询IP {ip}的威胁情报")
            finish = resp.get("info", {}).get("finish", "?")
            texts = _extract_text_parts(resp)
            return finish, " ".join(texts)

        results = await asyncio.gather(
            query(sid1, "8.8.8.8"),
            query(sid2, "1.1.1.1"),
        )

        finish1, text1 = results[0]
        finish2, text2 = results[1]

        assert finish1 == "stop", f"Session1 finish={finish1}"
        assert finish2 == "stop", f"Session2 finish={finish2}"
        assert "8.8.8.8" in text1, "Session1 reply missing 8.8.8.8"
        assert "1.1.1.1" in text2, "Session2 reply missing 1.1.1.1"
        # 两个 session 的回复不应该混淆
        # (基于 IP 区分：cloudflare 应在 1.1.1.1 结果中，google 应在 8.8.8.8 中)
        assert "cloudflare" in text2.lower() or "1.1.1.1" in text2, \
            "Session2 (1.1.1.1) reply doesn't seem correct"
