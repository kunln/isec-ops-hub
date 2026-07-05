from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from flocks.channel.base import OutboundContext
from flocks.channel.builtin.telegram.channel import TelegramChannel
from flocks.commercial import policy as commercial_policy
from flocks.channel.builtin.feishu import media as feishu_media
from flocks.channel.builtin.feishu import streaming_card as feishu_streaming_card
from flocks.channel.builtin.weixin import cdn as weixin_cdn
from flocks.channel.builtin.weixin import qr_login as weixin_qr_login


@pytest.mark.asyncio
async def test_weixin_qr_login_rejects_before_http_session_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    client_session = MagicMock()
    monkeypatch.setattr(commercial_policy, "ensure_outbound_allowed", fake_ensure_outbound_allowed)
    monkeypatch.setattr("aiohttp.ClientSession", client_session)

    with pytest.raises(commercial_policy.CommercialPolicyError, match="blocked by commercial policy"):
        await weixin_qr_login._api_get("https://ilink.example.com", "bot/qrcode")

    assert calls == [
        {
            "url": "https://ilink.example.com/bot/qrcode",
            "purpose": "Weixin QR login API request",
            "require_initialized": False,
        }
    ]
    client_session.assert_not_called()


@pytest.mark.asyncio
async def test_feishu_media_url_fetch_rejects_before_http_client_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    async_client = MagicMock()
    monkeypatch.setattr(commercial_policy, "ensure_outbound_allowed", fake_ensure_outbound_allowed)
    monkeypatch.setattr(feishu_media.httpx, "AsyncClient", async_client)

    with pytest.raises(commercial_policy.CommercialPolicyError, match="blocked by commercial policy"):
        await feishu_media._fetch_url_bytes("https://files.example.com/report.pdf")

    assert calls == [
        {
            "url": "https://files.example.com/report.pdf",
            "purpose": "Feishu media URL fetch",
            "require_initialized": False,
        }
    ]
    async_client.assert_not_called()


@pytest.mark.asyncio
async def test_feishu_streaming_card_post_rejects_before_http_client_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    get_http_client = AsyncMock()
    monkeypatch.setattr(commercial_policy, "ensure_outbound_allowed", fake_ensure_outbound_allowed)
    monkeypatch.setattr(feishu_streaming_card, "_get_http_client", get_http_client)

    with pytest.raises(commercial_policy.CommercialPolicyError, match="blocked by commercial policy"):
        await feishu_streaming_card._api_post(
            "https://open.feishu.cn/open-apis/cardkit/v1/cards",
            "token",
            {"type": "card_json"},
        )

    assert calls == [
        {
            "url": "https://open.feishu.cn/open-apis/cardkit/v1/cards",
            "purpose": "Feishu streaming card API request",
            "require_initialized": False,
        }
    ]
    get_http_client.assert_not_called()


@pytest.mark.asyncio
async def test_weixin_cdn_download_rejects_before_session_get_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    session = MagicMock()
    monkeypatch.setattr(commercial_policy, "ensure_outbound_allowed", fake_ensure_outbound_allowed)

    with pytest.raises(commercial_policy.CommercialPolicyError, match="blocked by commercial policy"):
        await weixin_cdn.download_bytes(session, url="https://novac2c.cdn.weixin.qq.com/c2c/file")

    assert calls == [
        {
            "url": "https://novac2c.cdn.weixin.qq.com/c2c/file",
            "purpose": "Weixin CDN media download",
            "require_initialized": False,
        }
    ]
    session.get.assert_not_called()


@pytest.mark.asyncio
async def test_telegram_send_rejects_before_http_client_when_outbound_disabled(monkeypatch):
    calls: list[dict] = []

    async def fake_ensure_outbound_allowed(**kwargs):
        calls.append(kwargs)
        raise commercial_policy.CommercialPolicyError("blocked by commercial policy")

    get_http_client = AsyncMock()
    monkeypatch.setattr(commercial_policy, "ensure_outbound_allowed", fake_ensure_outbound_allowed)
    monkeypatch.setattr("flocks.channel.builtin.telegram.channel.get_http_client", get_http_client)

    channel = TelegramChannel()
    channel._config = {"botToken": "123:abc"}

    with pytest.raises(commercial_policy.CommercialPolicyError, match="blocked by commercial policy"):
        await channel.send_text(OutboundContext(channel_id="telegram", to="user:42", text="hello"))

    assert calls == [
        {
            "url": "https://api.telegram.org/bot123:abc/sendMessage",
            "purpose": "Telegram send message",
            "require_initialized": False,
        }
    ]
    get_http_client.assert_not_called()
