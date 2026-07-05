"""
Feishu Bot identity lookup and caching.

Fetches the bot's own open_id via the bot/v3/info API during WebSocket / Webhook
startup, for accurate @mention detection in subsequent message handling.

One cached entry per account_id, TTL 24h (bot open_id never changes, so long TTL is safe).
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from flocks.utils.log import Log

log = Log.create(service="channel.feishu.identity")

_BOT_IDENTITY_TTL = 86400  # 24h
_BOT_IDENTITY_FAILURE_TTL = 300  # 5m negative cache to avoid hammering the API

_identity_cache: dict[str, tuple[str, str, float]] = {}
# key: account_id  →  (open_id, name, expires_at)
_identity_lock = asyncio.Lock()


async def get_bot_identity(
    config: dict,
    account_id: str = "default",
) -> tuple[Optional[str], Optional[str]]:
    """Return (open_id, name) of the bot for the given account.

    Results are cached for 24 hours.  On error returns (None, None).
    """
    now = time.time()
    async with _identity_lock:
        cached = _identity_cache.get(account_id)
        if cached:
            open_id, name, expires_at = cached
            if now < expires_at:
                return (open_id or None), (name or None)

    try:
        from flocks.channel.builtin.feishu.client import api_request_for_account
        data = await api_request_for_account(
            "GET", "/bot/v3/info",
            config=config,
            account_id=account_id,
        )
        # The bot info endpoint returns {"bot": {...}} in real traffic.
        # Keep a fallback for nested shapes to stay compatible with mocks.
        bot = data.get("bot") or (data.get("data") or {}).get("bot") or {}
        open_id: Optional[str] = bot.get("open_id") or bot.get("bot_open_id") or None
        name: Optional[str] = bot.get("app_name") or bot.get("name") or None

        async with _identity_lock:
            _identity_cache[account_id] = (
                open_id or "",
                name or "",
                now + _BOT_IDENTITY_TTL,
            )

        log.info("feishu.identity.resolved", {
            "account_id": account_id,
            "open_id": open_id,
            "name": name,
        })
        return open_id, name

    except Exception as e:
        async with _identity_lock:
            _identity_cache[account_id] = ("", "", now + _BOT_IDENTITY_FAILURE_TTL)
        log.warning("feishu.identity.fetch_failed", {
            "account_id": account_id,
            "error": str(e),
        })
        return None, None


def get_cached_bot_open_id(account_id: str = "default") -> Optional[str]:
    """Synchronously read the cached bot open_id (no API request)."""
    cached = _identity_cache.get(account_id)
    if cached:
        open_id, _, expires_at = cached
        if time.time() < expires_at and open_id:
            return open_id
    return None
