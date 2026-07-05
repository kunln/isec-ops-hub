"""
Feishu sender name async resolution (contact/v3/users API).

Used to populate sender_name on InboundMessage during inbound processing,
so the Agent knows who is speaking.

Design:
- In-memory cache, TTL 10 minutes (user names change infrequently)
- Fails silently returning None, does not block the message pipeline
- Supports open_id / user_id / union_id identifier types
- Returns (name, permission_denied) tuple so callers can detect permission errors
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Optional, Tuple

from flocks.utils.log import Log

log = Log.create(service="channel.feishu.sender_name")

_CACHE_TTL_SECONDS = 600   # 10 minutes
_CACHE_MAX = 5000

# LRU cache: (name_or_empty, expires_at, is_permission_error)
_name_cache: OrderedDict[str, tuple[str, float, bool]] = OrderedDict()
_cache_lock = asyncio.Lock()


def _resolve_user_id_type(sender_id: str) -> str:
    """Infer the user_id_type parameter from the ID prefix."""
    trimmed = sender_id.strip()
    if trimmed.startswith("ou_"):
        return "open_id"
    if trimmed.startswith("on_"):
        return "union_id"
    return "user_id"


async def resolve_sender_name(
    sender_id: str,
    config: dict,
    account_id: str = "default",
) -> Tuple[Optional[str], bool]:
    """Look up and cache the Feishu user's display name.

    Returns (name, permission_denied):
    - name: display name, or None on lookup failure
    - permission_denied: True if the failure was a permission error (not a network error);
      callers can use this to inject a permission hint to the Agent
    """
    if not sender_id or not sender_id.strip():
        return None, False

    sid = sender_id.strip()
    cache_key = f"{account_id}:{sid}"
    now = time.time()

    # Check cache (LRU: move to end on hit)
    async with _cache_lock:
        cached = _name_cache.get(cache_key)
        if cached:
            name, expires_at, is_perm_err = cached
            if now < expires_at:
                _name_cache.move_to_end(cache_key)
                return (name or None), is_perm_err
            else:
                del _name_cache[cache_key]

    try:
        from flocks.channel.builtin.feishu.client import api_request_for_account
        user_id_type = _resolve_user_id_type(sid)
        data = await api_request_for_account(
            "GET", f"/contact/v3/users/{sid}",
            config=config,
            account_id=account_id,
            params={"user_id_type": user_id_type},
        )
        user = (data.get("data") or {}).get("user") or {}
        name: Optional[str] = (
            user.get("name")
            or user.get("display_name")
            or user.get("nickname")
            or user.get("en_name")
        )
        if name and not isinstance(name, str):
            name = str(name)

        async with _cache_lock:
            _name_cache[cache_key] = (name or "", now + _CACHE_TTL_SECONDS, False)
            _name_cache.move_to_end(cache_key)
            while len(_name_cache) > _CACHE_MAX:
                _name_cache.popitem(last=False)

        return name if name else None, False

    except Exception as e:
        err_str = str(e)
        is_permission_error = "403" in err_str or "99991672" in err_str
        if is_permission_error:
            log.warning("feishu.sender_name.permission_denied", {
                "sender_id": sid,
                "account_id": account_id,
                "hint": "Missing contact:user.base:readonly permission; cannot resolve sender name",
            })
        else:
            log.debug("feishu.sender_name.fetch_failed", {
                "sender_id": sid,
                "account_id": account_id,
                "error": err_str,
            })

        async with _cache_lock:
            _name_cache[cache_key] = ("", now + _CACHE_TTL_SECONDS, is_permission_error)
            _name_cache.move_to_end(cache_key)
            while len(_name_cache) > _CACHE_MAX:
                _name_cache.popitem(last=False)

        return None, is_permission_error
