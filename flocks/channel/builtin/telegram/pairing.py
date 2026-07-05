"""
Pairing-code store for Telegram channel user authorisation.

When ``allowFrom`` is configured, unknown users receive a one-time code via
the Bot.  The operator enters the code in the Flocks UI to add the user to
the allowlist.  Codes expire after ``PAIRING_TTL_S`` seconds.
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Optional

from flocks.utils.log import Log
from .client import ensure_telegram_http_allowed, get_http_client

log = Log.create(service="channel.telegram")

PAIRING_TTL_S: int = 300  # 5 minutes


class PairingStore:
    """In-process, TTL-based store for pending pairing codes."""

    def __init__(self) -> None:
        self._pending: dict[str, dict[str, Any]] = {}

    def create(self, user_id: str, username: Optional[str], chat_id: Optional[str] = None) -> str:
        """Generate a new code for *user_id*, replacing any previous one."""
        self._pending = {
            c: v for c, v in self._pending.items()
            if v["user_id"] != user_id and v["expires_at"] > time.monotonic()
        }
        code = secrets.token_hex(3).upper()
        self._pending[code] = {
            "user_id": user_id,
            "username": username,
            "chat_id": chat_id or user_id,
            "expires_at": time.monotonic() + PAIRING_TTL_S,
        }
        return code

    def consume(self, code: str) -> Optional[dict[str, Any]]:
        """Return and remove the entry for *code*, or ``None`` if invalid/expired."""
        entry = self._pending.pop(code.upper(), None)
        if entry is None:
            return None
        if entry["expires_at"] < time.monotonic():
            return None
        return entry

    def cleanup(self) -> None:
        """Remove all expired entries."""
        now = time.monotonic()
        self._pending = {c: v for c, v in self._pending.items() if v["expires_at"] > now}


# Module-level singleton shared across all TelegramChannel instances.
pairing_store = PairingStore()


async def send_pairing_code(
    base_url: str,
    message: dict[str, Any],
    sender_id: str,
    username: Optional[str],
) -> None:
    """Send a pairing-code message to the user and record it in the store."""
    pairing_store.cleanup()
    chat_id = str(message["chat"]["id"])
    code = pairing_store.create(sender_id, username, chat_id=chat_id)
    display_name = f"@{username}" if username else f"user {sender_id}"
    text = (
        f"👋 Hi, {display_name}!\n\n"
        f"Your pairing code is:\n\n"
        f"<code>{code}</code>\n\n"
        f"Enter this code in the Flocks UI under the Telegram channel settings to complete pairing.\n"
        f"⏱ Valid for 5 minutes."
    )
    try:
        url = f"{base_url}/sendMessage"
        await ensure_telegram_http_allowed(url, purpose="Telegram pairing code")
        client = await get_http_client()
        await client.post(
            url,
            json={
                "chat_id": message["chat"]["id"],
                "text": text,
                "parse_mode": "HTML",
            },
            timeout=10,
        )
        log.info("telegram.pairing.code_sent", {
            "user_id": sender_id,
            "username": username or "",
        })
    except Exception as exc:
        log.warning("telegram.pairing.reply_failed", {"error": str(exc)})


async def send_pairing_confirmed(base_url: str, entry: dict[str, Any]) -> None:
    """Notify the Telegram user that they have been successfully paired."""
    user_id = entry.get("user_id", "")
    username = entry.get("username") or None
    chat_id = entry.get("chat_id") or user_id
    if not chat_id:
        return

    display_name = f"@{username}" if username else f"user {user_id}"
    text = (
        f"✅ You're all set, {display_name}!\n\n"
        f"Pairing successful. You can now chat with the bot."
    )
    try:
        url = f"{base_url}/sendMessage"
        await ensure_telegram_http_allowed(url, purpose="Telegram pairing confirmation")
        client = await get_http_client()
        await client.post(
            url,
            json={"chat_id": chat_id, "text": text},
            timeout=10,
        )
        log.info("telegram.pairing.confirmed_sent", {
            "user_id": user_id,
            "chat_id": chat_id,
        })
    except Exception as exc:
        log.warning("telegram.pairing.confirm_failed", {"error": str(exc)})
