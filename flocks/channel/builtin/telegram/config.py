"""
Configuration constants and helper functions for the Telegram channel plugin.

Covers:
- Polling / backoff tuning constants
- Type coercion utilities
- Account / API-base resolution
- Mode detection (polling vs webhook)
- Mention / command parsing
"""

from __future__ import annotations

import random
import re
from typing import Any, Optional

import httpx

from flocks.channel.base import ChatType


# ---------------------------------------------------------------------------
# Polling tuning
# ---------------------------------------------------------------------------
POLL_LONG_TIMEOUT_S: int = 30
POLL_HTTP_TIMEOUT_S: int = 45
POLL_INITIAL_BACKOFF_S: float = 2.0
POLL_MAX_BACKOFF_S: float = 30.0
POLL_BACKOFF_FACTOR: float = 1.8
POLL_BACKOFF_JITTER: float = 0.25

# Startup drain: non-blocking getUpdates(timeout=0) to kick old long-poll session
DRAIN_MAX_ATTEMPTS: int = 10
DRAIN_RETRY_INTERVAL_S: float = 3.0


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------
_TARGET_PREFIX_RE = re.compile(r"^(?:telegram|tg|user|group):", re.IGNORECASE)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{5,}$")
_COMMAND_RE = re.compile(
    r"^/(?P<command>[A-Za-z0-9_]+)(?:@(?P<username>[A-Za-z0-9_]+))?(?P<rest>(?:\s+.*)?)$"
)


# ---------------------------------------------------------------------------
# Type coercions
# ---------------------------------------------------------------------------

def coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and re.fullmatch(r"-?\d+", stripped):
            try:
                return int(stripped)
            except ValueError:
                return None
    return None


def coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def clean_bot_username(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    value = raw.strip().lstrip("@").lower()
    if not value or not _USERNAME_RE.fullmatch(value):
        return None
    return value


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def strip_target_prefixes(raw: str) -> str:
    value = raw.strip()
    while value:
        next_value = _TARGET_PREFIX_RE.sub("", value, count=1).strip()
        if next_value == value:
            return value
        value = next_value
    return value


def parse_target(raw: str) -> tuple[str, Optional[int]]:
    normalized = strip_target_prefixes(raw)
    if not normalized:
        return "", None
    explicit_topic = re.fullmatch(r"(.+?):topic:(\d+)", normalized)
    if explicit_topic:
        return explicit_topic.group(1), int(explicit_topic.group(2))
    implicit_topic = re.fullmatch(r"(.+):(\d+)", normalized)
    if implicit_topic:
        return implicit_topic.group(1), int(implicit_topic.group(2))
    return normalized, None


# ---------------------------------------------------------------------------
# Account / API-base resolution
# ---------------------------------------------------------------------------

def resolve_enabled_accounts(config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    accounts = config.get("accounts")
    if not isinstance(accounts, dict) or not accounts:
        return []
    enabled: list[tuple[str, dict[str, Any]]] = []
    for account_id, account_cfg in accounts.items():
        if not isinstance(account_cfg, dict):
            continue
        if account_cfg.get("enabled", True) is False:
            continue
        enabled.append((str(account_id), account_cfg))
    return enabled


def resolve_account_config(
    config: dict[str, Any],
    account_id: Optional[str] = None,
) -> tuple[str, dict[str, Any]]:
    accounts = resolve_enabled_accounts(config)
    if account_id:
        if not accounts and account_id == "default":
            return "default", {**config, "_account_id": "default"}
        for candidate_id, candidate_cfg in accounts:
            if candidate_id == account_id:
                return candidate_id, {
                    **config,
                    **candidate_cfg,
                    "_account_id": candidate_id,
                }
        raise ValueError(f"Telegram account '{account_id}' not found")

    if accounts:
        if len(accounts) > 1:
            raise ValueError(
                "Telegram project plugin currently supports exactly one enabled account in webhook mode"
            )
        candidate_id, candidate_cfg = accounts[0]
        return candidate_id, {**config, **candidate_cfg, "_account_id": candidate_id}

    return "default", {**config, "_account_id": "default"}


def resolve_api_base(config: dict[str, Any], token: str) -> str:
    api_root = coerce_str(config.get("apiRoot"))
    base = api_root.rstrip("/") if api_root else "https://api.telegram.org"
    return f"{base}/bot{token}"


# ---------------------------------------------------------------------------
# Mode detection
# ---------------------------------------------------------------------------

def is_webhook_mode(config: dict[str, Any]) -> bool:
    """Webhook mode when mode="webhook" or webhookSecret is present; otherwise polling."""
    mode = coerce_str(config.get("mode")).lower()
    if mode == "webhook":
        return True
    if mode == "polling":
        return False
    return bool(coerce_str(config.get("webhookSecret")))


# ---------------------------------------------------------------------------
# Retry / backoff helpers
# ---------------------------------------------------------------------------

def is_retryable(status_code: int, error: Exception | None = None) -> bool:
    if status_code in {408, 409, 425, 429, 500, 502, 503, 504}:
        return True
    if isinstance(error, (httpx.TimeoutException, httpx.NetworkError)):
        return True
    return False


def compute_backoff(
    attempt: int,
    initial: float,
    maximum: float,
    factor: float,
    jitter: float,
) -> float:
    base = min(initial * (factor ** attempt), maximum)
    deviation = base * jitter
    return base + random.uniform(-deviation, deviation)


# ---------------------------------------------------------------------------
# Message / mention helpers
# ---------------------------------------------------------------------------

def extract_text(message: dict[str, Any]) -> str:
    text = message.get("text")
    if isinstance(text, str) and text.strip():
        return text
    caption = message.get("caption")
    if isinstance(caption, str) and caption.strip():
        return caption
    return ""


def resolve_chat_type(chat: dict[str, Any]) -> Optional[ChatType]:
    chat_type = coerce_str(chat.get("type")).lower()
    if chat_type == "private":
        return ChatType.DIRECT
    if chat_type in {"group", "supergroup", "channel"}:
        return ChatType.GROUP
    return None


def is_reply_to_bot(
    message: dict[str, Any],
    bot_username: Optional[str],
    bot_user_id: Optional[int],
) -> bool:
    reply_to = message.get("reply_to_message")
    if not isinstance(reply_to, dict):
        return False
    sender = reply_to.get("from")
    if not isinstance(sender, dict) or not sender.get("is_bot"):
        return False
    if bot_user_id is not None and sender.get("id") == bot_user_id:
        return True
    reply_username = clean_bot_username(sender.get("username"))
    return bool(bot_username and reply_username == bot_username)


def strip_bot_mentions(text: str, bot_username: str) -> str:
    pattern = re.compile(rf"(?i)(?<!\w)@{re.escape(bot_username)}(?!\w)")
    cleaned = pattern.sub(" ", text)
    return re.sub(r"\s+", " ", cleaned).strip()


def resolve_mention_state(
    *,
    message: dict[str, Any],
    chat_type: ChatType,
    text: str,
    bot_username: Optional[str],
    bot_user_id: Optional[int],
) -> tuple[bool, str]:
    if chat_type == ChatType.DIRECT:
        return False, ""
    if not text:
        return False, ""

    normalized_username = clean_bot_username(bot_username)
    if normalized_username:
        command_match = _COMMAND_RE.match(text.strip())
        if command_match:
            target = clean_bot_username(command_match.group("username"))
            if target and target == normalized_username:
                rest = (command_match.group("rest") or "").strip()
                cleaned = f"/{command_match.group('command')}"
                if rest:
                    cleaned = f"{cleaned} {rest}"
                return True, cleaned

        mention_stripped = strip_bot_mentions(text, normalized_username)
        if mention_stripped != text.strip():
            return True, mention_stripped

    if is_reply_to_bot(message, normalized_username, bot_user_id):
        return True, text.strip()

    return False, ""
