"""
Feishu "typing" indicator.

Simulates a "typing" status by adding / removing the ``Typing`` Emoji
Reaction on the user's message. The reaction is added when the Agent
starts processing, and removed when it finishes.

Circuit breaker:
    If the Feishu API returns a rate-limit (99991400) or quota-exhausted
    (99991403 / 429) error, the circuit breaker trips and stops further
    keepalive attempts to avoid pointless retries.

Configuration:
    ``typingIndicator`` (default ``true``): set to ``false`` to disable.

Usage::

    async with feishu_typing_indicator(config, message_id, account_id):
        await run_agent(...)
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import AsyncIterator, Optional

from flocks.utils.log import Log

log = Log.create(service="channel.feishu.typing")

_TYPING_EMOJI = "Typing"

# Feishu API rate/quota error codes
_BACKOFF_CODES = frozenset({99991400, 99991403, 429})


# ---------------------------------------------------------------------------
# Error detection
# ---------------------------------------------------------------------------

def _is_backoff_error(exc: Exception) -> bool:
    """Return True if the exception represents a rate-limit or quota-exhausted error."""
    code = getattr(exc, "code", None)
    if isinstance(code, int) and code in _BACKOFF_CODES:
        return True
    # httpx / requests style: exc.response.status_code
    response = getattr(exc, "response", None)
    if response is not None:
        status = getattr(response, "status_code", None)
        if status == 429:
            return True
        # Feishu SDK may put error code in response.data["code"]
        data = getattr(response, "json", lambda: {})()
        if isinstance(data, dict):
            api_code = data.get("code")
            if isinstance(api_code, int) and api_code in _BACKOFF_CODES:
                return True
    return False


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

async def add_typing_indicator(
    config: dict,
    message_id: str,
    account_id: Optional[str] = None,
) -> Optional[str]:
    """Add a Typing Emoji Reaction to the message.

    Returns reaction_id (for later removal), or None on failure.
    Raises ``_BackoffError`` on rate-limit so callers can stop keepalive.
    """
    from flocks.channel.builtin.feishu.client import api_request_for_account

    try:
        data = await api_request_for_account(
            "POST", f"/im/v1/messages/{message_id}/reactions",
            config=config,
            account_id=account_id,
            json_body={"reaction_type": {"emoji_type": _TYPING_EMOJI}},
        )
        code = data.get("code", 0)
        if code != 0 and code in _BACKOFF_CODES:
            raise _BackoffError(code)
        reaction_id: Optional[str] = (data.get("data") or {}).get("reaction_id")
        return reaction_id
    except _BackoffError:
        raise
    except Exception as exc:
        if _is_backoff_error(exc):
            raise _BackoffError(getattr(exc, "code", 429)) from exc
        log.debug("feishu.typing.add_failed", {
            "message_id": message_id, "error": str(exc),
        })
        return None


async def remove_typing_indicator(
    config: dict,
    message_id: str,
    reaction_id: str,
    account_id: Optional[str] = None,
) -> None:
    """Remove a previously added Typing Emoji Reaction.

    Raises ``_BackoffError`` on rate-limit; other failures are silently ignored.
    """
    from flocks.channel.builtin.feishu.client import api_request_for_account

    try:
        data = await api_request_for_account(
            "DELETE", f"/im/v1/messages/{message_id}/reactions/{reaction_id}",
            config=config,
            account_id=account_id,
        )
        code = data.get("code", 0)
        if code != 0 and code in _BACKOFF_CODES:
            raise _BackoffError(code)
    except _BackoffError:
        raise
    except Exception as exc:
        if _is_backoff_error(exc):
            raise _BackoffError(getattr(exc, "code", 429)) from exc
        log.debug("feishu.typing.remove_failed", {
            "message_id": message_id,
            "reaction_id": reaction_id,
            "error": str(exc),
        })


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def feishu_typing_indicator(
    config: dict,
    message_id: str,
    account_id: Optional[str] = None,
) -> AsyncIterator[None]:
    """Async context manager: automatically adds/removes the Typing indicator.

    - If ``typingIndicator`` is ``false``, passes through without making any API calls.
    - If adding the Reaction encounters a rate-limit, skips Typing (does not block the Agent).
    - Automatically removes the Reaction on exit; rate-limit on removal logs a warning and continues.

    Usage::

        async with feishu_typing_indicator(config, msg.message_id, account_id):
            result = await run_agent(session_id, ...)
    """
    enabled = config.get("typingIndicator", True)
    if not enabled or not message_id:
        yield
        return

    reaction_id: Optional[str] = None
    try:
        reaction_id = await add_typing_indicator(config, message_id, account_id)
    except _BackoffError as e:
        log.warning("feishu.typing.backoff_on_add", {
            "message_id": message_id, "code": e.code,
            "hint": "Rate-limited; skipping Typing Indicator",
        })
        # Skip typing, do not block
        yield
        return
    except Exception as e:
        log.debug("feishu.typing.unexpected_add_error", {
            "message_id": message_id, "error": str(e),
        })

    try:
        yield
    finally:
        if reaction_id:
            try:
                await remove_typing_indicator(config, message_id, reaction_id, account_id)
            except _BackoffError as e:
                log.warning("feishu.typing.backoff_on_remove", {
                    "message_id": message_id, "reaction_id": reaction_id, "code": e.code,
                })
            except Exception as e:
                log.debug("feishu.typing.remove_error", {
                    "message_id": message_id, "error": str(e),
                })


# ---------------------------------------------------------------------------
# Internal exception
# ---------------------------------------------------------------------------

class _BackoffError(Exception):
    """Internal exception: rate-limit / quota-exhausted, circuit breaker tripped."""
    def __init__(self, code: int) -> None:
        super().__init__(f"Feishu typing backoff: code {code}")
        self.code = code
