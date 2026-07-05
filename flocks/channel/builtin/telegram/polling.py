"""
Long-poll (getUpdates) loop for the Telegram channel.

``PollingLoop`` owns the entire lifecycle of a single polling session:
  1. deleteWebhook — ensures no competing webhook is active
  2. _drain_old_session — sends getUpdates(timeout=0) to evict any lingering
     long-poll connection from a previous process / reload
  3. Main while-loop — 30-second getUpdates requests with exponential-backoff
     error recovery

Messages are processed immediately via the ``_process_update`` coroutine,
which handles pairing intercept and normal inbound dispatch.

A background ``_typing_pulse`` task is started while waiting for the AI
to produce a reply so users see the "… is typing" indicator throughout.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

import httpx

from flocks.channel.base import InboundMessage
from flocks.utils.log import Log

from .client import ensure_telegram_http_allowed, get_http_client
from .config import (
    DRAIN_MAX_ATTEMPTS,
    DRAIN_RETRY_INTERVAL_S,
    POLL_BACKOFF_FACTOR,
    POLL_BACKOFF_JITTER,
    POLL_HTTP_TIMEOUT_S,
    POLL_INITIAL_BACKOFF_S,
    POLL_LONG_TIMEOUT_S,
    POLL_MAX_BACKOFF_S,
    coerce_int,
    coerce_str,
    compute_backoff,
    resolve_account_config,
)
from .inbound import BotIdentityResolver, build_inbound_message
from .pairing import PairingStore, send_pairing_code

log = Log.create(service="channel.telegram")

# Update types we subscribe to
_ALLOWED_UPDATES = ["message", "channel_post"]

# Typing indicator re-send interval (Telegram expires typing after ~5 s)
_TYPING_PULSE_INTERVAL_S: float = 4.0

OnMessageCB = Callable[[InboundMessage], Awaitable[None]]
RecordMessageCB = Callable[[], None]


class PollingLoop:
    """Encapsulates one long-poll session for a single bot account."""

    def __init__(
        self,
        account_id: str,
        base_url: str,
        config: dict[str, Any],
        identity: BotIdentityResolver,
        pairing: PairingStore,
        on_message: OnMessageCB,
        record_message: RecordMessageCB,
    ) -> None:
        self._account_id = account_id
        self._base_url = base_url
        self._config = config
        self._identity = identity
        self._pairing = pairing
        self._on_message = on_message
        self._record_message = record_message

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self, abort_event: asyncio.Event) -> None:
        """Run until *abort_event* is set."""
        await self._delete_webhook(abort_event)
        if abort_event.is_set():
            return

        offset = await self._drain_old_session(abort_event)
        if abort_event.is_set():
            return

        log.info("telegram.polling.started", {"account": self._account_id})
        backoff_attempt = 0

        while not abort_event.is_set():
            try:
                updates = await self._fetch_updates(offset, abort_event)
                if updates is None:
                    break

                backoff_attempt = 0
                for update in updates:
                    update_id = coerce_int(update.get("update_id"))
                    if update_id is not None:
                        offset = update_id + 1
                    await self._process_update(update)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                if abort_event.is_set():
                    break
                backoff_attempt += 1
                sleep_s = compute_backoff(
                    backoff_attempt - 1,
                    POLL_INITIAL_BACKOFF_S,
                    POLL_MAX_BACKOFF_S,
                    POLL_BACKOFF_FACTOR,
                    POLL_BACKOFF_JITTER,
                )
                log.warning("telegram.polling.error", {
                    "error": str(exc),
                    "attempt": backoff_attempt,
                    "retry_in_s": round(sleep_s, 1),
                })
                try:
                    await asyncio.wait_for(abort_event.wait(), timeout=sleep_s)
                    break
                except asyncio.TimeoutError:
                    pass

        log.info("telegram.polling.stopped", {"account": self._account_id})

    # ------------------------------------------------------------------
    # Startup helpers
    # ------------------------------------------------------------------

    async def _delete_webhook(self, abort_event: asyncio.Event) -> None:
        if abort_event.is_set():
            return
        try:
            client = await get_http_client()
            url = f"{self._base_url}/deleteWebhook"
            await ensure_telegram_http_allowed(url, purpose="Telegram delete webhook")
            response = await client.post(
                url,
                json={"drop_pending_updates": False},
                timeout=10,
            )
            data: dict[str, Any] = {}
            try:
                data = response.json()
            except ValueError:
                pass
            if not data.get("ok", response.is_success):
                log.warning("telegram.polling.delete_webhook_failed", {
                    "status_code": response.status_code,
                    "description": data.get("description", ""),
                })
            else:
                log.info("telegram.polling.webhook_cleared", {})
        except Exception as exc:
            log.warning("telegram.polling.delete_webhook_error", {"error": str(exc)})

    async def _drain_old_session(self, abort_event: asyncio.Event) -> Optional[int]:
        """Send getUpdates(timeout=0) repeatedly until we own the connection.

        Retries up to DRAIN_MAX_ATTEMPTS times on 409.  Any updates received
        during drain are dispatched normally so no messages are lost.
        Returns the starting offset for the main long-poll loop.
        """
        offset: Optional[int] = None
        client = await get_http_client()

        for attempt in range(DRAIN_MAX_ATTEMPTS):
            if abort_event.is_set():
                return offset

            payload: dict[str, Any] = {
                "timeout": 0,
                "allowed_updates": _ALLOWED_UPDATES,
            }
            if offset is not None:
                payload["offset"] = offset

            try:
                url = f"{self._base_url}/getUpdates"
                await ensure_telegram_http_allowed(url, purpose="Telegram drain updates")
                response = await client.post(
                    url,
                    json=payload,
                    timeout=10,
                )
            except (asyncio.CancelledError, httpx.HTTPError):
                break

            if response.status_code == 409:
                log.info("telegram.polling.drain_conflict", {
                    "attempt": attempt + 1,
                    "max": DRAIN_MAX_ATTEMPTS,
                })
                try:
                    await asyncio.wait_for(
                        abort_event.wait(), timeout=DRAIN_RETRY_INTERVAL_S,
                    )
                    return offset
                except asyncio.TimeoutError:
                    continue

            if response.status_code >= 400:
                break

            try:
                data = response.json()
            except ValueError:
                break

            results = data.get("result") or []
            for update in results:
                uid = coerce_int(update.get("update_id"))
                if uid is not None:
                    offset = uid + 1
                await self._process_update(update)

            log.info("telegram.polling.drain_ok", {
                "attempt": attempt + 1,
                "pending_updates": len(results),
            })
            return offset

        log.warning("telegram.polling.drain_gave_up", {"attempts": DRAIN_MAX_ATTEMPTS})
        return offset

    # ------------------------------------------------------------------
    # Per-update processing
    # ------------------------------------------------------------------

    async def _process_update(self, update: dict[str, Any]) -> None:
        """Dispatch one Telegram update: pairing intercept or inbound forward.

        Handles both ``message`` (regular chats / groups) and ``channel_post``
        (posts in Telegram channels where the bot is an admin).
        """
        message = update.get("message") or update.get("channel_post")
        if not isinstance(message, dict):
            return

        sender = message.get("from") or {}
        sender_id = coerce_str(sender.get("id"))

        pairing_on = self._is_pairing_enabled()
        log.info("telegram.polling.access_check", {
            "sender_id": sender_id or "(none)",
            "pairing_enabled": pairing_on,
            "already_paired": self._is_paired(sender_id) if (sender_id and pairing_on) else None,
        })

        if sender_id and pairing_on and not self._is_paired(sender_id):
            uname = coerce_str(sender.get("username")) or None
            log.info("telegram.polling.pairing_triggered", {
                "sender_id": sender_id,
                "username": uname or "",
            })
            await send_pairing_code(self._base_url, message, sender_id, uname)
            return

        try:
            inbound = await build_inbound_message(
                message, self._account_id, self._identity, self._config,
            )
        except Exception as exc:
            log.warning("telegram.polling.build_inbound_failed", {"error": str(exc)})
            return

        if not inbound:
            log.warning("telegram.polling.inbound_none", {
                "sender_id": sender_id,
                "text": (message.get("text") or "")[:50],
            })
            return

        chat_id = inbound.chat_id
        thread_id = coerce_int(inbound.thread_id)

        # Send typing indicator while waiting for the AI response.
        typing_stop = asyncio.Event()
        typing_task = asyncio.create_task(
            self._typing_pulse(chat_id, thread_id, typing_stop)
        )
        try:
            await self._on_message(inbound)
            self._record_message()
            log.info("telegram.polling.dispatched", {
                "sender_id": sender_id,
                "chat_id": chat_id,
            })
        except Exception as exc:
            log.warning("telegram.polling.dispatch_failed", {"error": str(exc)})
        finally:
            typing_stop.set()
            typing_task.cancel()
            try:
                await typing_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Typing indicator
    # ------------------------------------------------------------------

    async def _typing_pulse(
        self,
        chat_id: str,
        thread_id: Optional[int],
        stop_event: asyncio.Event,
    ) -> None:
        """Send sendChatAction(typing) every ~4 s until *stop_event* is set.

        Failures are silently ignored so a transient API error never disrupts
        the main message-processing pipeline.
        """
        client = await get_http_client()
        while not stop_event.is_set():
            try:
                payload: dict[str, Any] = {"chat_id": chat_id, "action": "typing"}
                if thread_id is not None:
                    payload["message_thread_id"] = thread_id
                url = f"{self._base_url}/sendChatAction"
                await ensure_telegram_http_allowed(url, purpose="Telegram typing indicator")
                await client.post(
                    url,
                    json=payload,
                    timeout=5,
                )
            except Exception:
                pass
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=_TYPING_PULSE_INTERVAL_S)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------------
    # getUpdates
    # ------------------------------------------------------------------

    async def _fetch_updates(
        self,
        offset: Optional[int],
        abort_event: asyncio.Event,
    ) -> Optional[list[dict[str, Any]]]:
        if abort_event.is_set():
            return None

        payload: dict[str, Any] = {
            "timeout": POLL_LONG_TIMEOUT_S,
            "allowed_updates": _ALLOWED_UPDATES,
        }
        if offset is not None:
            payload["offset"] = offset

        client = await get_http_client()
        try:
            url = f"{self._base_url}/getUpdates"
            await ensure_telegram_http_allowed(url, purpose="Telegram poll updates")
            response = await client.post(
                url,
                json=payload,
                timeout=POLL_HTTP_TIMEOUT_S,
            )
        except asyncio.CancelledError:
            return None
        except httpx.TimeoutException:
            if abort_event.is_set():
                return None
            raise RuntimeError("getUpdates timed out")
        except httpx.HTTPError as exc:
            raise RuntimeError(f"getUpdates request failed: {exc}")

        if abort_event.is_set():
            return None

        if response.status_code >= 400:
            try:
                data = response.json()
            except ValueError:
                data = {}
            description = data.get("description") or f"HTTP {response.status_code}"
            raise RuntimeError(f"getUpdates failed ({response.status_code}): {description}")

        try:
            data = response.json()
        except ValueError:
            return []

        return data.get("result") or []

    # ------------------------------------------------------------------
    # Allowlist helpers
    # ------------------------------------------------------------------

    def _is_pairing_enabled(self) -> bool:
        try:
            _, account = resolve_account_config(self._config)
        except ValueError:
            account = self._config
        # Pairing is active whenever the key exists, even if the list is empty.
        # Missing key = open access; empty list = require pairing for everyone.
        return "allowFrom" in account

    def _is_paired(self, sender_id: str) -> bool:
        try:
            _, account = resolve_account_config(self._config)
        except ValueError:
            account = self._config
        allow_from: list[str] = account.get("allowFrom") or []
        return str(sender_id) in [str(a) for a in allow_from]
