"""
Feishu inbound message debouncing and merging.

When a user sends multiple messages in quick succession, they are
automatically merged into one before triggering the on_message callback,
avoiding a full Agent invocation per message.

Debounce key (isolation granularity):
    feishu:{account_id}:{chat_id}:thread:{root_id|"main"}:{sender_id}

Merge rules:
- text        : texts joined with \\n (duplicate blank lines removed)
- mentioned   : True if any message is @-mentioned
- mention_text: taken from the last message
- message_id  : taken from the last message (used for reply_to_id)
- Control commands (/reset /new /model etc.) bypass debounce immediately
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from flocks.channel.base import ChatType, InboundMessage
from flocks.utils.log import Log

log = Log.create(service="channel.feishu.debounce")

# Default debounce window (ms); 0 = disabled
_DEFAULT_DEBOUNCE_MS = 800

# Control command prefixes that bypass debounce immediately
_CONTROL_PREFIXES = ("/reset", "/new", "/model", "/help", "/status", "/cancel")


def _is_control_command(text: str) -> bool:
    t = text.strip().lower()
    return any(t.startswith(p) for p in _CONTROL_PREFIXES)


def _is_text_message(msg: "InboundMessage") -> bool:
    """Only plain text messages should be debounced.

    Non-text types (image, file, interactive, share_chat, merge_forward, etc.)
    should be dispatched immediately.
    """
    raw = msg.raw
    if isinstance(raw, dict):
        msg_type = (raw.get("event") or {}).get("message", {}).get("message_type", "")
        if msg_type and msg_type != "text":
            return False
    return True


def _merge_texts(texts: list[str]) -> str:
    """Join multiple texts into one, collapsing excess blank lines."""
    combined = "\n".join(t for t in texts if t.strip())
    # Collapse 3+ consecutive newlines into 2
    return re.sub(r"\n{3,}", "\n\n", combined).strip()


def _build_debounce_key(msg: InboundMessage) -> str:
    root = msg.thread_id or "main"
    return f"feishu:{msg.account_id}:{msg.chat_id}:thread:{root}:{msg.sender_id}"


# ------------------------------------------------------------------
# Debounce window data
# ------------------------------------------------------------------

@dataclass
class _Window:
    key: str
    entries: list[InboundMessage] = field(default_factory=list)
    timer: Optional[asyncio.TimerHandle] = field(default=None, compare=False)


# ------------------------------------------------------------------
# InboundDebouncer
# ------------------------------------------------------------------

class InboundDebouncer:
    """Buffer messages per-session and merge them before firing the callback.

    Usage::

        debouncer = InboundDebouncer(
            debounce_ms=800,
            on_flush=on_message,
        )

        # Inside a WebSocket event_handler:
        await debouncer.enqueue(msg)
    """

    def __init__(
        self,
        debounce_ms: int = _DEFAULT_DEBOUNCE_MS,
        on_flush: Optional[Callable[[InboundMessage], Awaitable[None]]] = None,
        on_suppressed_ids: Optional[Callable[[list[str]], Awaitable[None]]] = None,
    ) -> None:
        self._debounce_ms = debounce_ms
        self._on_flush = on_flush
        # Callback: notify the list of merged/dropped message_ids for dedup persistence
        self._on_suppressed_ids = on_suppressed_ids
        self._windows: dict[str, _Window] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_callback(self, cb: Callable[[InboundMessage], Awaitable[None]]) -> None:
        self._on_flush = cb

    def set_suppressed_ids_callback(
        self, cb: Callable[[list[str]], Awaitable[None]]
    ) -> None:
        self._on_suppressed_ids = cb

    def set_debounce_ms(self, debounce_ms: int) -> None:
        self._debounce_ms = debounce_ms

    async def enqueue(self, msg: InboundMessage) -> None:
        """Add a message to the debounce queue.

        Control commands and media messages bypass immediately; plain text
        enters the debounce window.  If the window already contains messages
        and the new one is a control command, the window is flushed first,
        then the control command is fired separately.
        """
        # Debounce disabled, media message, or non-text → dispatch immediately
        if self._debounce_ms <= 0 or msg.media_url or not _is_text_message(msg):
            await self._fire(msg)
            return

        text = (msg.mention_text or msg.text).strip()

        if _is_control_command(text):
            log.debug("feishu.debounce.bypass_control", {
                "account_id": msg.account_id, "cmd": text.split()[0],
            })
            # Flush any pending window first to preserve ordering
            key = _build_debounce_key(msg)
            if key in self._windows:
                win = self._windows.pop(key)
                if win.timer is not None:
                    win.timer.cancel()
                if win.entries:
                    merged = _merge_entries(_dedup_by_message_id(win.entries))
                    suppressed = [
                        e.message_id for e in _dedup_by_message_id(win.entries)
                        if e.message_id and e.message_id != merged.message_id
                    ]
                    if suppressed and self._on_suppressed_ids:
                        try:
                            await self._on_suppressed_ids(suppressed)
                        except Exception as e:
                            log.warning("feishu.debounce.suppressed_record_error", {"error": str(e)})
                    await self._fire(merged)
            await self._fire(msg)
            return

        key = _build_debounce_key(msg)
        loop = self._get_loop()

        if key in self._windows:
            win = self._windows[key]
            if win.timer is not None:
                win.timer.cancel()
            win.entries.append(msg)
        else:
            win = _Window(key=key, entries=[msg])
            self._windows[key] = win

        delay = self._debounce_ms / 1000.0
        win.timer = loop.call_later(delay, self._schedule_flush, key)

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.get_running_loop()
        return self._loop

    def _schedule_flush(self, key: str) -> None:
        """Called by call_later on the event-loop thread to schedule a flush coroutine."""
        asyncio.ensure_future(self._flush_window(key))

    async def _flush_window(self, key: str) -> None:
        win = self._windows.pop(key, None)
        if not win or not win.entries:
            return

        deduped = _dedup_by_message_id(win.entries)
        merged = _merge_entries(deduped)
        dispatched_id = merged.message_id

        # Write back suppressed (un-dispatched) message_ids to the dedup persistence
        # layer so they are not reprocessed after a WebSocket reconnect.
        suppressed = [
            e.message_id for e in deduped
            if e.message_id and e.message_id != dispatched_id
        ]
        if suppressed and self._on_suppressed_ids:
            try:
                await self._on_suppressed_ids(suppressed)
            except Exception as e:
                log.warning("feishu.debounce.suppressed_record_error", {"error": str(e)})

        log.debug("feishu.debounce.flush", {
            "key": key,
            "count": len(win.entries),
            "deduped": len(deduped),
            "suppressed": len(suppressed),
            "merged_len": len(merged.text),
        })
        await self._fire(merged)

    async def _fire(self, msg: InboundMessage) -> None:
        if self._on_flush:
            try:
                await self._on_flush(msg)
            except Exception as e:
                log.error("feishu.debounce.callback_error", {"error": str(e)})


# ------------------------------------------------------------------
# Message merge logic
# ------------------------------------------------------------------

def _dedup_by_message_id(entries: list[InboundMessage]) -> list[InboundMessage]:
    """Deduplicate within the window: keep only the last entry per message_id."""
    seen_ids: set[str] = set()
    deduped: list[InboundMessage] = []
    for entry in reversed(entries):
        if entry.message_id not in seen_ids:
            seen_ids.add(entry.message_id)
            deduped.insert(0, entry)
    return deduped


def _merge_entries(entries: list[InboundMessage]) -> InboundMessage:
    """Merge multiple InboundMessages into one."""
    if len(entries) == 1:
        return entries[0]

    last = entries[-1]

    # Merge texts: use mention_text (@ key already stripped) from each entry
    texts = [(e.mention_text or e.text) for e in entries]
    merged_text = _merge_texts(texts)

    # mentioned: OR
    mentioned = any(e.mentioned for e in entries)

    return InboundMessage(
        channel_id=last.channel_id,
        account_id=last.account_id,
        message_id=last.message_id,        # use the last message's message_id
        sender_id=last.sender_id,
        sender_name=last.sender_name,
        chat_id=last.chat_id,
        chat_type=last.chat_type,
        text=merged_text,
        media_url=last.media_url,
        reply_to_id=last.reply_to_id,
        thread_id=last.thread_id,
        mentioned=mentioned,
        mention_text=merged_text,
        raw=last.raw,
    )


# ------------------------------------------------------------------
# Global registry: one InboundDebouncer per account_id
# ------------------------------------------------------------------

_registry: dict[str, InboundDebouncer] = {}


def get_debouncer(
    account_id: str,
    debounce_ms: int = _DEFAULT_DEBOUNCE_MS,
    on_flush: Optional[Callable[[InboundMessage], Awaitable[None]]] = None,
    on_suppressed_ids: Optional[Callable[[list[str]], Awaitable[None]]] = None,
) -> InboundDebouncer:
    """Return (or lazily create) the InboundDebouncer for the given account."""
    if account_id not in _registry:
        _registry[account_id] = InboundDebouncer(
            debounce_ms=debounce_ms,
            on_flush=on_flush,
            on_suppressed_ids=on_suppressed_ids,
        )
    else:
        _registry[account_id].set_debounce_ms(debounce_ms)
        if on_flush is not None:
            _registry[account_id].set_callback(on_flush)
        if on_suppressed_ids is not None:
            _registry[account_id].set_suppressed_ids_callback(on_suppressed_ids)
    return _registry[account_id]
