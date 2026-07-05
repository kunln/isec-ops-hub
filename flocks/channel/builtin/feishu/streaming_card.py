"""
Feishu streaming card output (Card Kit Streaming API).

When config["streaming"] = true, the card is updated in real-time as the
Agent generates text, providing a streaming experience where users see
progress without waiting for the full reply.

API flow:
    1. POST /cardkit/v1/cards                                    → create streaming card, get card_id
    2. POST /im/v1/messages                                      → send card to session, get message_id
    3. PUT  /cardkit/v1/cards/{id}/elements/content/content      → incremental text update
    4. PATCH /cardkit/v1/cards/{id}/settings                     → disable streaming mode (streaming_mode=false)

Permission requirement: cardkit:card:write
On HTTP 403, automatically falls back to static send and logs a warning.

Throttle strategy (coalesce):
    append() may be called very frequently; coalesce_ms merges writes into
    a single update window to avoid excessive Feishu API requests.

Token cache:
    Reuses the client-layer get_tenant_token cache to avoid double-caching.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid as _uuid_mod
from typing import Optional

from flocks.channel.builtin.feishu.client import (
    _get_http_client,
    _ensure_channel_http_allowed,
    _resolve_account_config,
    _resolve_account_credentials,
    ensure_api_success,
    get_tenant_token,
)
from flocks.channel.builtin.feishu.config import (
    resolve_api_base,
    resolve_receive_id_type,
    resolve_token_url,
    strip_target_prefix,
)
from flocks.utils.log import Log

log = Log.create(service="channel.feishu.streaming_card")

_DEFAULT_COALESCE_MS = 200      # append throttle window (ms)
_DEFAULT_THROTTLE_MS = 100      # max update rate: 10 times/sec
_DEFAULT_PLACEHOLDER = "Thinking..."


# ------------------------------------------------------------------
# Internal utilities
# ------------------------------------------------------------------

async def _get_token(config: dict, account_id: Optional[str]) -> str:
    """Obtain tenant_access_token, reusing the client-layer shared cache."""
    acc_config = _resolve_account_config(config, account_id)
    app_id, app_secret = _resolve_account_credentials(config, account_id)
    return await get_tenant_token(app_id, app_secret, resolve_token_url(acc_config))


async def _api_post(url: str, token: str, body: dict) -> dict:
    await _ensure_channel_http_allowed(url, purpose="Feishu streaming card API request")
    client = await _get_http_client()
    resp = await client.post(
        url,
        json=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    # Raise PermissionError on 403 so callers can degrade gracefully
    if resp.status_code == 403:
        raise PermissionError(f"Feishu API 403 Forbidden: {url}")
    resp.raise_for_status()
    return ensure_api_success(
        resp.json(),
        context=f"Feishu streaming card request failed: POST {url}",
        http_status=resp.status_code,
    )


async def _api_put(url: str, token: str, body: dict) -> dict:
    await _ensure_channel_http_allowed(url, purpose="Feishu streaming card API request")
    client = await _get_http_client()
    resp = await client.put(
        url,
        json=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    return ensure_api_success(
        resp.json(),
        context=f"Feishu streaming card request failed: PUT {url}",
        http_status=resp.status_code,
    )


async def _api_patch(url: str, token: str, body: dict) -> dict:
    await _ensure_channel_http_allowed(url, purpose="Feishu streaming card API request")
    client = await _get_http_client()
    resp = await client.patch(
        url,
        json=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"},
    )
    resp.raise_for_status()
    return ensure_api_success(
        resp.json(),
        context=f"Feishu streaming card request failed: PATCH {url}",
        http_status=resp.status_code,
    )


def _build_card_json(text: str, header: Optional["StreamingCardHeader"] = None) -> dict:
    """Build the Card Kit 2.0 initial card JSON with streaming_mode=true."""
    card: dict = {
        "schema": "2.0",
        "config": {
            "streaming_mode": True,
            "summary": {"content": "[Generating...]"},
            "streaming_config": {
                "print_frequency_ms": {"default": 50},
                "print_step": {"default": 1},
            },
            "wide_screen_mode": True,
        },
        "body": {
            "elements": [
                {"tag": "markdown", "content": text or _DEFAULT_PLACEHOLDER, "element_id": "content"}
            ]
        },
    }
    if header:
        card["header"] = {
            "title": {"tag": "plain_text", "content": header.title},
            "template": header.template or "blue",
        }
    return card


def _truncate_summary(text: str, max_len: int = 50) -> str:
    """Generate summary text for the closed streaming card (single line, truncated)."""
    if not text:
        return ""
    clean = text.replace("\n", " ").strip()
    return clean if len(clean) <= max_len else clean[:max_len - 3] + "..."


# ------------------------------------------------------------------
# StreamingCardHeader
# ------------------------------------------------------------------

class StreamingCardHeader:
    """Streaming card header configuration.

    template values: blue, green, red, orange, purple, indigo,
    wathet, turquoise, yellow, grey, carmine, violet, lime
    """

    def __init__(self, title: str, template: str = "blue") -> None:
        self.title = title
        self.template = template


# ------------------------------------------------------------------
# StreamingCard
# ------------------------------------------------------------------

class StreamingCard:
    """Feishu streaming card controller.

    Typical usage (with Agent streaming output)::

        card = StreamingCard(config=cfg, account_id="default", chat_id="oc_xxx")
        message_id = await card.start()         # send initial placeholder card

        async for chunk in agent.stream():
            await card.append(chunk)            # append incrementally

        await card.finalize(full_text)          # write final text and close streaming mode
    """

    def __init__(
        self,
        config: dict,
        account_id: Optional[str],
        chat_id: str,
        reply_to_id: Optional[str] = None,
        coalesce_ms: int = _DEFAULT_COALESCE_MS,
        header: Optional[StreamingCardHeader] = None,
    ) -> None:
        self._config = config
        self._account_id = account_id
        self._chat_id = chat_id
        self._reply_to_id = reply_to_id
        self._coalesce_ms = coalesce_ms
        self._header = header

        self._card_id: Optional[str] = None
        self._message_id: Optional[str] = None
        self._sequence: int = 1
        self._current_text: str = ""

        # Throttle buffer: holds pending text to write
        self._pending_text: Optional[str] = None
        self._coalesce_task: Optional[asyncio.Task] = None
        self._write_lock = asyncio.Lock()
        self._last_update_time: float = 0.0

        # Whether degraded to static mode (e.g. insufficient permissions)
        self._degraded = False
        self._closed = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> Optional[str]:
        """Create the streaming card and send it to the session. Returns message_id or None on failure."""
        acc_config = _resolve_account_config(self._config, self._account_id)
        api_base = resolve_api_base(acc_config)

        try:
            token = await _get_token(self._config, self._account_id)

            # 1. Create streaming card (card_json format, streaming_mode=true)
            create_url = f"{api_base}/cardkit/v1/cards"
            card_json = _build_card_json(_DEFAULT_PLACEHOLDER, self._header)
            create_body = {
                "type": "card_json",
                "data": json.dumps(card_json),
            }
            create_resp = await _api_post(create_url, token, create_body)

            self._card_id = (create_resp.get("data") or {}).get("card_id", "")
            if not self._card_id:
                self._degraded = True
                return None

            # 2. Send the card to the session
            card_content = json.dumps({"type": "card", "data": {"card_id": self._card_id}})

            if self._reply_to_id:
                reply_url = f"{api_base}/im/v1/messages/{self._reply_to_id}/reply"
                send_resp = await _api_post(reply_url, token, {
                    "msg_type": "interactive",
                    "content": card_content,
                })
            else:
                receive_id = strip_target_prefix(self._chat_id)
                receive_id_type = resolve_receive_id_type(self._chat_id)
                send_url = f"{api_base}/im/v1/messages?receive_id_type={receive_id_type}"
                send_resp = await _api_post(send_url, token, {
                    "receive_id": receive_id,
                    "msg_type": "interactive",
                    "content": card_content,
                })

            self._message_id = (send_resp.get("data") or {}).get("message_id", "")
            if not self._message_id:
                self._degraded = True
                return None
            log.info("feishu.streaming_card.started", {
                "card_id": self._card_id,
                "message_id": self._message_id,
                "account_id": self._account_id,
            })
            return self._message_id

        except PermissionError:
            log.warning("feishu.streaming_card.no_permission", {
                "account_id": self._account_id,
                "hint": "cardkit:card:write permission required; falling back to static send",
            })
            self._degraded = True
            return None
        except Exception as e:
            log.warning("feishu.streaming_card.start_error", {
                "account_id": self._account_id, "error": str(e),
            })
            self._degraded = True
            return None

    async def append(self, text_chunk: str) -> None:
        """Append a text chunk, writing immediately or coalescing within the throttle window."""
        if self._degraded or self._closed or not self._card_id or not text_chunk:
            return

        async with self._write_lock:
            prev = self._pending_text if self._pending_text is not None else self._current_text
            merged = _merge_text(prev, text_chunk)
            if merged == self._current_text:
                return
            self._pending_text = merged

        now_ms = _now_ms()
        if now_ms - self._last_update_time * 1000 < _DEFAULT_THROTTLE_MS:
            if self._coalesce_task and not self._coalesce_task.done():
                self._coalesce_task.cancel()
            self._coalesce_task = asyncio.create_task(self._coalesce_flush())
            return

        # Not throttled: cancel delayed task and write immediately
        if self._coalesce_task and not self._coalesce_task.done():
            self._coalesce_task.cancel()
        async with self._write_lock:
            text = self._pending_text
            self._pending_text = None
        if text and text != self._current_text:
            self._current_text = text
            self._last_update_time = now_ms / 1000.0
            await self._update_card_content(text)

    async def finalize(self, final_text: str) -> None:
        """Write the final text and close streaming mode (streaming_mode=false)."""
        if self._degraded or not self._card_id:
            return

        self._closed = True

        # Cancel throttle task
        if self._coalesce_task and not self._coalesce_task.done():
            self._coalesce_task.cancel()

        async with self._write_lock:
            self._pending_text = None

        # Use final_text as authoritative content (direct replace, not merge)
        # to avoid _merge_text overlap detection truncating long texts.
        if final_text and final_text != self._current_text:
            self._current_text = final_text
            await self._update_card_content(final_text)

        # Close streaming mode
        await self._close_streaming_mode(self._current_text)
        log.info("feishu.streaming_card.finalized", {
            "card_id": self._card_id, "text_len": len(self._current_text),
        })

    async def abort(self, error_text: Optional[str] = None) -> None:
        """Abort with an error message and close streaming mode."""
        if self._degraded or not self._card_id:
            return
        if self._coalesce_task and not self._coalesce_task.done():
            self._coalesce_task.cancel()
        self._closed = True
        msg = error_text or "⚠ An error occurred"
        await self._update_card_content(msg)
        await self._close_streaming_mode(msg)

    @property
    def is_degraded(self) -> bool:
        """True if streaming is unavailable and caller should fall back to static send."""
        return self._degraded

    @property
    def message_id(self) -> Optional[str]:
        return self._message_id

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    async def _coalesce_flush(self) -> None:
        """Wait coalesce_ms then write buffered text."""
        await asyncio.sleep(self._coalesce_ms / 1000.0)
        async with self._write_lock:
            if self._pending_text is None:
                return
            text = self._pending_text
            self._pending_text = None

        if text == self._current_text:
            return

        self._current_text = text
        self._last_update_time = _now_ms() / 1000.0
        await self._update_card_content(text)

    async def _update_card_content(self, text: str) -> None:
        """Call the Card Kit elements/content/content API to update card content."""
        if not self._card_id:
            return
        try:
            acc_config = _resolve_account_config(self._config, self._account_id)
            api_base = resolve_api_base(acc_config)
            token = await _get_token(self._config, self._account_id)

            uid = f"s_{self._card_id}_{self._sequence}"
            content_url = (
                f"{api_base}/cardkit/v1/cards/{self._card_id}/elements/content/content"
            )
            await _api_put(content_url, token, {
                "content": text or _DEFAULT_PLACEHOLDER,
                "sequence": self._sequence,
                "uuid": uid,
            })
            self._sequence += 1

        except Exception as e:
            log.warning("feishu.streaming_card.update_error", {
                "card_id": self._card_id, "error": str(e),
            })

    async def _close_streaming_mode(self, final_text: str) -> None:
        """Call PATCH /cardkit/v1/cards/{id}/settings to disable streaming_mode."""
        if not self._card_id:
            return
        try:
            acc_config = _resolve_account_config(self._config, self._account_id)
            api_base = resolve_api_base(acc_config)
            token = await _get_token(self._config, self._account_id)

            uid = f"c_{self._card_id}_{self._sequence}"
            settings_url = f"{api_base}/cardkit/v1/cards/{self._card_id}/settings"
            await _api_patch(settings_url, token, {
                "settings": json.dumps({
                    "config": {
                        "streaming_mode": False,
                        "summary": {"content": _truncate_summary(final_text)},
                    },
                }),
                "sequence": self._sequence,
                "uuid": uid,
            })
            self._sequence += 1

        except Exception as e:
            log.warning("feishu.streaming_card.close_error", {
                "card_id": self._card_id, "error": str(e),
            })


# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

def _now_ms() -> float:
    import time as _time
    return _time.time() * 1000
def _merge_text(previous: Optional[str], next_text: str) -> str:
    """Merge incremental text chunks, handling overlaps and prefix/suffix relationships."""
    prev = previous or ""
    nxt = next_text or ""
    if not nxt:
        return prev
    if not prev or nxt == prev:
        return nxt
    if nxt.startswith(prev):
        return nxt
    if prev.startswith(nxt):
        return prev
    if nxt in prev:
        return prev
    if prev in nxt:
        return nxt
    # Attempt overlap merge
    max_overlap = min(len(prev), len(nxt))
    for overlap in range(max_overlap, 0, -1):
        if prev[-overlap:] == nxt[:overlap]:
            return prev + nxt[overlap:]
    # Fallback: direct concatenation to avoid token loss
    return prev + nxt
