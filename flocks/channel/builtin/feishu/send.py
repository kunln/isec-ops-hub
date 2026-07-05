"""
Feishu message sending helpers.

Supports:
- Plain text (msg_type=text)
- Rich-text post with markdown (msg_type=post, default)
- Interactive card with markdown (msg_type=interactive, renderMode=card)
- Reply with auto-fallback when the target message is withdrawn
- Message editing (PATCH /im/v1/messages/{id})
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from flocks.channel.builtin.feishu.client import (
    FeishuApiError,
    api_request_for_account,
)
from flocks.channel.builtin.feishu.config import (
    resolve_receive_id_type,
    strip_target_prefix,
)
from flocks.utils.log import Log

log = Log.create(service="channel.feishu.send")

# Feishu error codes for withdrawn / not-found messages
_WITHDRAWN_REPLY_CODES = {230011, 231003}

_DEFAULT_TEXT_CHUNK_LIMIT = 4000


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _build_text_payload(text: str) -> tuple[str, str]:
    """Return (content_json, msg_type) for plain text."""
    return json.dumps({"text": text}), "text"


def _build_post_payload(text: str) -> tuple[str, str]:
    """Return (content_json, msg_type) for a post message with markdown support.

    Feishu ``post`` messages render ``tag=md`` elements as markdown
    in the desktop and mobile clients.
    """
    content = json.dumps({
        "zh_cn": {
            "content": [[{"tag": "md", "text": text}]],
        },
    })
    return content, "post"


def _build_card_payload(text: str) -> tuple[str, str]:
    """Return (content_json, msg_type) for an interactive markdown card."""
    card = {
        "schema": "2.0",
        "config": {"wide_screen_mode": True},
        "body": {
            "elements": [{"tag": "markdown", "content": text}],
        },
    }
    return json.dumps(card), "interactive"


def _build_payload(text: str, render_mode: str) -> tuple[str, str]:
    """Select the appropriate payload builder based on *render_mode*.

    - ``"plain"``  → msg_type=text (no markdown)
    - ``"card"``   → msg_type=interactive (full markdown card)
    - ``"auto"`` / anything else → msg_type=post (markdown via tag=md)
    """
    if render_mode == "plain":
        return _build_text_payload(text)
    if render_mode == "card":
        return _build_card_payload(text)
    return _build_post_payload(text)


# ---------------------------------------------------------------------------
# Withdrawn-reply detection
# ---------------------------------------------------------------------------

def _is_withdrawn_reply_error(exc: Exception) -> bool:
    """Return True when *exc* indicates the reply target was withdrawn."""
    if isinstance(exc, FeishuApiError) and exc.code in _WITHDRAWN_REPLY_CODES:
        return True
    msg = str(exc).lower()
    return "withdrawn" in msg or "not found" in msg


# ---------------------------------------------------------------------------
# Core send
# ---------------------------------------------------------------------------

async def _send_direct(
    *,
    config: dict,
    to: str,
    content: str,
    msg_type: str,
    account_id: Optional[str],
) -> Dict[str, Any]:
    """Send a direct (non-reply) message."""
    raw_to = strip_target_prefix(to)
    receive_id_type = resolve_receive_id_type(to)
    data = await api_request_for_account(
        "POST", "/im/v1/messages",
        config=config,
        account_id=account_id,
        params={"receive_id_type": receive_id_type},
        json_body={
            "receive_id": raw_to,
            "msg_type": msg_type,
            "content": content,
        },
    )
    return data


def _chunk_text(text: str, limit: int) -> list[str]:
    """Split long text into chunks, preferring newline boundaries."""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining)
            break
        # Try to split at last newline within limit
        cut = remaining[:limit].rfind("\n")
        if cut <= limit // 4:
            cut = limit
        chunk = remaining[:cut].rstrip()
        remaining = remaining[cut:].lstrip("\n")
        if chunk:
            chunks.append(chunk)
    return chunks or [text]


async def _send_single(
    *,
    config: dict,
    to: str,
    content: str,
    msg_type: str,
    reply_to_id: Optional[str],
    account_id: Optional[str],
) -> Dict[str, Any]:
    """Send a single message, with reply-fallback logic."""
    if reply_to_id:
        try:
            data = await api_request_for_account(
                "POST", f"/im/v1/messages/{reply_to_id}/reply",
                config=config,
                account_id=account_id,
                json_body={"msg_type": msg_type, "content": content},
            )
        except Exception as exc:
            if not _is_withdrawn_reply_error(exc):
                raise
            log.warning("feishu.send.reply_fallback", {
                "reply_to_id": reply_to_id, "reason": str(exc),
            })
            if not to:
                raise ValueError(
                    f"Cannot fallback from withdrawn reply: 'to' is empty (reply_to_id={reply_to_id})"
                ) from exc
            data = await _send_direct(
                config=config, to=to, content=content, msg_type=msg_type,
                account_id=account_id,
            )
    else:
        data = await _send_direct(
            config=config, to=to, content=content, msg_type=msg_type,
            account_id=account_id,
        )
    return data


def _extract_message_result(data: dict, *, context: str) -> Dict[str, Any]:
    msg_data = data.get("data") or {}
    message_id = msg_data.get("message_id", "")
    if not message_id:
        raise RuntimeError(f"{context}: missing message_id in response")
    return {
        "message_id": message_id,
        "chat_id": msg_data.get("chat_id"),
    }


async def send_payload_feishu(
    *,
    config: dict,
    to: str,
    content: str,
    msg_type: str,
    reply_to_id: Optional[str] = None,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send an already-built Feishu payload and validate the returned identifiers."""
    data = await _send_single(
        config=config,
        to=to,
        content=content,
        msg_type=msg_type,
        reply_to_id=reply_to_id,
        account_id=account_id,
    )
    return _extract_message_result(data, context="Feishu send failed")


async def send_message_feishu(
    *,
    config: dict,
    to: str,
    text: str,
    reply_to_id: Optional[str] = None,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a text/post/card message via the Feishu IM API.

    Long texts are automatically chunked into multiple messages.

    The message format is controlled by ``config["renderMode"]``:
    - ``"plain"`` → plain text
    - ``"card"``  → interactive markdown card
    - otherwise  → post with markdown (default)

    When ``reply_to_id`` is set the reply endpoint is used, with automatic
    fallback to a direct message if the target has been withdrawn.

    Returns ``{"message_id": "...", "chat_id": "..."}`` on success.
    Raises on unrecoverable API errors.
    """
    render_mode = config.get("renderMode", "auto")
    chunk_limit = int(config.get("textChunkLimit", _DEFAULT_TEXT_CHUNK_LIMIT))
    chunks = _chunk_text(text, chunk_limit)

    last_data: Dict[str, Any] = {}
    for i, chunk in enumerate(chunks):
        content, msg_type = _build_payload(chunk, render_mode)
        # Only the first chunk is a reply; subsequent chunks are direct sends
        effective_reply = reply_to_id if i == 0 else None
        last_data = await send_payload_feishu(
            config=config, to=to, content=content, msg_type=msg_type,
            reply_to_id=effective_reply, account_id=account_id,
        )
    return last_data


async def edit_message_feishu(
    *,
    config: dict,
    message_id: str,
    text: str,
    account_id: Optional[str] = None,
) -> None:
    """Edit an existing Feishu message in-place (PATCH /im/v1/messages/{id}).

    Note: Feishu only allows editing messages within 24 hours of sending.
    The message format mirrors ``send_message_feishu`` (respects renderMode).
    """
    render_mode = config.get("renderMode", "auto")
    content, msg_type = _build_payload(text, render_mode)
    await api_request_for_account(
        "PATCH", f"/im/v1/messages/{message_id}",
        config=config,
        account_id=account_id,
        json_body={"msg_type": msg_type, "content": content},
    )
