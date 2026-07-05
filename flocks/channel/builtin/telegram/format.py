"""
Markdown → Telegram HTML conversion and text chunking.

Telegram supports a limited HTML subset:
  <b>, <i>, <s>, <u>, <code>, <pre><code>, <a href="...">, <tg-spoiler>

We convert the most common Markdown markers to this format so that AI
responses rendered in Markdown are displayed with rich formatting in the app.
"""

from __future__ import annotations

import html as _html
import re


# Maximum bytes for a single Telegram message
TELEGRAM_CHUNK_LIMIT: int = 4096


def markdown_to_telegram_html(text: str) -> str:
    """Convert a Markdown string to Telegram-compatible HTML.

    Supported syntax:
      - **bold** / __bold__
      - *italic* / _italic_  (word-boundary aware)
      - ***bold italic***
      - ``code``  (inline)
      - ```lang\\ncode block```
      - ~~strikethrough~~
      - [link text](url)
      - # / ## / ### headers  →  <b>text</b>

    HTML special characters in user-supplied content are escaped before
    the Markdown markers are applied, so the output is always safe to pass
    directly to Telegram's ``parse_mode="HTML"``.
    """
    if not text:
        return ""

    placeholders: list[str] = []

    def protect(html_fragment: str) -> str:
        idx = len(placeholders)
        placeholders.append(html_fragment)
        return f"\x01P{idx}\x01"

    result = text

    # 1. Protect fenced code blocks  ``` ... ```
    def _code_block(m: re.Match) -> str:
        lang = (m.group(1) or "").strip()
        code = _html.escape(m.group(2), quote=False)
        if lang:
            return protect(f'<pre><code class="language-{lang}">{code}</code></pre>')
        return protect(f"<pre><code>{code}</code></pre>")

    result = re.sub(r"```(\w*)\n?(.*?)```", _code_block, result, flags=re.DOTALL)

    # 2. Protect inline code  ` ... `
    def _inline_code(m: re.Match) -> str:
        return protect(f"<code>{_html.escape(m.group(1), quote=False)}</code>")

    result = re.sub(r"`([^`\n]+)`", _inline_code, result)

    # 3. Escape HTML in the rest (placeholders survive: no <, >, & in \x01P0\x01)
    result = _html.escape(result, quote=False)

    # 4. Apply Markdown markers (strict order: longest markers first)
    # Bold + italic: ***text***
    result = re.sub(r"\*\*\*(.+?)\*\*\*", r"<b><i>\1</i></b>", result, flags=re.DOTALL)
    # Bold: **text** or __text__
    result = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", result, flags=re.DOTALL)
    result = re.sub(r"__([^_\n]+)__", r"<b>\1</b>", result)
    # Italic: *text* — only outside word characters to avoid matching foo*bar*baz
    result = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<i>\1</i>", result)
    # Italic: _text_ — same boundary rule, no underscores inside
    result = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"<i>\1</i>", result)
    # Strikethrough: ~~text~~
    result = re.sub(r"~~(.+?)~~", r"<s>\1</s>", result, flags=re.DOTALL)
    # Links: [text](url)
    result = re.sub(
        r"\[([^\]]+)\]\((https?://[^)]+)\)",
        lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>',
        result,
    )
    # Headers: # Heading → <b>Heading</b>
    result = re.sub(r"^#{1,6}\s+(.+)$", r"<b>\1</b>", result, flags=re.MULTILINE)

    # 5. Restore protected fragments
    for i, fragment in enumerate(placeholders):
        result = result.replace(f"\x01P{i}\x01", fragment)

    return result


def split_html_chunks(html: str, limit: int = TELEGRAM_CHUNK_LIMIT) -> list[str]:
    """Split *html* into a list of strings each at most *limit* characters long.

    Splits preferentially at paragraph boundaries (``\\n\\n``), then line
    boundaries (``\\n``), and only falls back to hard character-position
    splits when a single line exceeds *limit*.  This keeps the number of
    messages predictable and avoids cutting in the middle of sentences.
    """
    if not html:
        return []
    if len(html) <= limit:
        return [html]

    chunks: list[str] = []
    current = ""

    for para in re.split(r"\n\n", html):
        sep = "\n\n" if current else ""
        candidate = f"{current}{sep}{para}"
        if len(candidate) <= limit:
            current = candidate
            continue

        if current:
            chunks.append(current)
            current = ""

        # Try splitting the paragraph by line
        for line in para.split("\n"):
            sep = "\n" if current else ""
            candidate = f"{current}{sep}{line}"
            if len(candidate) <= limit:
                current = candidate
            else:
                if current:
                    chunks.append(current)
                    current = ""
                # Hard-split a single line
                while len(line) > limit:
                    chunks.append(line[:limit])
                    line = line[limit:]
                current = line

    if current:
        chunks.append(current)

    return chunks or [html[:limit]]
