"""
Robust JSON parsing and repair utilities.

Centralises all JSON-recovery logic so that runner, server routes, and any
future consumer share a single, well-tested implementation.
"""

from __future__ import annotations

import json
import re
from typing import Any, Tuple

from flocks.utils.log import Log

log = Log.create(service="utils.json_repair")


# ──────────────────────────────────────────────────────────────────────
# 1. Robust JSON parser
# ──────────────────────────────────────────────────────────────────────

def parse_json_robust(json_str: str) -> Tuple[Any, bool]:
    """Parse JSON robustly, tolerating "Extra data" after the first object.

    Uses ``json.JSONDecoder().raw_decode()`` to extract the first complete
    JSON value when ``json.loads()`` fails with an *Extra data* error.

    Args:
        json_str: Raw JSON string (may contain trailing garbage).

    Returns:
        ``(parsed_value, True)`` on success, ``(None, False)`` on failure.
    """
    if not json_str or not json_str.strip():
        return None, False

    # Fast path – standard parsing
    try:
        return json.loads(json_str), True
    except json.JSONDecodeError as exc:
        if "Extra data" not in str(exc):
            return None, False

    # Slow path – extract first object only
    try:
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(json_str) and json_str[idx] in " \t\n\r":
            idx += 1
        result, end_idx = decoder.raw_decode(json_str, idx)
        log.debug("json_repair.raw_decode_success", {
            "parsed_end": end_idx,
            "total_len": len(json_str),
            "extra_data_len": len(json_str) - end_idx,
        })
        return result, True
    except json.JSONDecodeError:
        return None, False


# ──────────────────────────────────────────────────────────────────────
# 2. String-aware truncated-JSON repair
# ──────────────────────────────────────────────────────────────────────

def repair_truncated_json(json_str: str) -> str:
    """Repair truncated JSON with proper string-boundary awareness.

    Unlike naive brace / bracket counting, this function uses a mini
    state-machine that tracks whether the scanner is currently inside a
    JSON string literal.  Escaped characters (``\\``, ``\\"``, ``\\n``,
    ``\\uXXXX``, …) are handled correctly so that braces / brackets
    embedded in string *values* are never mis-counted.

    **Typical truncation patterns this fixes:**

    1. *Truncated inside a string value* ::

           {"content": "long text that gets cut o
           → close string, close remaining braces

    2. *Truncated between key-value pairs* ::

           {"content": "text", "filePa
           → remove incomplete pair, close braces

    3. *Trailing comma* ::

           {"content": "text",
           → remove comma, close braces

    4. *Nested JSON inside a string* (e.g. ``write`` tool content) ::

           {"content": "{\\\"nodes\\\":[{\\\"id\\\":\\\"a\\\""}
           Only **1** structural brace is open; inner ones live in a string.

    Args:
        json_str: Potentially truncated JSON string.

    Returns:
        Best-effort repaired JSON string (may still be semantically
        incomplete but should be *syntactically* valid JSON).
    """
    if not json_str or not json_str.strip():
        return json_str

    s = json_str.rstrip()
    in_string = False
    escape_next = False
    stack: list[str] = []  # structural closers needed, e.g. '}', ']'

    for ch in s:
        if escape_next:
            escape_next = False
            continue

        if in_string:
            if ch == "\\":
                escape_next = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                stack.append("}")
            elif ch == "[":
                stack.append("]")
            elif ch in ("}", "]"):
                if stack and stack[-1] == ch:
                    stack.pop()

    repaired = s

    # ── 1. Close a truncated string ──────────────────────────────────
    if in_string:
        # Drop a trailing incomplete escape or unicode escape (\uXX…)
        repaired = re.sub(r"\\(?:u[0-9a-fA-F]{0,3})?$", "", repaired)
        repaired += '"'

    # ── 2. Remove trailing comma ─────────────────────────────────────
    stripped = repaired.rstrip()
    if stripped.endswith(","):
        repaired = stripped[:-1]

    # ── 3. Handle truncation after a colon (incomplete value) ────────
    stripped = repaired.rstrip()
    if stripped.endswith(":"):
        # e.g. {"key": "val", "incomp":  — drop back to last comma/brace
        last_comma = stripped.rfind(",")
        last_brace = stripped.rfind("{")
        cut = max(last_comma, last_brace)
        if cut > 0:
            repaired = stripped[:cut] if stripped[cut] == "," else stripped[: cut + 1]

    # ── 4. Close remaining open structures ───────────────────────────
    for closer in reversed(stack):
        repaired += closer

    if repaired != s:
        log.debug("json_repair.repaired", {
            "original_len": len(s),
            "repaired_len": len(repaired),
            "was_in_string": in_string,
            "unclosed_structures": len(stack),
        })

    return repaired
