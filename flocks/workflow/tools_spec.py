"""Tool metadata types shared by workflow tools and adapter (no circular deps)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from pydantic import BaseModel  # type: ignore
except Exception:
    BaseModel = object  # type: ignore


class DictLikeStr(str):
    """A str that also supports `.get(key, default)` for dict-like access."""

    def __new__(cls, value: Any, /, **meta: Any):  # type: ignore[override]
        obj = str.__new__(cls, "" if value is None else str(value))
        obj._meta = dict(meta)  # type: ignore[attr-defined]
        return obj

    def get(self, key: str, default: Any = None) -> Any:
        meta = getattr(self, "_meta", None)
        if isinstance(meta, dict) and key in meta:
            return meta[key]
        if key in {"result", "text", "value"}:
            return str(self)
        return default


@dataclass(frozen=True)
class ToolSpec:
    """Structured tool definition (name, description, args_schema, signature)."""

    name: str
    description: str = ""
    args_schema: Any = None
    signature: str = ""

    def json_schema(self) -> Optional[Dict[str, Any]]:
        s = self.args_schema
        if s is None:
            return None
        if isinstance(s, dict):
            return s
        try:
            if isinstance(s, type) and issubclass(s, BaseModel):  # type: ignore[arg-type]
                return s.model_json_schema()  # type: ignore[attr-defined]
        except Exception:
            return None
        return None
