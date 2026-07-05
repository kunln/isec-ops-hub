"""
Langfuse observability helper.

This module provides a tiny wrapper with graceful no-op fallback:
- If Langfuse is not installed or credentials are missing, calls do nothing.
- If Langfuse is configured, traces/generations/spans are reported.
"""

from __future__ import annotations

import os
import contextvars
from typing import Any, Dict, Optional

from flocks.utils.log import Log

log = Log.create(service="observability.langfuse")


class _NoopObservation:
    """No-op observation object used when Langfuse is unavailable."""

    def __init__(self, obs_type: str):
        self.obs_type = obs_type

    def generation(self, **_: Any) -> "_NoopObservation":
        return _NoopObservation("generation")

    def span(self, **_: Any) -> "_NoopObservation":
        return _NoopObservation("span")

    def update(self, **_: Any) -> None:
        return None

    def end(self, **_: Any) -> None:
        return None


_client: Optional[Any] = None
_initialized = False
_current_observation: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "langfuse_current_observation",
    default=None,
)


def _filter_none(values: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def _truncate_value(value: Any, max_chars: int = 8000) -> Any:
    if isinstance(value, str):
        if len(value) <= max_chars:
            return value
        return value[:max_chars] + f"...[truncated:{len(value) - max_chars}]"
    return value


def _sanitize_payload(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in value.items():
            sanitized[k] = _sanitize_payload(v)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_payload(v) for v in value]
    return _truncate_value(value)


def initialize() -> None:
    """Initialize Langfuse client once (no-op when unavailable)."""
    global _client, _initialized
    if _initialized:
        return
    _initialized = True

    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    # Keep backward compatibility with old env names while supporting
    # official Langfuse naming used in docs.
    host = (
        os.getenv("LANGFUSE_HOST")
        or os.getenv("LANGFUSE_BASE_URL")
        or os.getenv("LANGFUSE_BASEURL")
    )
    enabled = os.getenv("FLOCKS_LANGFUSE_ENABLED", "true").lower() != "false"

    if not enabled:
        log.info("langfuse.disabled_by_env")
        return
    if not public_key or not secret_key:
        log.info("langfuse.not_configured")
        return

    try:
        from langfuse import Langfuse

        kwargs = _filter_none(
            {
                "public_key": public_key,
                "secret_key": secret_key,
                "host": host,
            }
        )
        _client = Langfuse(**kwargs)
        log.info("langfuse.initialized", {"host": host or "default"})
    except Exception as exc:
        log.warn("langfuse.init_failed", {"error": str(exc)})
        _client = None


def _get_client() -> Optional[Any]:
    if not _initialized:
        initialize()
    return _client


def create_trace(
    *,
    name: str,
    input: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> Any:
    client = _get_client()
    if not client:
        return _NoopObservation("trace")

    payload = _filter_none(
        {
            "name": name,
            "input": _sanitize_payload(input),
            "metadata": _sanitize_payload(metadata) if metadata else None,
            "session_id": session_id,
            "user_id": user_id,
            "tags": tags,
        }
    )
    try:
        # Old SDKs may expose .trace(), newer SDKs are OTEL-native and expose
        # .start_span() / .start_observation().
        if hasattr(client, "trace"):
            return client.trace(**payload)
        trace_obs = client.start_span(
            name=name,
            input=payload.get("input"),
            metadata=payload.get("metadata"),
        )
        # Best-effort enrich current trace with session/user dimensions.
        try:
            client.update_current_trace(
                session_id=session_id,
                user_id=user_id,
                tags=tags,
                input=payload.get("input"),
                metadata=payload.get("metadata"),
            )
        except Exception:
            pass
        return trace_obs
    except Exception as exc:
        log.warn("langfuse.trace_failed", {"error": str(exc), "name": name})
        return _NoopObservation("trace")


def create_generation(
    *,
    parent: Any = None,
    name: str,
    model: str,
    input: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Any:
    client = _get_client()
    if not client:
        return _NoopObservation("generation")
    if parent is None:
        parent = get_current_observation()

    payload = _filter_none(
        {
            "name": name,
            "model": model,
            "input": _sanitize_payload(input),
            "metadata": _sanitize_payload(metadata) if metadata else None,
        }
    )
    try:
        if parent and hasattr(parent, "generation"):
            return parent.generation(**payload)
        if parent and hasattr(parent, "start_generation"):
            return parent.start_generation(**payload)
        if parent and hasattr(parent, "start_observation"):
            return parent.start_observation(as_type="generation", **payload)
        if hasattr(client, "start_generation"):
            return client.start_generation(**payload)
        if hasattr(client, "start_observation"):
            return client.start_observation(as_type="generation", **payload)
    except Exception as exc:
        log.warn("langfuse.generation_failed", {"error": str(exc), "name": name})
    return _NoopObservation("generation")


def create_span(
    *,
    parent: Any = None,
    name: str,
    input: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Any:
    client = _get_client()
    if not client:
        return _NoopObservation("span")
    if parent is None:
        parent = get_current_observation()

    payload = _filter_none(
        {
            "name": name,
            "input": _sanitize_payload(input),
            "metadata": _sanitize_payload(metadata) if metadata else None,
        }
    )
    try:
        if parent and hasattr(parent, "span"):
            return parent.span(**payload)
        if parent and hasattr(parent, "start_span"):
            return parent.start_span(**payload)
        if parent and hasattr(parent, "start_observation"):
            return parent.start_observation(as_type="span", **payload)
        if hasattr(client, "start_span"):
            return client.start_span(**payload)
        if hasattr(client, "start_observation"):
            return client.start_observation(as_type="span", **payload)
    except Exception as exc:
        log.warn("langfuse.span_failed", {"error": str(exc), "name": name})
    return _NoopObservation("span")


def end_observation(
    observation: Any,
    *,
    output: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
    usage: Optional[Dict[str, Any]] = None,
    level: Optional[str] = None,
    status_message: Optional[str] = None,
) -> None:
    if not observation:
        return

    payload = _filter_none(
        {
            "output": _sanitize_payload(output),
            "metadata": _sanitize_payload(metadata) if metadata else None,
            "level": level,
            "status_message": status_message,
        }
    )
    if usage:
        payload["usage"] = usage

    try:
        if hasattr(observation, "end"):
            observation.end(**payload)
            return
    except TypeError:
        try:
            observation.end()
            return
        except Exception:
            pass
    except Exception:
        pass

    try:
        if hasattr(observation, "update"):
            observation.update(**payload)
    except Exception as exc:
        log.debug("langfuse.end_fallback_update_failed", {"error": str(exc)})


def is_active() -> bool:
    """Return True when Langfuse is initialized and has a live client."""
    return _get_client() is not None


def shutdown() -> None:
    """Flush pending events and shut down the Langfuse client."""
    client = _get_client()
    if not client:
        return
    try:
        if hasattr(client, "flush"):
            client.flush()
    except Exception as exc:
        log.warn("langfuse.flush_failed", {"error": str(exc)})
    try:
        if hasattr(client, "shutdown"):
            client.shutdown()
    except Exception as exc:
        log.debug("langfuse.shutdown_failed", {"error": str(exc)})


class ObservationScope:
    """
    Context manager that mirrors openai-agents style trace/span scopes.

    It keeps current observation in a context variable so child observations
    can be created without manually threading parent references everywhere.
    """

    def __init__(self, observation: Any):
        self.observation = observation
        self._token: Optional[contextvars.Token] = None
        self._ended = False

    def __enter__(self) -> "ObservationScope":
        self._token = _current_observation.set(self.observation)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_val and not self._ended:
            end_observation(
                self.observation,
                output=str(exc_val),
                level="ERROR",
                status_message="exception",
            )
            self._ended = True
        if self._token is not None:
            _current_observation.reset(self._token)
            self._token = None

    def end(self, **kwargs: Any) -> None:
        if self._ended:
            return
        end_observation(self.observation, **kwargs)
        self._ended = True


def get_current_observation() -> Any:
    """Return current observation from context (if any)."""
    return _current_observation.get()


def trace_scope(
    *,
    name: str,
    input: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> ObservationScope:
    obs = create_trace(
        name=name,
        input=input,
        metadata=metadata,
        session_id=session_id,
        user_id=user_id,
        tags=tags,
    )
    return ObservationScope(obs)


def generation_scope(
    *,
    name: str,
    model: str,
    input: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
    parent: Any = None,
) -> ObservationScope:
    parent_obs = parent or get_current_observation()
    obs = create_generation(
        parent=parent_obs,
        name=name,
        model=model,
        input=input,
        metadata=metadata,
    )
    return ObservationScope(obs)


def span_scope(
    *,
    name: str,
    input: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
    parent: Any = None,
) -> ObservationScope:
    parent_obs = parent or get_current_observation()
    obs = create_span(
        parent=parent_obs,
        name=name,
        input=input,
        metadata=metadata,
    )
    return ObservationScope(obs)
