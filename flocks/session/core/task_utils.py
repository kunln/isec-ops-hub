"""
asyncio Task utilities for session execution.

Provides helpers for fire-and-forget background tasks that log exceptions
instead of silently discarding them (Python's default behavior for
unhandled Task exceptions prints a warning but can be easy to miss).
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Coroutine, Optional, TypeVar

from flocks.utils.log import Log


_log = Log.create(service="session.task")

T = TypeVar("T")


def _make_exception_logger(label: str):
    """Return a done-callback that logs any unhandled Task exception."""
    def _cb(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _log.error(f"{label}.unhandled_exception", {
                "error": str(exc),
                "error_type": type(exc).__name__,
            })
    return _cb


def fire_and_forget(
    coro: Coroutine,
    *,
    label: str,
    name: Optional[str] = None,
) -> asyncio.Task:
    """Schedule *coro* as a background Task and log any exception it raises.

    Unlike bare ``asyncio.create_task()``, the returned Task has a
    done-callback attached so unhandled exceptions surface in logs rather
    than being silently swallowed or emitting a ``Task exception was never
    retrieved`` warning.

    Args:
        coro:   The coroutine to schedule.
        label:  Log key prefix used when reporting exceptions
                (e.g. ``"title_generation"``).
        name:   Optional Task name (useful for debugging with
                ``asyncio.all_tasks()``).

    Returns:
        The created Task.
    """
    task = asyncio.create_task(coro, name=name)
    task.add_done_callback(_make_exception_logger(label))
    return task
