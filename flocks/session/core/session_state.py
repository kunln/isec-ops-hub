"""
Session state tracking for Flocks compatibility.

**Single-process limitation**: all state lives in module-level globals
protected by a ``threading.Lock``.  This design is intentional — the Flocks
Python server runs as a single process (uvicorn with one worker) and all
session state is scoped to that process.

If multi-process deployment is needed in the future (e.g. gunicorn with
multiple workers), this module must be replaced with a shared backend
(Redis, database, or IPC).

Module-level globals are protected by a threading.Lock so that concurrent
asyncio tasks (which may run in different threads when using a thread-pool
executor) do not corrupt the shared dicts.

Note: asyncio.Lock would be more natural here, but these functions are
called from both sync and async contexts, so threading.Lock is safer.
"""

import threading
from typing import Dict, Optional, Set

from flocks.utils.log import Log


log = Log.create(service="session.state")

_lock = threading.Lock()

# The "main" session ID — set once when the server starts a top-level
# session, read by subagents to know their parent context.
_main_session_id: Optional[str] = None
# session_id → agent name mapping (tracks which agent is running each session)
_session_agent: Dict[str, str] = {}
# Set of session IDs that are subagent (delegated) sessions
_subagent_sessions: Set[str] = set()


def set_main_session(session_id: Optional[str]) -> None:
    global _main_session_id
    with _lock:
        _main_session_id = session_id
    log.debug("session.main.set", {"session_id": session_id})


def get_main_session_id() -> Optional[str]:
    with _lock:
        return _main_session_id


def set_session_agent(session_id: str, agent: str) -> None:
    with _lock:
        _session_agent[session_id] = agent
    log.debug("session.agent.set", {"session_id": session_id, "agent": agent})


def get_session_agent(session_id: str) -> Optional[str]:
    with _lock:
        return _session_agent.get(session_id)


def clear_session_agent(session_id: str) -> None:
    with _lock:
        _session_agent.pop(session_id, None)
    log.debug("session.agent.cleared", {"session_id": session_id})


def add_subagent_session(session_id: str) -> None:
    with _lock:
        _subagent_sessions.add(session_id)
    log.debug("session.subagent.added", {"session_id": session_id})


def remove_subagent_session(session_id: str) -> None:
    with _lock:
        _subagent_sessions.discard(session_id)
    log.debug("session.subagent.removed", {"session_id": session_id})


def list_subagent_sessions() -> Set[str]:
    with _lock:
        return set(_subagent_sessions)
