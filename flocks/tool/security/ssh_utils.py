"""
Shared SSH utilities for host security tools.

Provides common SSH connection logic, credential resolution,
audit logging, and session-level connection pooling used by
both ssh_host_cmd and ssh_run_script tools.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asyncssh

from flocks.utils.log import Log

log = Log.create(service="tool.ssh_utils")

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

AUDIT_LOG_PATH = Path.home() / ".flocks" / "audit" / "ssh_commands.log"


def audit_log(
    session_id: str,
    host: str,
    username: str,
    port: int,
    command: str,
    decision: str,
    source: str,
    exit_code: Optional[int] = None,
    output_bytes: int = 0,
    elapsed_ms: int = 0,
) -> None:
    """Append an audit record for an SSH command decision/execution."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"[{ts}] session={session_id} host={host} user={username} port={port}\n"
        f"  cmd: {command}\n"
        f"  decision: {decision} | source: {source}\n"
        f"  exit_code: {exit_code if exit_code is not None else '-'}"
        f"  output_bytes: {output_bytes}  elapsed_ms: {elapsed_ms}\n\n"
    )
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


# ---------------------------------------------------------------------------
# Session-level SSH connection pool
# ---------------------------------------------------------------------------

class SSHConnectionPool:
    """Per-session SSH connection cache.

    Keeps at most one connection per (session_id, host, port, username) tuple.
    Connections are released when the pool is explicitly closed or when the
    pool object is garbage-collected.
    """

    def __init__(self) -> None:
        self._connections: dict[tuple[str, str, int, str], asyncssh.SSHClientConnection] = {}
        self._locks: dict[tuple[str, str, int, str], asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    def _key(self, session_id: str, host: str, port: int, username: str) -> tuple[str, str, int, str]:
        return (session_id, host, port, username)

    async def get_connection(
        self,
        session_id: str,
        host: str,
        port: int,
        username: str,
        key_path: Optional[str],
        password: Optional[str],
    ) -> asyncssh.SSHClientConnection:
        """Return an existing connection or create a new one.

        Stale connections are not proactively detected here — the caller is
        responsible for catching connection errors and calling
        ``invalidate_connection()`` before retrying.  This avoids relying on
        asyncssh private attributes for liveness checks.
        """
        key = self._key(session_id, host, port, username)

        async with self._global_lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()

        async with self._locks[key]:
            conn = self._connections.get(key)
            if conn is not None:
                return conn

            connect_kwargs: dict = dict(
                host=host,
                port=port,
                username=username,
                connect_timeout=15,
                known_hosts=None,
                keepalive_interval=30,
            )
            if key_path:
                connect_kwargs["client_keys"] = [key_path]
            elif password:
                connect_kwargs["password"] = password

            conn = await asyncssh.connect(**connect_kwargs)
            self._connections[key] = conn
            return conn

    def invalidate_connection(
        self, session_id: str, host: str, port: int, username: str
    ) -> None:
        """Evict a stale connection from the pool so the next call reconnects."""
        key = self._key(session_id, host, port, username)
        self._connections.pop(key, None)

    async def close_session(self, session_id: str) -> None:
        """Close all connections belonging to *session_id*."""
        to_close: list[tuple] = [k for k in self._connections if k[0] == session_id]
        for key in to_close:
            conn = self._connections.pop(key, None)
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    async def close_all(self) -> None:
        """Close every cached connection."""
        for conn in self._connections.values():
            try:
                conn.close()
            except Exception:
                pass
        self._connections.clear()


_pool = SSHConnectionPool()


def get_ssh_pool() -> SSHConnectionPool:
    """Return the module-level connection pool singleton."""
    return _pool


# ---------------------------------------------------------------------------
# Session lifecycle integration
# ---------------------------------------------------------------------------

def _on_session_deleted(event: dict) -> None:
    """Release SSH connections when a session is deleted.

    Subscribed to the ``session.deleted`` bus event at module import time.
    Schedules an async close on the running event loop so it doesn't block
    the synchronous bus callback.
    """
    try:
        props = event.get("properties", {})
        session_id = props.get("sessionID") or props.get("session_id")
        if not session_id:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_pool.close_session(session_id))
        except RuntimeError:
            pass
    except Exception:
        pass


try:
    from flocks.bus.bus import Bus
    from flocks.bus.events import SessionDeleted
    Bus.subscribe(SessionDeleted, _on_session_deleted)
except Exception:
    pass


# ---------------------------------------------------------------------------
# SSH command execution
# ---------------------------------------------------------------------------

async def execute_ssh_command(
    host: str,
    command: str,
    username: str,
    port: int,
    key_path: Optional[str],
    password: Optional[str],
    timeout_s: int,
    session_id: Optional[str] = None,
) -> tuple[int, str, str]:
    """Execute a command on a remote host via SSH.

    When *session_id* is provided the connection is fetched from (and
    cached in) the session-level connection pool, dramatically reducing
    latency for multi-command investigations.  Without a session_id a
    fresh one-shot connection is created each time.

    Returns:
        (exit_code, stdout, stderr)
    """
    if session_id:
        conn = await _pool.get_connection(
            session_id=session_id,
            host=host, port=port, username=username,
            key_path=key_path, password=password,
        )
        try:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout_s,
            )
            return (
                result.exit_status or 0,
                result.stdout or "",
                result.stderr or "",
            )
        except (asyncssh.ConnectionLost, asyncssh.DisconnectError, BrokenPipeError, OSError):
            # Stale connection — evict from pool and retry with a fresh one.
            _pool.invalidate_connection(session_id, host, port, username)
            conn = await _pool.get_connection(
                session_id=session_id,
                host=host, port=port, username=username,
                key_path=key_path, password=password,
            )
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout_s,
            )
            return (
                result.exit_status or 0,
                result.stdout or "",
                result.stderr or "",
            )

    connect_kwargs: dict = dict(
        host=host,
        port=port,
        username=username,
        connect_timeout=15,
        known_hosts=None,
    )
    if key_path:
        connect_kwargs["client_keys"] = [key_path]
    elif password:
        connect_kwargs["password"] = password

    async with asyncssh.connect(**connect_kwargs) as conn:
        result = await asyncio.wait_for(
            conn.run(command, check=False),
            timeout=timeout_s,
        )
        return (
            result.exit_status or 0,
            result.stdout or "",
            result.stderr or "",
        )


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------

def resolve_ssh_credentials(
    username: Optional[str],
    key_path: Optional[str],
    password: Optional[str],
) -> tuple[str, Optional[str], Optional[str]]:
    """Resolve SSH credentials from provided values or SecretManager.

    Falls back to SecretManager defaults for any unset credential.

    Returns:
        (username, key_path, password) with defaults applied
    """
    try:
        from flocks.security import get_secret_manager
        sm = get_secret_manager()
        if not username:
            username = sm.get("ssh_default_user") or "root"
        if not key_path:
            key_path = sm.get("ssh_default_key_path")
        if not password and not key_path:
            password = sm.get("ssh_default_password")
    except Exception as e:
        log.warn("ssh_utils.credential_resolve_failed", {"error": str(e)})
        if not username:
            username = "root"

    return username, key_path, password
