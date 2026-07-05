"""
Session Context Interface

Defines the protocol (interface) between Agent Runtime and Session Engine.
Agent Runtime accesses session state (messages, status, compaction) through
this interface instead of directly importing session module internals.

This decoupling allows:
1. Agent Runtime to be tested independently
2. Different session backends (in-memory, SQLite, remote)
3. Clean separation of concerns between session management and task execution
"""

import logging
from typing import List, Optional, Dict, Any, Protocol, runtime_checkable
from dataclasses import dataclass, field

from flocks.session.message import MessageInfo, MessageRole, ToolPart
from flocks.session.session import SessionInfo

_log = logging.getLogger(__name__)


@runtime_checkable
class SessionContext(Protocol):
    """
    Interface provided by Session Engine to Agent Runtime.
    
    Agent Runtime uses this to read/write messages and manage session state
    without directly depending on session internals.
    """

    @property
    def session_id(self) -> str:
        """The current session ID."""
        ...

    @property
    def session(self) -> SessionInfo:
        """The current session info."""
        ...

    @property
    def directory(self) -> str:
        """The working directory for the session."""
        ...

    async def get_messages(self) -> List[MessageInfo]:
        """Get all messages in this session."""
        ...

    async def get_text_content(self, message: MessageInfo) -> str:
        """Get text content from a message."""
        ...

    async def get_parts(self, message_id: str) -> List[Any]:
        """Get parts for a message."""
        ...

    async def store_message(
        self,
        role: MessageRole,
        content: str,
        *,
        agent: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        parent_id: Optional[str] = None,
    ) -> MessageInfo:
        """Create and store a new message."""
        ...

    async def update_message(
        self,
        message_id: str,
        **kwargs: Any,
    ) -> None:
        """Update an existing message."""
        ...

    async def update_status(self, status_type: str, **kwargs: Any) -> None:
        """Update session status (busy, idle, retry, etc.)."""
        ...

    async def request_compaction(self) -> bool:
        """
        Check if compaction is needed and execute if so.
        Returns True if compaction was performed.
        """
        ...

    async def is_overflow(self, messages: List[MessageInfo], model_id: str) -> bool:
        """Check if message context exceeds model limits."""
        ...

    async def touch(self) -> None:
        """Update session timestamp."""
        ...


class DefaultSessionContext:
    """
    Default implementation of SessionContext using the existing session modules.
    
    Bridges the protocol to the existing Message, Session, SessionStatus,
    and SessionCompaction classes.
    """

    def __init__(self, session: SessionInfo):
        self._session = session

    @property
    def session_id(self) -> str:
        return self._session.id

    @property
    def session(self) -> SessionInfo:
        return self._session

    @property
    def directory(self) -> str:
        return self._session.directory or ""

    async def get_messages(self) -> List[MessageInfo]:
        from flocks.session.message import Message
        return await Message.list(self._session.id)

    async def get_text_content(self, message: MessageInfo) -> str:
        from flocks.session.message import Message
        return await Message.get_text_content(message)

    async def get_parts(self, message_id: str) -> List[Any]:
        from flocks.session.message import Message
        return await Message.parts(message_id, self._session.id)

    async def store_message(
        self,
        role: MessageRole,
        content: str,
        *,
        agent: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        parent_id: Optional[str] = None,
    ) -> MessageInfo:
        from flocks.session.message import Message
        return await Message.create(
            session_id=self._session.id,
            role=role,
            content=content,
            agent=agent,
            model=model,
            provider=provider,
            parent_id=parent_id,
        )

    async def update_message(
        self,
        message_id: str,
        **kwargs: Any,
    ) -> None:
        from flocks.session.message import Message
        await Message.update(self._session.id, message_id, **kwargs)

    async def update_status(self, status_type: str, **kwargs: Any) -> None:
        from flocks.session.core.status import (
            SessionStatus,
            SessionStatusBusy,
            SessionStatusIdle,
            SessionStatusRetry,
        )
        status_map = {
            "busy": SessionStatusBusy,
            "idle": SessionStatusIdle,
            "retry": SessionStatusRetry,
        }
        status_cls = status_map.get(status_type)
        if status_cls:
            if status_type == "retry":
                SessionStatus.set(self._session.id, status_cls(**kwargs))
            else:
                SessionStatus.set(self._session.id, status_cls())
        elif status_type == "clear":
            SessionStatus.clear(self._session.id)

    async def request_compaction(self) -> bool:
        from flocks.session.lifecycle.compaction import SessionCompaction
        from flocks.session.lifecycle.compaction.policy import CompactionPolicy
        from flocks.session.message import Message
        from flocks.provider.provider import Provider
        try:
            session = self._session
            provider_id = session.provider or ""
            model_id = session.model or ""
            if not provider_id or not model_id:
                _log.debug("context.compact.no_model_info")
                return False

            messages = await Message.list(session.id)
            if not messages:
                return False

            context_window, max_output, max_input = Provider.resolve_model_info(
                provider_id, model_id,
            )
            policy = (
                CompactionPolicy.from_model(
                    context_window=context_window,
                    max_output_tokens=max_output or 4096,
                    max_input_tokens=max_input,
                )
                if context_window > 0
                else CompactionPolicy.default()
            )

            last_user = None
            for m in reversed(messages):
                role = m.role.value if hasattr(m.role, "value") else m.role
                if role == "user":
                    last_user = m
                    break
            parent_id = last_user.id if last_user else ""

            # Prune before summarization (matches session_loop flow)
            await SessionCompaction.prune(session.id, policy=policy)

            raw_msgs = [m.model_dump() if hasattr(m, "model_dump") else {} for m in messages]
            result = await SessionCompaction.process(
                session_id=session.id,
                parent_id=parent_id,
                messages=raw_msgs,
                model_id=model_id,
                provider_id=provider_id,
                auto=True,
                policy=policy,
            )
            return result == "continue"
        except Exception as _e:
            _log.debug("context.compact.failed: %s", _e)
            return False

    async def is_overflow(self, messages: List[MessageInfo], model_id: str) -> bool:
        from flocks.session.lifecycle.compaction import SessionCompaction
        from flocks.session.lifecycle.compaction.policy import CompactionPolicy
        from flocks.session.prompt import SessionPrompt
        from flocks.provider.provider import Provider
        try:
            provider_id = self._session.provider or ""
            if not provider_id:
                return False

            context_window, max_output, max_input = Provider.resolve_model_info(
                provider_id, model_id,
            )
            if context_window <= 0:
                return False

            policy = CompactionPolicy.from_model(
                context_window=context_window,
                max_output_tokens=max_output or 4096,
                max_input_tokens=max_input,
            )

            estimated = await SessionPrompt.estimate_full_context_tokens(
                self._session.id, messages,
            )
            tokens = {
                "input": estimated,
                "output": 0,
                "cache": {"read": 0, "write": 0},
            }
            return await SessionCompaction.is_overflow(
                tokens=tokens,
                model_context=context_window,
                policy=policy,
            )
        except Exception as _e:
            _log.debug("context.is_overflow.failed: %s", _e)
            return False

    async def touch(self) -> None:
        from flocks.session.session import Session
        await Session.touch(self._session.project_id, self._session.id)
