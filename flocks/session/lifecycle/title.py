"""
Session Title generation module

Automatically generates titles for sessions using LLM after the first user message.
Based on Flocks' ported src/session/title.ts
"""

from typing import Any, Awaitable, Callable, Dict, List, Optional
import asyncio

from flocks.utils.log import Log
from flocks.provider.provider import ChatMessage

EventPublishCallback = Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]]

log = Log.create(service="session.title")


# Reuse the canonical title prompt from prompt_strings (single source of truth)
from flocks.session.prompt_strings import PROMPT_TITLE as _CANONICAL_TITLE_PROMPT


class SessionTitle:
    """Session title generation"""
    
    @classmethod
    async def generate_title_after_first_message(
        cls,
        session_id: str,
        model_id: str,
        provider_id: str,
        event_publish_callback: EventPublishCallback = None,
    ) -> Optional[str]:
        """
        Generate session title using LLM after the first user message
        
        Triggers when exactly 1 user message exists and the session has no
        meaningful title yet. Uses the first user message to generate a concise
        title via LLM, with a simple text-based fallback.
        
        Args:
            session_id: Session ID
            model_id: Model to use for generation
            provider_id: Provider to use for generation
            
        Returns:
            Generated title or None
        """
        try:
            from flocks.session.session import Session
            from flocks.session.message import Message
            from flocks.provider.provider import Provider
            
            log.info("title.generation.start", {
                "session_id": session_id,
                "model_id": model_id,
                "provider_id": provider_id,
            })
            
            # Check if session already has a non-default title
            session = await Session.get_by_id(session_id)
            if not session:
                log.warn("title.session_not_found", {"session_id": session_id})
                return None
            
            _DEFAULT_TITLES = {
                "new chat", "new session", "新对话", "新会话", "untitled",
            }
            
            log.debug("title.session_info", {
                "session_id": session_id,
                "current_title": session.title,
                "is_default": (not session.title) or session.title.lower().strip() in _DEFAULT_TITLES or Session.is_default_title(session.title),
            })
            
            # Skip if already has a meaningful title (not default placeholder or auto-generated timestamp title)
            if session.title and session.title.lower().strip() not in _DEFAULT_TITLES and not Session.is_default_title(session.title):
                log.debug("title.already_exists", {"session_id": session_id, "title": session.title})
                return session.title
            
            # Get all messages (use async version)
            messages = await Message.list(session_id)
            
            # Count user messages
            user_messages = [m for m in messages if str(m.role) == "user"]
            
            # Only generate title after first user message (exactly 1 user message)
            if len(user_messages) != 1:
                log.debug("title.not_first_message", {
                    "session_id": session_id,
                    "user_message_count": len(user_messages)
                })
                return None
            
            # Get the first user message content
            first_user_msg = user_messages[0]
            parts = await Message.parts(first_user_msg.id, session_id)
            question = ""
            for part in parts:
                if hasattr(part, 'type') and part.type == "text" and hasattr(part, 'text'):
                    question = part.text[:300]  # Truncate long messages
                    break
            
            if not question:
                log.warn("title.no_question", {"session_id": session_id})
                return None
            
            # Call LLM to generate title
            Provider._ensure_initialized()
            provider = Provider.get(provider_id)
            
            if not provider:
                log.warn("title.provider_not_found", {"provider_id": provider_id})
                return cls._generate_simple_title(question)
            
            log.info("title.generating", {
                "session_id": session_id,
                "provider_id": provider_id,
                "model_id": model_id,
            })
            
            # Send PROMPT_TITLE as system instruction, user question as user message
            title = ""
            try:
                async for chunk in provider.chat_stream(
                    model_id,
                    [
                        ChatMessage(role="system", content=_CANONICAL_TITLE_PROMPT),
                        ChatMessage(role="user", content=question),
                    ],
                    max_tokens=50,
                ):
                    if hasattr(chunk, 'delta') and chunk.delta:
                        title += chunk.delta
            except Exception as llm_err:
                log.warn("title.llm_failed", {
                    "session_id": session_id,
                    "error": str(llm_err),
                })
            
            # Clean up the generated title
            title = title.strip().strip('"').strip("'").strip()
            
            # Validate title length
            if len(title) > 50:
                title = title[:47] + "..."
            
            if not title:
                title = cls._generate_simple_title(question)
            
            # Update session with title
            await Session.update(session.project_id, session_id, title=title)
            
            log.info("title.generated", {
                "session_id": session_id,
                "title": title,
            })
            
            # Publish event for frontend to update (via injected callback)
            if event_publish_callback:
                await event_publish_callback("session.updated", {
                    "id": session_id,
                    "title": title,
                })
            
            return title
            
        except Exception as e:
            log.error("title.generation_error", {
                "error": str(e),
                "session_id": session_id,
            })
            return None
    
    @classmethod
    async def ensure_title(
        cls,
        session_id: str,
        model_id: str,
        provider_id: str,
        messages: List,
        event_publish_callback: EventPublishCallback = None,
    ) -> Optional[str]:
        """
        Ensure session has a title, generate if needed (legacy method)
        
        Args:
            session_id: Session ID
            model_id: Model to use for generation
            provider_id: Provider to use for generation
            messages: Session messages
            event_publish_callback: Optional SSE event publisher
            
        Returns:
            Generated title or None
        """
        return await cls.generate_title_after_first_message(
            session_id, model_id, provider_id,
            event_publish_callback=event_publish_callback,
        )
    
    @staticmethod
    def _generate_simple_title(text: str, max_length: int = 50) -> str:
        """
        Generate a simple title from text (fallback)
        
        Args:
            text: Input text
            max_length: Maximum title length
            
        Returns:
            Generated title
        """
        # Clean up text
        text = text.strip()
        
        # Remove "User: " prefix if present
        if text.startswith("User: "):
            text = text[6:]
        
        # Take first line or sentence
        lines = text.split('\n')
        first_line = lines[0].strip()
        
        # Truncate if too long
        if len(first_line) > max_length:
            title = first_line[:max_length - 3] + "..."
        else:
            title = first_line
        
        # Fallback to "New Chat" if empty
        if not title:
            title = "New Chat"
        
        return title
