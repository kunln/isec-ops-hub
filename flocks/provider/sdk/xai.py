"""
xAI (Grok) provider implementation

Based on @ai-sdk/xai from Flocks's bundled providers
"""

from typing import List, AsyncIterator, Optional
import os

from flocks.provider.provider import (
    BaseProvider,
    ModelInfo,
    ModelCapabilities,
    ChatMessage,
    ChatResponse,
    StreamChunk,
)


class XAIProvider(BaseProvider):
    """xAI (Grok) provider"""
    
    def __init__(self):
        super().__init__(provider_id="xai", name="xAI")
        self._api_key = os.getenv("XAI_API_KEY")
        self._base_url = "https://api.x.ai/v1"
        self._client = None
    
    def _get_client(self):
        """Get or create xAI client (OpenAI compatible)"""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                api_key = self._config.api_key if self._config else self._api_key
                if not api_key:
                    raise ValueError("xAI API key not configured. Set XAI_API_KEY environment variable.")
                
                self._client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=self._base_url,
                )
            except ImportError:
                raise ImportError("openai package not installed. Install with: pip install openai")
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get list of xAI models"""
        return [
            ModelInfo(
                id="grok-2",
                name="Grok 2",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=True,
                    max_tokens=131072,
                    context_window=131072,
                ),
            ),
            ModelInfo(
                id="grok-2-mini",
                name="Grok 2 Mini",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=131072,
                    context_window=131072,
                ),
            ),
        ]
    
    async def chat(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> ChatResponse:
        """Send chat completion request to xAI"""
        client = self._get_client()
        
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        response = await client.chat.completions.create(
            model=model_id,
            messages=formatted_messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens"),
        )
        
        choice = response.choices[0]
        return ChatResponse(
            id=response.id,
            model=response.model,
            content=choice.message.content or "",
            finish_reason=choice.finish_reason,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            }
        )
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """Send streaming chat completion request to xAI"""
        client = self._get_client()
        
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        stream = await client.chat.completions.create(
            model=model_id,
            messages=formatted_messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens"),
            stream=True,
        )
        
        async for chunk in stream:
            if chunk.choices:
                choice = chunk.choices[0]
                if choice.delta.content:
                    yield StreamChunk(
                        delta=choice.delta.content,
                        finish_reason=choice.finish_reason,
                    )
