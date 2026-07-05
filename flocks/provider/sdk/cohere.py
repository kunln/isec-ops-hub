"""
Cohere provider implementation
"""

from typing import List, AsyncIterator
import os

from flocks.provider.provider import (
    BaseProvider,
    ModelInfo,
    ModelCapabilities,
    ChatMessage,
    ChatResponse,
    StreamChunk,
)
from flocks.utils.log import Log

log = Log.create(service="provider.cohere")


class CohereProvider(BaseProvider):
    """Cohere provider"""
    
    def __init__(self):
        super().__init__(provider_id="cohere", name="Cohere")
        self._api_key = os.getenv("COHERE_API_KEY")
        self._client = None
    
    def _get_client(self):
        """Get or create Cohere client"""
        if self._client is None:
            try:
                # Cohere uses OpenAI-compatible API
                from openai import AsyncOpenAI
                
                # Get API key
                api_key = self._config.api_key if self._config else self._api_key
                if not api_key:
                    api_key = os.getenv("COHERE_API_KEY")
                if not api_key:
                    raise ValueError("Cohere API key not configured")
                
                # Create client with Cohere endpoint
                self._client = AsyncOpenAI(
                    api_key=api_key,
                    base_url="https://api.cohere.com/v1",
                )
                self.log.info("cohere.client.created")
                    
            except ImportError:
                raise ImportError("openai package not installed. Install with: pip install openai")
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get list of Cohere models"""
        return [
            ModelInfo(
                id="command-r-plus",
                name="Command R+",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=128000,
                ),
            ),
            ModelInfo(
                id="command-r",
                name="Command R",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=128000,
                ),
            ),
            ModelInfo(
                id="command",
                name="Command",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=False,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=4096,
                ),
            ),
            ModelInfo(
                id="command-light",
                name="Command Light",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=False,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=4096,
                ),
            ),
        ]
    
    async def chat(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> ChatResponse:
        """Send chat completion request to Cohere"""
        client = self._get_client()
        
        # Convert messages to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Extract parameters
        temperature = kwargs.get("temperature", 0.7)
        max_tokens = kwargs.get("max_tokens")
        tools = kwargs.get("tools")
        
        # Make request
        request_params = {
            "model": model_id,
            "messages": formatted_messages,
            "temperature": temperature,
        }
        
        if max_tokens:
            request_params["max_tokens"] = max_tokens
        if tools:
            request_params["tools"] = tools
        
        response = await client.chat.completions.create(**request_params)
        
        # Format response
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
        """Send streaming chat completion request to Cohere"""
        client = self._get_client()
        
        # Convert messages to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Extract parameters
        temperature = kwargs.get("temperature", 0.7)
        max_tokens = kwargs.get("max_tokens")
        tools = kwargs.get("tools")
        
        # Make streaming request
        request_params = {
            "model": model_id,
            "messages": formatted_messages,
            "temperature": temperature,
            "stream": True,
        }
        
        if max_tokens:
            request_params["max_tokens"] = max_tokens
        if tools:
            request_params["tools"] = tools
        
        stream = await client.chat.completions.create(**request_params)
        
        async for chunk in stream:
            if chunk.choices:
                choice = chunk.choices[0]
                if choice.delta.content:
                    yield StreamChunk(
                        delta=choice.delta.content,
                        finish_reason=choice.finish_reason,
                    )
