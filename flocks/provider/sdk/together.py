"""
Together AI provider implementation
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

log = Log.create(service="provider.together")


class TogetherProvider(BaseProvider):
    """Together AI provider"""
    
    def __init__(self):
        super().__init__(provider_id="together", name="Together AI")
        self._api_key = os.getenv("TOGETHER_API_KEY")
        self._client = None
    
    def _get_client(self):
        """Get or create Together client"""
        if self._client is None:
            try:
                # Together uses OpenAI-compatible API
                from openai import AsyncOpenAI
                
                # Get API key
                api_key = self._config.api_key if self._config else self._api_key
                if not api_key:
                    api_key = os.getenv("TOGETHER_API_KEY")
                if not api_key:
                    raise ValueError("Together API key not configured")
                
                # Create client with Together endpoint
                self._client = AsyncOpenAI(
                    api_key=api_key,
                    base_url="https://api.together.xyz/v1",
                )
                self.log.info("together.client.created")
                    
            except ImportError:
                raise ImportError("openai package not installed. Install with: pip install openai")
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get list of Together models"""
        return [
            ModelInfo(
                id="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
                name="Llama 3.1 70B Turbo",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=8192,
                    context_window=128000,
                ),
            ),
            ModelInfo(
                id="meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
                name="Llama 3.1 8B Turbo",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=8192,
                    context_window=128000,
                ),
            ),
            ModelInfo(
                id="mistralai/Mixtral-8x7B-Instruct-v0.1",
                name="Mixtral 8x7B",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=False,
                    supports_vision=False,
                    max_tokens=32768,
                    context_window=32768,
                ),
            ),
            ModelInfo(
                id="Qwen/Qwen2.5-72B-Instruct-Turbo",
                name="Qwen 2.5 72B Turbo",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=8192,
                    context_window=32768,
                ),
            ),
        ]
    
    async def chat(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> ChatResponse:
        """Send chat completion request to Together"""
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
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
        )
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """Send streaming chat completion request to Together"""
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
