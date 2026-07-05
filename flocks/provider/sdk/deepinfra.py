"""
DeepInfra provider implementation

Based on @ai-sdk/deepinfra from Flocks's bundled providers
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


class DeepInfraProvider(BaseProvider):
    """DeepInfra provider - hosts open-source models"""
    
    def __init__(self):
        super().__init__(provider_id="deepinfra", name="DeepInfra")
        self._api_key = os.getenv("DEEPINFRA_API_KEY")
        self._base_url = "https://api.deepinfra.com/v1/openai"
        self._client = None
    
    def _get_client(self):
        """Get or create DeepInfra client (OpenAI compatible)"""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                api_key = self._config.api_key if self._config else self._api_key
                if not api_key:
                    raise ValueError("DeepInfra API key not configured. Set DEEPINFRA_API_KEY environment variable.")
                
                self._client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=self._base_url,
                )
            except ImportError:
                raise ImportError("openai package not installed. Install with: pip install openai")
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get list of DeepInfra models"""
        return [
            ModelInfo(
                id="meta-llama/Llama-3.3-70B-Instruct",
                name="Llama 3.3 70B Instruct",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=131072,
                ),
            ),
            ModelInfo(
                id="meta-llama/Llama-3.1-8B-Instruct",
                name="Llama 3.1 8B Instruct",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=131072,
                ),
            ),
            ModelInfo(
                id="mistralai/Mixtral-8x7B-Instruct-v0.1",
                name="Mixtral 8x7B Instruct",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=32768,
                ),
            ),
            ModelInfo(
                id="Qwen/Qwen2.5-72B-Instruct",
                name="Qwen 2.5 72B Instruct",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
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
        """Send chat completion request to DeepInfra"""
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
        """Send streaming chat completion request to DeepInfra"""
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
