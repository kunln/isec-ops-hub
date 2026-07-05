"""
Local model provider implementation

Supports local inference engines:
- Ollama
- LM Studio
- vLLM
- text-generation-webui

Ported from original local model support pattern
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
from flocks.utils.log import Log


log = Log.create(service="local-provider")


class LocalProvider(BaseProvider):
    """Local model provider - supports Ollama, LM Studio, etc."""
    
    def __init__(self):
        super().__init__(provider_id="local", name="Local Models")
        self._base_url = os.getenv("LOCAL_LLM_BASE_URL", "http://localhost:11434/v1")
        self._client = None
    
    def _get_client(self):
        """Get or create local model client (OpenAI compatible)"""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                
                base_url = self._base_url
                if self._config and self._config.base_url:
                    base_url = self._config.base_url
                
                # Most local servers don't need an API key
                api_key = "not-needed"
                if self._config and self._config.api_key:
                    api_key = self._config.api_key
                
                self._client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=base_url,
                )
                log.info("local.client.created", {"base_url": base_url})
                
            except ImportError:
                raise ImportError("openai package not installed. Install with: pip install openai")
        return self._client
    
    async def _detect_models(self) -> List[ModelInfo]:
        """Try to detect available models from the local server"""
        try:
            client = self._get_client()
            models = await client.models.list()
            
            detected = []
            for model in models.data:
                detected.append(ModelInfo(
                    id=model.id,
                    name=model.id,
                    provider_id=self.id,
                    capabilities=ModelCapabilities(
                        supports_streaming=True,
                        supports_tools=True,
                        supports_vision=False,
                        max_tokens=4096,
                        context_window=8192,
                    ),
                ))
            return detected
        except Exception as e:
            log.warn("local.detect_models.failed", {"error": str(e)})
            return []
    
    def get_models(self) -> List[ModelInfo]:
        """Get list of local models (defaults, actual detection is async)"""
        # Return common default models - actual detection happens in async context
        return [
            ModelInfo(
                id="llama3.2",
                name="Llama 3.2 (Ollama)",
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
                id="qwen2.5:14b",
                name="Qwen 2.5 14B (Ollama)",
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
                id="deepseek-r1:14b",
                name="DeepSeek R1 14B (Ollama)",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=False,
                    max_tokens=4096,
                    context_window=128000,
                ),
            ),
        ]
    
    async def chat(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> ChatResponse:
        """Send chat completion request to local model"""
        client = self._get_client()
        
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        try:
            response = await client.chat.completions.create(
                model=model_id,
                messages=formatted_messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens"),
            )
            
            choice = response.choices[0]
            return ChatResponse(
                id=response.id if hasattr(response, 'id') else "local",
                model=response.model if hasattr(response, 'model') else model_id,
                content=choice.message.content or "",
                finish_reason=choice.finish_reason or "stop",
                usage={
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                    "total_tokens": response.usage.total_tokens if response.usage else 0,
                }
            )
        except Exception as e:
            log.error("local.chat.error", {"model": model_id, "error": str(e)})
            raise
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """Send streaming chat completion request to local model"""
        client = self._get_client()
        
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        try:
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
        except Exception as e:
            log.error("local.chat_stream.error", {"model": model_id, "error": str(e)})
            raise
