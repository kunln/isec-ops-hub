"""
ZenMux Provider SDK

Provides integration with ZenMux - a multi-model routing service.
Routes requests to different AI providers based on configuration.

Ported from original zenmux implementation.
"""

import os
from typing import Optional, Dict, Any, List, AsyncIterator

from flocks.provider.provider import (
    BaseProvider,
    ModelInfo,
    ModelCapabilities,
    ChatMessage,
    ChatResponse,
    StreamChunk,
)
from flocks.utils.log import Log

log = Log.create(service="provider.zenmux")


class ZenMuxProvider(BaseProvider):
    """
    ZenMux Provider
    
    Integrates with ZenMux routing service for:
    - Multi-model routing and load balancing
    - Fallback across providers
    - Unified API for multiple AI providers
    - Cost optimization through routing
    
    Environment Variables:
        ZENMUX_API_KEY: API key for ZenMux service
        ZENMUX_BASE_URL: Optional custom base URL
    """
    
    # Default models available through ZenMux
    # These are virtual models that route to actual providers
    DEFAULT_MODELS = [
        {
            "id": "gpt-4-turbo",
            "name": "GPT-4 Turbo (ZenMux)",
            "context_window": 128000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gpt-4o",
            "name": "GPT-4o (ZenMux)",
            "context_window": 128000,
            "max_tokens": 16384,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "claude-3-5-sonnet",
            "name": "Claude 3.5 Sonnet (ZenMux)",
            "context_window": 200000,
            "max_tokens": 8192,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "claude-3-opus",
            "name": "Claude 3 Opus (ZenMux)",
            "context_window": 200000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gemini-1.5-pro",
            "name": "Gemini 1.5 Pro (ZenMux)",
            "context_window": 1000000,
            "max_tokens": 8192,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "auto",
            "name": "Auto Router (ZenMux)",
            "context_window": 128000,
            "max_tokens": 8192,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
    ]
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize ZenMux provider.
        
        Args:
            api_key: ZenMux API key (or from ZENMUX_API_KEY env)
            base_url: Override API base URL
            **kwargs: Additional configuration
        """
        super().__init__(provider_id="zenmux", name="ZenMux")
        
        # Get API key from environment if not provided
        self.api_key = api_key or os.environ.get("ZENMUX_API_KEY", "")
        
        # Set base URL
        if base_url:
            self._base_url = base_url
        else:
            self._base_url = os.environ.get(
                "ZENMUX_BASE_URL",
                "https://api.zenmux.ai/v1"
            )
        
        self._client = None
        self._models_config = self.DEFAULT_MODELS.copy()
        
        log.info("zenmux.initialized", {"base_url": self._base_url})
    
    def _get_client(self):
        """Get or create OpenAI-compatible client for ZenMux."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                
                if not self.api_key:
                    raise ValueError(
                        "ZenMux API key not configured. "
                        "Set ZENMUX_API_KEY environment variable."
                    )
                
                # ZenMux-specific headers as per Flocks implementation
                self._client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self._base_url,
                    default_headers={
                        "HTTP-Referer": "https://flocks.ai/",
                        "X-Title": "flocks",
                    }
                )
                
            except ImportError:
                raise ImportError(
                    "openai package not installed. Install with: pip install openai"
                )
        
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get available ZenMux models."""
        models = []
        for config in self._models_config:
            models.append(ModelInfo(
                id=config["id"],
                name=config["name"],
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=config.get("supports_streaming", True),
                    supports_tools=config.get("supports_tools", True),
                    supports_vision=config.get("supports_vision", False),
                    max_tokens=config.get("max_tokens", 4096),
                    context_window=config.get("context_window", 128000),
                ),
            ))
        return models
    
    async def chat(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> ChatResponse:
        """
        Create a chat completion using ZenMux.
        
        Args:
            model_id: Model to use (or 'auto' for automatic routing)
            messages: List of conversation messages
            **kwargs: Additional parameters (temperature, max_tokens, etc.)
            
        Returns:
            Chat completion response
        """
        client = self._get_client()
        
        # Convert messages to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        try:
            response = await client.chat.completions.create(
                model=model_id,
                messages=formatted_messages,
                max_tokens=kwargs.get("max_tokens"),
                temperature=kwargs.get("temperature", 0.7),
            )
            
            choice = response.choices[0]
            
            return ChatResponse(
                id=response.id,
                model=response.model,
                content=choice.message.content or "",
                finish_reason=choice.finish_reason or "stop",
                usage={
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                    "total_tokens": response.usage.total_tokens if response.usage else 0,
                }
            )
            
        except Exception as e:
            log.error("zenmux.chat.error", {"error": str(e), "model": model_id})
            raise
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """
        Create a streaming chat completion using ZenMux.
        
        Args:
            model_id: Model to use
            messages: List of conversation messages
            **kwargs: Additional parameters
            
        Yields:
            Streaming response chunks
        """
        client = self._get_client()
        
        # Convert messages to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        try:
            stream = await client.chat.completions.create(
                model=model_id,
                messages=formatted_messages,
                max_tokens=kwargs.get("max_tokens"),
                temperature=kwargs.get("temperature", 0.7),
                stream=True,
            )
            
            async for chunk in stream:
                if chunk.choices:
                    choice = chunk.choices[0]
                    if choice.delta.content:
                        yield StreamChunk(
                            delta=choice.delta.content,
                            finish_reason=None,
                        )
                    elif choice.finish_reason:
                        yield StreamChunk(
                            delta="",
                            finish_reason=choice.finish_reason,
                        )
                        
        except Exception as e:
            log.error("zenmux.stream.error", {"error": str(e), "model": model_id})
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check ZenMux service health."""
        try:
            client = self._get_client()
            
            # Simple models list request to verify connectivity
            models = await client.models.list()
            
            return {
                "healthy": True,
                "provider": self.id,
                "model_count": len(list(models)),
            }
            
        except Exception as e:
            return {
                "healthy": False,
                "provider": self.id,
                "error": str(e),
            }


# Provider factory function
def create_provider(**kwargs) -> ZenMuxProvider:
    """Create a ZenMux provider instance."""
    return ZenMuxProvider(**kwargs)
