"""
Vercel AI Provider SDK

Provides integration with Vercel AI platform.
Uses OpenAI-compatible API with Vercel-specific headers.

Ported from original @ai-sdk/vercel implementation.
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

log = Log.create(service="provider.vercel")


class VercelProvider(BaseProvider):
    """
    Vercel AI Provider
    
    Integrates with Vercel's AI platform for:
    - Chat completions via OpenAI-compatible API
    - Multiple model support through Vercel's routing
    - Edge-optimized inference
    
    Environment Variables:
        VERCEL_AI_API_KEY: API key for Vercel AI
        VERCEL_AI_BASE_URL: Optional custom base URL
    """
    
    # Default models available through Vercel AI
    DEFAULT_MODELS = [
        {
            "id": "gpt-4-turbo",
            "name": "GPT-4 Turbo (Vercel)",
            "context_window": 128000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gpt-3.5-turbo",
            "name": "GPT-3.5 Turbo (Vercel)",
            "context_window": 16385,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": False,
            "supports_streaming": True,
        },
        {
            "id": "claude-3-sonnet",
            "name": "Claude 3 Sonnet (Vercel)",
            "context_window": 200000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "claude-3-haiku",
            "name": "Claude 3 Haiku (Vercel)",
            "context_window": 200000,
            "max_tokens": 4096,
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
        Initialize Vercel AI provider.
        
        Args:
            api_key: Vercel AI API key (or from VERCEL_AI_API_KEY env)
            base_url: Override API base URL
            **kwargs: Additional configuration
        """
        super().__init__(provider_id="vercel", name="Vercel AI")
        
        # Get API key from environment if not provided
        self.api_key = api_key or os.environ.get("VERCEL_AI_API_KEY", "")
        
        # Set base URL (Vercel AI uses OpenAI-compatible endpoint)
        if base_url:
            self._base_url = base_url
        else:
            self._base_url = os.environ.get(
                "VERCEL_AI_BASE_URL", 
                "https://api.vercel.ai/v1"
            )
        
        self._client = None
        self._models_config = self.DEFAULT_MODELS.copy()
        
        log.info("vercel.initialized", {"base_url": self._base_url})
    
    def _get_client(self):
        """Get or create OpenAI-compatible client for Vercel AI."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                
                if not self.api_key:
                    raise ValueError(
                        "Vercel AI API key not configured. "
                        "Set VERCEL_AI_API_KEY environment variable."
                    )
                
                # Vercel-specific headers as per Flocks implementation
                self._client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self._base_url,
                    default_headers={
                        "http-referer": "https://flocks.ai/",
                        "x-title": "flocks",
                    }
                )
                
            except ImportError:
                raise ImportError(
                    "openai package not installed. Install with: pip install openai"
                )
        
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get available Vercel AI models."""
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
        Create a chat completion using Vercel AI.
        
        Args:
            model_id: Model to use
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
            log.error("vercel.chat.error", {"error": str(e), "model": model_id})
            raise
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """
        Create a streaming chat completion using Vercel AI.
        
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
            log.error("vercel.stream.error", {"error": str(e), "model": model_id})
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Vercel AI service health."""
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
def create_provider(**kwargs) -> VercelProvider:
    """Create a Vercel AI provider instance."""
    return VercelProvider(**kwargs)
