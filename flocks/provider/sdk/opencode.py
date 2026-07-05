"""
Provider SDK for external AI service

Provides integration with external AI models service.
Supports both authenticated (paid) and public (free) access.
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

log = Log.create(service="provider.opencode")


class OpenCodeProvider(BaseProvider):
    """
    External AI Service Provider
    
    Provides access to external AI models including:
    - Free tier models with limited capabilities
    - Paid tier models with full features
    
    The provider supports both authenticated and public access modes.
    When no API key is provided, free models are available with a public key.
    
    Environment Variables:
        OPENCODE_API_KEY: API key for authenticated access (technical identifier)
        OPENCODE_BASE_URL: Optional custom base URL (technical identifier)
    """
    
    # Free models available without authentication
    FREE_MODELS = [
        {
            "id": "gpt-4o-mini",
            "name": "GPT-4o Mini (Free)",
            "context_window": 128000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
            "free": True,
        },
        {
            "id": "gpt-3.5-turbo",
            "name": "GPT-3.5 Turbo (Free)",
            "context_window": 16385,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": False,
            "supports_streaming": True,
            "free": True,
        },
    ]
    
    # Paid models requiring authentication
    PAID_MODELS = [
        {
            "id": "gpt-4-turbo",
            "name": "GPT-4 Turbo",
            "context_window": 128000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
            "free": False,
        },
        {
            "id": "gpt-4o",
            "name": "GPT-4o",
            "context_window": 128000,
            "max_tokens": 16384,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
            "free": False,
        },
        {
            "id": "claude-3-sonnet",
            "name": "Claude 3 Sonnet",
            "context_window": 200000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
            "free": False,
        },
        {
            "id": "claude-3-opus",
            "name": "Claude 3 Opus",
            "context_window": 200000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
            "free": False,
        },
    ]
    
    # Public API key for free tier access
    PUBLIC_API_KEY = "public"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize OpenCode provider.
        
        Args:
            api_key: OpenCode API key for paid access (or from OPENCODE_API_KEY env)
            base_url: Override API base URL
            **kwargs: Additional configuration
        """
        super().__init__(provider_id="opencode", name="OpenCode")
        
        # Get API key from environment if not provided
        self.api_key = api_key or os.environ.get("OPENCODE_API_KEY", "")
        
        # Track if using authenticated or public access
        self.is_authenticated = bool(self.api_key)
        
        # If no API key, use public key for free tier
        if not self.is_authenticated:
            self.api_key = self.PUBLIC_API_KEY
        
        # Set base URL
        if base_url:
            self._base_url = base_url
        else:
            self._base_url = os.environ.get(
                "OPENCODE_BASE_URL",
                "https://api.opencode.ai/v1"
            )
        
        self._client = None
        
        log.info("opencode.initialized", {
            "base_url": self._base_url,
            "is_authenticated": self.is_authenticated,
        })
    
    def _get_client(self):
        """Get or create OpenAI-compatible client for OpenCode."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                
                self._client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self._base_url,
                    default_headers={
                        "X-OpenCode-Client": "flocks",
                        "X-OpenCode-Version": "1.0.0",
                    }
                )
                
            except ImportError:
                raise ImportError(
                    "openai package not installed. Install with: pip install openai"
                )
        
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """
        Get available OpenCode models.
        
        Returns free models only if not authenticated,
        or all models if authenticated.
        """
        models = []
        
        # Always include free models
        for config in self.FREE_MODELS:
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
        
        # Include paid models only if authenticated
        if self.is_authenticated:
            for config in self.PAID_MODELS:
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
        Create a chat completion using OpenCode.
        
        Args:
            model_id: Model to use
            messages: List of conversation messages
            **kwargs: Additional parameters (temperature, max_tokens, etc.)
            
        Returns:
            Chat completion response
        """
        client = self._get_client()
        
        # Verify model access
        available_models = {m.id for m in self.get_models()}
        if model_id not in available_models:
            raise ValueError(
                f"Model '{model_id}' not available. "
                f"{'Authenticate to access paid models.' if not self.is_authenticated else ''}"
            )
        
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
            log.error("opencode.chat.error", {"error": str(e), "model": model_id})
            raise
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """
        Create a streaming chat completion using OpenCode.
        
        Args:
            model_id: Model to use
            messages: List of conversation messages
            **kwargs: Additional parameters
            
        Yields:
            Streaming response chunks
        """
        client = self._get_client()
        
        # Verify model access
        available_models = {m.id for m in self.get_models()}
        if model_id not in available_models:
            raise ValueError(
                f"Model '{model_id}' not available. "
                f"{'Authenticate to access paid models.' if not self.is_authenticated else ''}"
            )
        
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
            log.error("opencode.stream.error", {"error": str(e), "model": model_id})
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check OpenCode service health."""
        try:
            client = self._get_client()
            
            # Simple models list request to verify connectivity
            models = await client.models.list()
            
            return {
                "healthy": True,
                "provider": self.id,
                "is_authenticated": self.is_authenticated,
                "model_count": len(list(models)),
            }
            
        except Exception as e:
            return {
                "healthy": False,
                "provider": self.id,
                "is_authenticated": self.is_authenticated,
                "error": str(e),
            }


# Provider factory function
def create_provider(**kwargs) -> OpenCodeProvider:
    """Create an OpenCode provider instance."""
    return OpenCodeProvider(**kwargs)
