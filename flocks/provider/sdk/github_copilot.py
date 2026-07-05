"""
GitHub Copilot Provider SDK

Provides integration with GitHub Copilot's AI capabilities.
Supports both individual and enterprise accounts with OAuth authentication.

Ported from original @ai-sdk/github-copilot implementation.
"""

import os
import re
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

log = Log.create(service="provider.github-copilot")


def is_gpt5_or_later(model_id: str) -> bool:
    """
    Check if model is GPT-5 or later version.
    
    Args:
        model_id: Model identifier
        
    Returns:
        True if model is GPT-5 or later
    """
    match = re.match(r'^gpt-(\d+)', model_id)
    if not match:
        return False
    return int(match.group(1)) >= 5


def should_use_responses_api(model_id: str) -> bool:
    """
    Determine if the responses API should be used for this model.
    
    GPT-5 and later (except gpt-5-mini) use the responses API.
    
    Args:
        model_id: Model identifier
        
    Returns:
        True if responses API should be used
    """
    return is_gpt5_or_later(model_id) and not model_id.startswith("gpt-5-mini")


class GitHubCopilotProvider(BaseProvider):
    """
    GitHub Copilot Provider
    
    Integrates with GitHub Copilot's AI features including:
    - Chat completions via OpenAI-compatible API
    - Code suggestions and completions
    - Support for multiple models (GPT-4, Claude, etc.)
    
    Authentication:
    - Uses OAuth tokens from GitHub Copilot
    - Supports both individual and enterprise accounts
    """
    
    # Default models available through GitHub Copilot
    DEFAULT_MODELS = [
        {
            "id": "gpt-4o",
            "name": "GPT-4o",
            "context_window": 128000,
            "max_tokens": 16384,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gpt-4-turbo",
            "name": "GPT-4 Turbo",
            "context_window": 128000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "claude-3.5-sonnet",
            "name": "Claude 3.5 Sonnet",
            "context_window": 200000,
            "max_tokens": 8192,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "claude-3-opus",
            "name": "Claude 3 Opus",
            "context_window": 200000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gpt-3.5-turbo",
            "name": "GPT-3.5 Turbo",
            "context_window": 16385,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": False,
            "supports_streaming": True,
        },
    ]
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        is_enterprise: bool = False,
        **kwargs
    ):
        """
        Initialize GitHub Copilot provider.
        
        Args:
            api_key: GitHub Copilot OAuth token (or from GITHUB_COPILOT_TOKEN env)
            base_url: Override API base URL
            is_enterprise: Whether this is an enterprise account
            **kwargs: Additional configuration
        """
        provider_id = "github-copilot-enterprise" if is_enterprise else "github-copilot"
        name = "GitHub Copilot Enterprise" if is_enterprise else "GitHub Copilot"
        
        super().__init__(provider_id=provider_id, name=name)
        
        # Get API key from environment if not provided
        self.api_key = api_key or os.environ.get("GITHUB_COPILOT_TOKEN", "")
        
        # Enterprise might have different token env var
        if is_enterprise and not self.api_key:
            self.api_key = os.environ.get("GITHUB_COPILOT_ENTERPRISE_TOKEN", "")
        
        self.is_enterprise = is_enterprise
        
        # Set base URL (GitHub Copilot uses a specific endpoint)
        if base_url:
            self._base_url = base_url
        else:
            self._base_url = "https://api.githubcopilot.com"
        
        self._client = None
        self._models_config = self.DEFAULT_MODELS.copy()
        
        log.info("github_copilot.initialized", {
            "is_enterprise": is_enterprise,
            "base_url": self._base_url,
        })
    
    def _get_client(self):
        """Get or create OpenAI-compatible client for GitHub Copilot."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                
                if not self.api_key:
                    raise ValueError(
                        "GitHub Copilot API key not configured. "
                        "Set GITHUB_COPILOT_TOKEN environment variable or authenticate via OAuth."
                    )
                
                self._client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self._base_url,
                    default_headers={
                        "Copilot-Integration-Id": "flocks-agent",
                        "Editor-Version": "flocks/1.0.0",
                    }
                )
                
            except ImportError:
                raise ImportError(
                    "openai package not installed. Install with: pip install openai"
                )
        
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get available GitHub Copilot models."""
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
        Create a chat completion using GitHub Copilot.
        
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
            # Determine API method based on model
            use_responses = should_use_responses_api(model_id)
            
            if use_responses:
                # Use responses API for GPT-5+
                response = await client.responses.create(
                    model=model_id,
                    input=formatted_messages,
                    max_output_tokens=kwargs.get("max_tokens"),
                    temperature=kwargs.get("temperature", 0.7),
                )
                
                return ChatResponse(
                    id=response.id,
                    model=response.model,
                    content=response.output[0].content[0].text if response.output else "",
                    finish_reason=response.status or "stop",
                    usage={
                        "prompt_tokens": response.usage.input_tokens if response.usage else 0,
                        "completion_tokens": response.usage.output_tokens if response.usage else 0,
                        "total_tokens": (
                            (response.usage.input_tokens or 0) + 
                            (response.usage.output_tokens or 0)
                        ) if response.usage else 0,
                    }
                )
            else:
                # Use chat completions API
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
            log.error("github_copilot.chat.error", {"error": str(e), "model": model_id})
            raise
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """
        Create a streaming chat completion using GitHub Copilot.
        
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
            # Determine API method based on model
            use_responses = should_use_responses_api(model_id)
            
            if use_responses:
                # Use responses API for GPT-5+ (streaming)
                stream = await client.responses.create(
                    model=model_id,
                    input=formatted_messages,
                    max_output_tokens=kwargs.get("max_tokens"),
                    temperature=kwargs.get("temperature", 0.7),
                    stream=True,
                )
                
                async for event in stream:
                    if hasattr(event, 'delta') and event.delta:
                        if hasattr(event.delta, 'content') and event.delta.content:
                            for content in event.delta.content:
                                if hasattr(content, 'text'):
                                    yield StreamChunk(
                                        delta=content.text,
                                        finish_reason=None,
                                    )
                    
                    if hasattr(event, 'type') and event.type == 'response.done':
                        yield StreamChunk(
                            delta="",
                            finish_reason="stop",
                        )
            else:
                # Use chat completions API (streaming)
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
            log.error("github_copilot.stream.error", {"error": str(e), "model": model_id})
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check GitHub Copilot service health."""
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


class GitHubCopilotEnterpriseProvider(GitHubCopilotProvider):
    """
    GitHub Copilot Enterprise Provider
    
    Inherits from GitHubCopilotProvider with enterprise-specific settings.
    """
    
    def __init__(self, **kwargs):
        """Initialize GitHub Copilot Enterprise provider."""
        super().__init__(is_enterprise=True, **kwargs)


# Provider factory functions
def create_provider(**kwargs) -> GitHubCopilotProvider:
    """Create a GitHub Copilot provider instance."""
    return GitHubCopilotProvider(**kwargs)


def create_enterprise_provider(**kwargs) -> GitHubCopilotEnterpriseProvider:
    """Create a GitHub Copilot Enterprise provider instance."""
    return GitHubCopilotEnterpriseProvider(**kwargs)
