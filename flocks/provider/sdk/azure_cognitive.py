"""
Azure Cognitive Services Provider SDK

Provides integration with Azure Cognitive Services for AI capabilities.
This is a specialized Azure provider variant that uses Cognitive Services endpoints.

Ported from original azure-cognitive-services implementation.
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

log = Log.create(service="provider.azure-cognitive")


class AzureCognitiveServicesProvider(BaseProvider):
    """
    Azure Cognitive Services Provider
    
    Integrates with Azure Cognitive Services OpenAI endpoint:
    - Uses Azure Cognitive Services resource name for endpoint
    - Supports both chat completions and responses API
    - Compatible with Azure AD and API key authentication
    
    Environment Variables:
        AZURE_COGNITIVE_SERVICES_RESOURCE_NAME: Resource name for endpoint
        AZURE_API_KEY: API key for authentication
        AZURE_AD_TOKEN: Optional Azure AD token
    """
    
    # Default models available through Azure Cognitive Services
    DEFAULT_MODELS = [
        {
            "id": "gpt-4",
            "name": "GPT-4 (Azure Cognitive)",
            "context_window": 8192,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": False,
            "supports_streaming": True,
        },
        {
            "id": "gpt-4-turbo",
            "name": "GPT-4 Turbo (Azure Cognitive)",
            "context_window": 128000,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gpt-4o",
            "name": "GPT-4o (Azure Cognitive)",
            "context_window": 128000,
            "max_tokens": 16384,
            "supports_tools": True,
            "supports_vision": True,
            "supports_streaming": True,
        },
        {
            "id": "gpt-35-turbo",
            "name": "GPT-3.5 Turbo (Azure Cognitive)",
            "context_window": 16385,
            "max_tokens": 4096,
            "supports_tools": True,
            "supports_vision": False,
            "supports_streaming": True,
        },
    ]
    
    def __init__(
        self,
        resource_name: Optional[str] = None,
        api_key: Optional[str] = None,
        api_version: Optional[str] = None,
        use_completion_urls: bool = False,
        **kwargs
    ):
        """
        Initialize Azure Cognitive Services provider.
        
        Args:
            resource_name: Azure Cognitive Services resource name
            api_key: API key for authentication
            api_version: API version (default: 2024-02-15-preview)
            use_completion_urls: Use completion URLs instead of responses API
            **kwargs: Additional configuration
        """
        super().__init__(
            provider_id="azure-cognitive-services",
            name="Azure Cognitive Services"
        )
        
        # Get resource name from environment if not provided
        self.resource_name = (
            resource_name or
            os.environ.get("AZURE_COGNITIVE_SERVICES_RESOURCE_NAME") or
            ""
        )
        
        # Get API key
        self.api_key = (
            api_key or
            os.environ.get("AZURE_API_KEY") or
            os.environ.get("AZURE_OPENAI_API_KEY") or
            ""
        )
        
        # API version
        self.api_version = api_version or "2024-02-15-preview"
        
        # Use completion URLs (chat API) vs responses API
        self.use_completion_urls = use_completion_urls
        
        # Build base URL
        if self.resource_name:
            self._base_url = (
                f"https://{self.resource_name}.cognitiveservices.azure.com/openai"
            )
        else:
            self._base_url = None
        
        self._client = None
        self._models_config = self.DEFAULT_MODELS.copy()
        
        log.info("azure_cognitive.initialized", {
            "resource_name": self.resource_name,
            "use_completion_urls": use_completion_urls,
        })
    
    def _get_client(self):
        """Get or create OpenAI-compatible client for Azure Cognitive Services."""
        if self._client is None:
            try:
                from openai import AsyncAzureOpenAI
                
                if not self.resource_name:
                    raise ValueError(
                        "Azure Cognitive Services resource name not configured. "
                        "Set AZURE_COGNITIVE_SERVICES_RESOURCE_NAME environment variable."
                    )
                
                if not self.api_key:
                    raise ValueError(
                        "Azure API key not configured. "
                        "Set AZURE_API_KEY environment variable."
                    )
                
                self._client = AsyncAzureOpenAI(
                    api_key=self.api_key,
                    api_version=self.api_version,
                    azure_endpoint=self._base_url,
                )
                
            except ImportError:
                raise ImportError(
                    "openai package not installed. Install with: pip install openai"
                )
        
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get available Azure Cognitive Services models."""
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
                    context_window=config.get("context_window", 8192),
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
        Create a chat completion using Azure Cognitive Services.
        
        Args:
            model_id: Deployment name to use
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
            if self.use_completion_urls:
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
            else:
                # Use responses API (newer API)
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
                
        except Exception as e:
            log.error("azure_cognitive.chat.error", {"error": str(e), "model": model_id})
            raise
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """
        Create a streaming chat completion using Azure Cognitive Services.
        
        Args:
            model_id: Deployment name to use
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
            if self.use_completion_urls:
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
            else:
                # Use responses API (streaming)
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
                        
        except Exception as e:
            log.error("azure_cognitive.stream.error", {"error": str(e), "model": model_id})
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Azure Cognitive Services health."""
        if not self.resource_name:
            return {
                "healthy": False,
                "provider": self.id,
                "error": "Resource name not configured",
            }
        
        if not self.api_key:
            return {
                "healthy": False,
                "provider": self.id,
                "error": "API key not configured",
            }
        
        try:
            client = self._get_client()
            
            # Try to list deployments as health check
            deployments = await client.models.list()
            
            return {
                "healthy": True,
                "provider": self.id,
                "resource_name": self.resource_name,
                "deployment_count": len(list(deployments)),
            }
            
        except Exception as e:
            return {
                "healthy": False,
                "provider": self.id,
                "error": str(e),
            }


# Provider factory function
def create_provider(**kwargs) -> AzureCognitiveServicesProvider:
    """Create an Azure Cognitive Services provider instance."""
    return AzureCognitiveServicesProvider(**kwargs)
