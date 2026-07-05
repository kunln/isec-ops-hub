"""
Google Vertex AI provider implementation

Based on @ai-sdk/google-vertex from Flocks's bundled providers
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


log = Log.create(service="vertex-provider")


class VertexProvider(BaseProvider):
    """Google Vertex AI provider"""
    
    def __init__(self):
        super().__init__(provider_id="google-vertex", name="Google Vertex AI")
        self._project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
        self._location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-east5")
        self._client = None
    
    def _get_client(self):
        """Get or create Vertex AI client"""
        if self._client is None:
            try:
                import vertexai
                from vertexai.generative_models import GenerativeModel
                
                project = self._project
                location = self._location
                
                if self._config:
                    if self._config.custom_settings.get("project"):
                        project = self._config.custom_settings["project"]
                    if self._config.custom_settings.get("location"):
                        location = self._config.custom_settings["location"]
                
                if not project:
                    raise ValueError("Google Cloud project not configured. Set GOOGLE_CLOUD_PROJECT environment variable.")
                
                vertexai.init(project=project, location=location)
                self._client = True  # Flag that we're initialized
                
            except ImportError:
                raise ImportError("google-cloud-aiplatform package not installed. Install with: pip install google-cloud-aiplatform")
        return self._client
    
    def get_models(self) -> List[ModelInfo]:
        """Get list of Vertex AI models"""
        return [
            ModelInfo(
                id="gemini-1.5-pro",
                name="Gemini 1.5 Pro",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=True,
                    max_tokens=8192,
                    context_window=2000000,
                ),
            ),
            ModelInfo(
                id="gemini-1.5-flash",
                name="Gemini 1.5 Flash",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=True,
                    max_tokens=8192,
                    context_window=1000000,
                ),
            ),
            ModelInfo(
                id="gemini-2.0-flash-exp",
                name="Gemini 2.0 Flash",
                provider_id=self.id,
                capabilities=ModelCapabilities(
                    supports_streaming=True,
                    supports_tools=True,
                    supports_vision=True,
                    max_tokens=8192,
                    context_window=1000000,
                ),
            ),
        ]
    
    async def chat(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> ChatResponse:
        """Send chat completion request to Vertex AI"""
        from vertexai.generative_models import GenerativeModel, Content, Part
        
        self._get_client()
        
        model = GenerativeModel(model_id)
        
        # Convert messages to Vertex format
        contents = []
        system_instruction = None
        
        for msg in messages:
            if msg.role == "system":
                system_instruction = msg.content
            else:
                role = "model" if msg.role == "assistant" else "user"
                contents.append(Content(
                    role=role,
                    parts=[Part.from_text(msg.content)]
                ))
        
        # Create model with system instruction if present
        if system_instruction:
            model = GenerativeModel(model_id, system_instruction=system_instruction)
        
        # Generate response
        generation_config = {
            "temperature": kwargs.get("temperature", 0.7),
        }
        if kwargs.get("max_tokens"):
            generation_config["max_output_tokens"] = kwargs["max_tokens"]
        
        response = await model.generate_content_async(
            contents,
            generation_config=generation_config,
        )
        
        # Parse response
        content = response.text if response.text else ""
        
        return ChatResponse(
            id=str(hash(content))[:16],
            model=model_id,
            content=content,
            finish_reason="stop",
            usage={
                "prompt_tokens": response.usage_metadata.prompt_token_count if response.usage_metadata else 0,
                "completion_tokens": response.usage_metadata.candidates_token_count if response.usage_metadata else 0,
                "total_tokens": response.usage_metadata.total_token_count if response.usage_metadata else 0,
            }
        )
    
    async def chat_stream(
        self,
        model_id: str,
        messages: List[ChatMessage],
        **kwargs
    ) -> AsyncIterator[StreamChunk]:
        """Send streaming chat completion request to Vertex AI"""
        from vertexai.generative_models import GenerativeModel, Content, Part
        
        self._get_client()
        
        model = GenerativeModel(model_id)
        
        # Convert messages to Vertex format
        contents = []
        system_instruction = None
        
        for msg in messages:
            if msg.role == "system":
                system_instruction = msg.content
            else:
                role = "model" if msg.role == "assistant" else "user"
                contents.append(Content(
                    role=role,
                    parts=[Part.from_text(msg.content)]
                ))
        
        # Create model with system instruction if present
        if system_instruction:
            model = GenerativeModel(model_id, system_instruction=system_instruction)
        
        # Generate streaming response
        generation_config = {
            "temperature": kwargs.get("temperature", 0.7),
        }
        if kwargs.get("max_tokens"):
            generation_config["max_output_tokens"] = kwargs["max_tokens"]
        
        async for chunk in await model.generate_content_async(
            contents,
            generation_config=generation_config,
            stream=True,
        ):
            if chunk.text:
                yield StreamChunk(delta=chunk.text, finish_reason=None)
        
        yield StreamChunk(delta="", finish_reason="stop")
