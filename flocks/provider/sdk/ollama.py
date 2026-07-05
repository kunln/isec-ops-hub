"""
Ollama provider implementation.

Dedicated Ollama provider with auto-discovery of locally running models.
Uses OpenAI-compatible API at http://localhost:11434/v1.
Docs: https://ollama.com
"""

from flocks.provider.sdk.openai_base import OpenAIBaseProvider


class OllamaProvider(OpenAIBaseProvider):
    """Ollama local model provider (OpenAI-compatible)."""

    DEFAULT_BASE_URL = "http://localhost:11434/v1"
    ENV_API_KEY = []  # Ollama doesn't need an API key
    ENV_BASE_URL = "OLLAMA_BASE_URL"
    CATALOG_ID = "ollama"

    def __init__(self):
        super().__init__(provider_id="ollama", name="Ollama")

    def is_configured(self) -> bool:
        """Ollama doesn't need an API key, just a running server."""
        return True

    def _get_client(self):
        """Override to use dummy API key when none is configured."""
        if self._client is None:
            from openai import AsyncOpenAI

            base_url = (
                self._config.base_url
                if self._config and self._config.base_url
                else self._base_url
            )
            api_key = "ollama"
            if self._config and self._config.api_key:
                api_key = self._config.api_key

            self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        return self._client

    def get_models(self):
        """Return models from flocks.json (_config_models) only.

        catalog.json is not consulted at runtime; it is only used when
        credentials are first saved to pre-populate flocks.json.
        """
        return list(getattr(self, "_config_models", []))
