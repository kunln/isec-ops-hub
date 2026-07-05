"""
SiliconFlow (硅基流动) provider implementation.

SiliconFlow provides OpenAI-compatible API for hosting open-source models.
Docs: https://docs.siliconflow.cn

Models are loaded from catalog.json (CATALOG_ID = "siliconflow") and
user-added custom models from flocks.json (_config_models) by the parent
OpenAIBaseProvider.get_models().
"""

from flocks.provider.sdk.openai_base import OpenAIBaseProvider


class SiliconFlowProvider(OpenAIBaseProvider):
    """SiliconFlow provider (OpenAI-compatible)."""

    DEFAULT_BASE_URL = "https://api.siliconflow.cn/v1"
    ENV_API_KEY = ["SILICONFLOW_API_KEY"]
    ENV_BASE_URL = "SILICONFLOW_BASE_URL"
    CATALOG_ID = "siliconflow"

    def __init__(self):
        super().__init__(provider_id="siliconflow", name="硅基流动 (SiliconFlow)")
