"""
Tencent Hunyuan (腾讯混元) provider implementation.

Tencent Hunyuan provides OpenAI-compatible API.
Docs: https://cloud.tencent.com/document/product/1729
"""

from flocks.provider.sdk.openai_base import OpenAIBaseProvider


class TencentProvider(OpenAIBaseProvider):
    """Tencent Hunyuan provider (OpenAI-compatible).

    Models are loaded from catalog.json (CATALOG_ID = "tencent") and
    user-added custom models from flocks.json by the parent
    OpenAIBaseProvider.get_models().
    """

    DEFAULT_BASE_URL = "https://api.hunyuan.cloud.tencent.com/v1"
    ENV_API_KEY = ["HUNYUAN_API_KEY", "TENCENT_API_KEY"]
    ENV_BASE_URL = "HUNYUAN_BASE_URL"
    CATALOG_ID = "tencent"

    def __init__(self):
        super().__init__(provider_id="tencent", name="腾讯混元 (Tencent Hunyuan)")
