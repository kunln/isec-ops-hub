"""
Volcengine / Doubao (火山引擎 / 豆包) provider implementation.

Volcengine provides OpenAI-compatible API.
Docs: https://www.volcengine.com/docs/82379
"""

from flocks.provider.sdk.openai_base import OpenAIBaseProvider


class VolcengineProvider(OpenAIBaseProvider):
    """Volcengine / Doubao provider (OpenAI-compatible).

    Models are loaded from catalog.json (CATALOG_ID = "volcengine") and
    user-added custom models from flocks.json by the parent
    OpenAIBaseProvider.get_models().
    """

    DEFAULT_BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"
    ENV_API_KEY = ["VOLCENGINE_API_KEY", "ARK_API_KEY"]
    ENV_BASE_URL = "VOLCENGINE_BASE_URL"
    CATALOG_ID = "volcengine"

    def __init__(self):
        super().__init__(provider_id="volcengine", name="火山引擎 (Volcengine)")
