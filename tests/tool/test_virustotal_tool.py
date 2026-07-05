"""
Tests for VirusTotal API tool (tool/virustotal.py)

NOTE: This test was written for the old single-function virustotal.py.
The tool has been replaced with per-type query tools (virustotal_ip_query etc.)
in flocks/tool/security/virustotal.py. These tests are skipped pending rewrite.
"""

import pytest
import os
from unittest.mock import AsyncMock, MagicMock, patch

from flocks.tool.registry import ToolContext

pytestmark = pytest.mark.skip(reason="旧版 virustotal API 已替换为多工具版本，测试待更新")


@pytest.fixture
def mock_context():
    return ToolContext(session_id="test-session", message_id="test-message")


def make_aiohttp_mock(status: int, response_text: str):
    """Build an async context manager mock for aiohttp that works with
    `async with aiohttp.ClientSession() as session:
         async with session.get(...) as response:`
    """
    mock_response = AsyncMock()
    mock_response.status = status
    mock_response.text = AsyncMock(return_value=response_text)

    resp_cm = AsyncMock()
    resp_cm.__aenter__ = AsyncMock(return_value=mock_response)
    resp_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = AsyncMock()
    mock_session.get = MagicMock(return_value=resp_cm)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    return mock_session


# ======================================================================
# Unit helpers
# ======================================================================


class TestApiKey:
    def test_get_api_key_from_env(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-api-key"}):
            assert get_api_key() == "test-api-key"

    def test_get_api_key_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            assert get_api_key() is None


class TestUrlEncoding:
    def test_encode_simple_url(self):
        encoded = encode_url_id("http://example.com")
        assert isinstance(encoded, str) and len(encoded) > 0

    def test_encode_complex_url(self):
        encoded = encode_url_id("https://example.com/path?query=value&other=123")
        assert isinstance(encoded, str) and len(encoded) > 0


class TestFileHashValidation:
    def test_valid_md5_hash(self):
        assert validate_file_hash("5d41402abc4b2a76b9719d911017c592") is True

    def test_valid_sha1_hash(self):
        assert validate_file_hash("356a192b7913b04c54574d18c28d46e6395428ab") is True

    def test_valid_sha256_hash(self):
        assert validate_file_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True

    def test_invalid_hash_too_short(self):
        assert validate_file_hash("abc123") is False

    def test_invalid_hash_wrong_chars(self):
        assert validate_file_hash("g" * 32) is False

    def test_uppercase_hash(self):
        assert validate_file_hash("5D41402ABC4B2A76B9719D911017C592") is True


# ======================================================================
# virustotal_query integration tests
# ======================================================================


class TestVirusTotalQuery:
    @pytest.mark.asyncio
    async def test_missing_query_value(self, mock_context):
        result = await virustotal_query(ctx=mock_context, query_type="ip", query="")
        assert result.success is False
        assert "required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_query_type(self, mock_context):
        result = await virustotal_query(ctx=mock_context, query_type="invalid", query="8.8.8.8")
        assert result.success is False
        assert "invalid query_type" in result.error.lower()

    @pytest.mark.asyncio
    async def test_missing_api_key(self, mock_context):
        with patch.dict(os.environ, {}, clear=True):
            result = await virustotal_query(ctx=mock_context, query_type="ip", query="8.8.8.8", api_key=None)
            assert result.success is False
            assert "api key" in result.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_file_hash(self, mock_context):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            result = await virustotal_query(ctx=mock_context, query_type="file", query="invalid-hash")
            assert result.success is False
            assert "invalid file hash" in result.error.lower()

    @pytest.mark.asyncio
    async def test_ip_query_success(self, mock_context):
        mock_session = make_aiohttp_mock(200, '{"data": {"id": "8.8.8.8", "attributes": {}}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(ctx=mock_context, query_type="ip", query="8.8.8.8")
                assert result.success is True
                assert "data" in result.output

    @pytest.mark.asyncio
    async def test_domain_query_success(self, mock_context):
        mock_session = make_aiohttp_mock(200, '{"data": {"id": "example.com", "attributes": {}}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(ctx=mock_context, query_type="domain", query="example.com")
                assert result.success is True
                assert "data" in result.output

    @pytest.mark.asyncio
    async def test_file_query_success(self, mock_context):
        mock_session = make_aiohttp_mock(200, '{"data": {"attributes": {"last_analysis_stats": {}}}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(
                    ctx=mock_context,
                    query_type="file",
                    query="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                assert result.success is True
                assert "data" in result.output

    @pytest.mark.asyncio
    async def test_url_query_success(self, mock_context):
        mock_session = make_aiohttp_mock(200, '{"data": {"attributes": {"last_analysis_stats": {}}}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(ctx=mock_context, query_type="url", query="http://example.com")
                assert result.success is True
                assert "data" in result.output

    @pytest.mark.asyncio
    async def test_api_key_invalid(self, mock_context):
        mock_session = make_aiohttp_mock(401, '{"error": {"message": "Invalid API key"}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "invalid-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(ctx=mock_context, query_type="ip", query="8.8.8.8")
                assert result.success is False
                assert "api key" in result.error.lower()

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self, mock_context):
        mock_session = make_aiohttp_mock(429, '{"error": {"message": "Rate limit exceeded"}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(ctx=mock_context, query_type="ip", query="8.8.8.8")
                assert result.success is False
                assert "rate limit" in result.error.lower()

    @pytest.mark.asyncio
    async def test_resource_not_found(self, mock_context):
        mock_session = make_aiohttp_mock(404, '{"error": {"message": "Not found"}}')
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = await virustotal_query(ctx=mock_context, query_type="ip", query="1.2.3.4")
                assert result.success is False
                assert "not found" in result.error.lower()
