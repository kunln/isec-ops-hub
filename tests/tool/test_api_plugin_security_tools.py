from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from flocks.tool.registry import ToolContext
from flocks.tool.tool_loader import yaml_to_tool


def _load_tool(yaml_path: Path):
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    return yaml_to_tool(raw, yaml_path)


def _make_aiohttp_json_session(payload: dict):
    response = AsyncMock()
    response.status = 200
    response.json = AsyncMock(return_value=payload)
    response.raise_for_status = MagicMock()

    response_cm = AsyncMock()
    response_cm.__aenter__ = AsyncMock(return_value=response)
    response_cm.__aexit__ = AsyncMock(return_value=None)

    session = AsyncMock()
    session.get = MagicMock(return_value=response_cm)
    session.post = MagicMock(return_value=response_cm)
    session.request = MagicMock(return_value=response_cm)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


def _make_aiohttp_bytes_session(payload: bytes, content_type: str):
    response = AsyncMock()
    response.read = AsyncMock(return_value=payload)
    response.headers = {"Content-Type": content_type}
    response.raise_for_status = MagicMock()

    response_cm = AsyncMock()
    response_cm.__aenter__ = AsyncMock(return_value=response)
    response_cm.__aexit__ = AsyncMock(return_value=None)

    session = AsyncMock()
    session.get = MagicMock(return_value=response_cm)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


class TestThreatBookCnYamlTools:
    @pytest.mark.asyncio
    async def test_threatbook_cn_url_scan_uses_yaml_http_handler(self):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "threatbook-cn" / "threatbook_cn_url_scan.yaml"
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_json_session({
            "response_code": 0,
            "data": {"task_id": "scan-1", "status": "queued"},
        })

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(
                ToolContext(session_id="test", message_id="test"),
                url="https://example.com",
            )

        assert tool.info.source == "api"
        assert tool.info.provider == "threatbook-cn"
        assert result.success is True
        assert result.output["data"] == {"task_id": "scan-1", "status": "queued"}

    @pytest.mark.asyncio
    async def test_threatbook_cn_file_upload_uses_yaml_script_handler(self, tmp_path):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "threatbook-cn" / "threatbook_cn_file_upload.yaml"
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"hello")
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_json_session({
            "response_code": 0,
            "data": {
                "sha256": "abc123",
                "permalink": "https://x.threatbook.cn/report/abc123",
            },
        })

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(
                ToolContext(session_id="test", message_id="test"),
                file_path=str(sample),
            )

        assert tool.info.provider == "threatbook-cn"
        assert result.success is True
        assert result.output["sha256"] == "abc123"
        assert result.output["permalink"] == "https://x.threatbook.cn/report/abc123"


class TestThreatBookIoYamlTools:
    @pytest.mark.asyncio
    async def test_threatbook_io_ip_query_uses_yaml_http_handler(self):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "threatbook-io" / "threatbook_io_ip_query.yaml"
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_json_session({
            "response_code": 0,
            "data": {
                "8.8.8.8": {
                    "severity": "info",
                    "judgments": ["Whitelist"],
                }
            },
        })

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(
                ToolContext(session_id="test", message_id="test"),
                resource="8.8.8.8",
            )

        assert tool.info.source == "api"
        assert tool.info.provider == "threatbook-io"
        assert result.success is True
        assert result.output["data"]["8.8.8.8"]["severity"] == "info"

    @pytest.mark.asyncio
    async def test_threatbook_io_file_upload_uses_yaml_script_handler(self, tmp_path):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "threatbook-io" / "threatbook_io_file_upload.yaml"
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"hello")
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_json_session({
            "response_code": 200,
            "data": {"sha256": "def456", "status": "done"},
        })

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(
                ToolContext(session_id="test", message_id="test"),
                file_path=str(sample),
            )

        assert tool.info.provider == "threatbook-io"
        assert result.success is True
        assert result.output == {"sha256": "def456", "status": "done"}


class TestVirusTotalYamlTools:
    @pytest.mark.asyncio
    async def test_virustotal_ip_query_uses_yaml_script_handler(self):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "virustotal" / "virustotal_ip_query.yaml"
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_json_session({
            "data": {
                "attributes": {
                    "reputation": 12,
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "undetected": 10,
                        "harmless": 50,
                    },
                    "country": "US",
                    "as_owner": "Google LLC",
                    "tags": ["dns"],
                    "last_analysis_date": 1234567890,
                }
            }
        })

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(ToolContext(session_id="test", message_id="test"), ip="8.8.8.8")

        assert tool.info.source == "api"
        assert tool.info.provider == "virustotal"
        assert result.success is True
        assert result.output == {
            "data": {
                "attributes": {
                    "reputation": 12,
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "undetected": 10,
                        "harmless": 50,
                    },
                    "country": "US",
                    "as_owner": "Google LLC",
                    "tags": ["dns"],
                    "last_analysis_date": 1234567890,
                }
            }
        }
        assert result.metadata["api"] == "ip_addresses"


class TestUrlscanYamlTools:
    @pytest.mark.asyncio
    async def test_urlscan_screenshot_returns_base64_payload(self):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "urlscan" / "screenshot.yaml"
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_bytes_session(b"\x89PNG\r\n", "image/png")

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(ToolContext(session_id="test", message_id="test"), scan_id="scan-1")

        assert result.success is True
        assert result.output["content_type"] == "image/png"
        assert result.output["encoding"] == "base64"
        assert result.output["content_base64"] == "iVBORw0K"
        assert result.metadata["api"] == "screenshots"

    @pytest.mark.asyncio
    async def test_urlscan_dom_returns_text_payload(self):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "urlscan" / "dom.yaml"
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.return_value = "test_api_key"
        mock_session = _make_aiohttp_bytes_session(b"<html>ok</html>", "text/html")

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(ToolContext(session_id="test", message_id="test"), scan_id="scan-1")

        assert result.success is True
        assert result.output == {
            "content_type": "text/html",
            "content": "<html>ok</html>",
            "encoding": "utf-8",
        }
        assert result.metadata["api"] == "dom"


class TestFofaYamlTools:
    @pytest.mark.asyncio
    async def test_fofa_info_derives_email_and_api_key_from_canonical_secret(self):
        yaml_path = Path.cwd() / ".flocks" / "plugins" / "tools" / "api" / "fofa" / "info.yaml"
        mock_secret_manager = MagicMock()
        mock_secret_manager.get.side_effect = lambda key: {
            "fofa_key": "analyst@example.com:fofa-api-key",
        }.get(key)
        mock_session = _make_aiohttp_json_session({
            "error": False,
            "username": "analyst",
        })

        with (
            patch("flocks.security.get_secret_manager", return_value=mock_secret_manager),
            patch("aiohttp.ClientSession", return_value=mock_session),
        ):
            tool = _load_tool(yaml_path)
            result = await tool.handler(ToolContext(session_id="test", message_id="test"))

        assert tool.info.provider == "fofa"
        assert result.success is True
        assert result.output["username"] == "analyst"
        _, kwargs = mock_session.request.call_args
        assert kwargs["params"]["email"] == "analyst@example.com"
        assert kwargs["params"]["key"] == "fofa-api-key"
