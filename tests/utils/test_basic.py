"""
Basic tests to verify project setup
"""

import pytest
from flocks import __version__
from flocks.utils.id import Identifier
from flocks.utils.log import Log


def test_version():
    """Test version is a non-empty string; bare (no leading v) even if pyproject uses v-prefixed."""
    assert isinstance(__version__, str)
    assert __version__
    assert not __version__.startswith("v")


def test_identifier_generation():
    """Test identifier generation"""
    # Use ascending() which is the new API
    session_id = Identifier.ascending("session")
    assert session_id.startswith("ses_")  # New prefix format
    assert len(session_id) == 30  # "ses_" (4) + 26 chars
    
    message_id = Identifier.ascending("message")
    assert message_id.startswith("msg_")  # New prefix format


def test_identifier_validation():
    """Test identifier validation"""
    # Generate a valid ID to test
    valid_id = Identifier.ascending("session")
    assert Identifier.validate(valid_id, "session")
    
    # Test with wrong prefix
    assert not Identifier.validate(valid_id, "message")
    
    # Test with invalid format
    invalid_id = "msg_123"
    assert not Identifier.validate(invalid_id, "message")


def test_identifier_parse():
    """Test identifier parsing"""
    # Generate a valid ID to test parsing
    identifier = Identifier.ascending("session")
    prefix, id_part = Identifier.parse(identifier)
    assert prefix == "ses"  # New prefix format
    assert len(id_part) == 26  # ID part should be 26 characters


@pytest.mark.asyncio
async def test_log_initialization():
    """Test log system initialization"""
    await Log.init(print=False, dev=True, level="DEBUG")
    
    logger = Log.create(service="test")
    assert logger._tags.get("service") == "test"  # New API uses tags
    
    # Should not raise
    logger.info("test_event", {"data": "test"})
    logger.debug("debug_event")
    logger.warn("warn_event")
    logger.error("error_event")
