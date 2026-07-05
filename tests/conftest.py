"""
Pytest configuration and global fixtures
"""

import os

import pytest

_API_KEY_MARKERS = {
    "requires_anthropic_key": ("ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY not set"),
    "requires_openai_key": ("OPENAI_API_KEY", "OPENAI_API_KEY not set"),
    "requires_threatbook_key": ("THREATBOOK_API_KEY", "THREATBOOK_API_KEY not set"),
    "requires_google_key": ("GOOGLE_API_KEY", "GOOGLE_API_KEY not set"),
    "requires_glm_key": ("GLM_API_KEY", "GLM_API_KEY not set"),
}


def pytest_configure(config):
    """Configure custom markers"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (may require external services)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running (>30s per test)"
    )
    config.addinivalue_line(
        "markers",
        "live: mark test as requiring live services "
        "(set FLOCKS_LIVE_TEST=1 and start dev server to enable)"
    )
    for marker_name, (_, reason) in _API_KEY_MARKERS.items():
        config.addinivalue_line("markers", f"{marker_name}: skip if {reason}")


def pytest_runtest_setup(item):
    """Auto-skip tests whose required API keys are not set."""
    for marker_name, (env_var, reason) in _API_KEY_MARKERS.items():
        if item.get_closest_marker(marker_name) and not os.getenv(env_var):
            pytest.skip(reason)
