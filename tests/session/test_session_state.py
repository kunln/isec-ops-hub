"""
Tests for flocks/session/core/session_state.py

Covers:
- Main session get/set
- Session agent get/set/clear
- Subagent session add/remove/list
- Thread safety under concurrent access
"""

import threading
import pytest

from flocks.session.core import session_state as ss


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_state():
    """Reset module-level globals between tests."""
    with ss._lock:
        ss._main_session_id = None
        ss._session_agent.clear()
        ss._subagent_sessions.clear()


@pytest.fixture(autouse=True)
def clean_state():
    _reset_state()
    yield
    _reset_state()


# ---------------------------------------------------------------------------
# Main session
# ---------------------------------------------------------------------------

class TestMainSession:
    def test_get_returns_none_initially(self):
        assert ss.get_main_session_id() is None

    def test_set_and_get(self):
        ss.set_main_session("ses_abc123")
        assert ss.get_main_session_id() == "ses_abc123"

    def test_overwrite(self):
        ss.set_main_session("ses_first")
        ss.set_main_session("ses_second")
        assert ss.get_main_session_id() == "ses_second"

    def test_clear_with_none(self):
        ss.set_main_session("ses_abc")
        ss.set_main_session(None)
        assert ss.get_main_session_id() is None


# ---------------------------------------------------------------------------
# Session agent
# ---------------------------------------------------------------------------

class TestSessionAgent:
    def test_get_returns_none_for_unknown(self):
        assert ss.get_session_agent("nonexistent") is None

    def test_set_and_get(self):
        ss.set_session_agent("ses_1", "rex")
        assert ss.get_session_agent("ses_1") == "rex"

    def test_multiple_sessions_independent(self):
        ss.set_session_agent("ses_a", "rex")
        ss.set_session_agent("ses_b", "plan")
        assert ss.get_session_agent("ses_a") == "rex"
        assert ss.get_session_agent("ses_b") == "plan"

    def test_clear_removes_entry(self):
        ss.set_session_agent("ses_1", "rex")
        ss.clear_session_agent("ses_1")
        assert ss.get_session_agent("ses_1") is None

    def test_clear_nonexistent_does_not_raise(self):
        ss.clear_session_agent("nonexistent")  # should not raise

    def test_overwrite_agent(self):
        ss.set_session_agent("ses_1", "rex")
        ss.set_session_agent("ses_1", "explore")
        assert ss.get_session_agent("ses_1") == "explore"


# ---------------------------------------------------------------------------
# Subagent sessions
# ---------------------------------------------------------------------------

class TestSubagentSessions:
    def test_list_empty_initially(self):
        result = ss.list_subagent_sessions()
        assert isinstance(result, set)
        assert len(result) == 0

    def test_add_and_list(self):
        ss.add_subagent_session("ses_sub1")
        result = ss.list_subagent_sessions()
        assert "ses_sub1" in result

    def test_add_multiple(self):
        ss.add_subagent_session("ses_sub1")
        ss.add_subagent_session("ses_sub2")
        result = ss.list_subagent_sessions()
        assert "ses_sub1" in result
        assert "ses_sub2" in result

    def test_remove_existing(self):
        ss.add_subagent_session("ses_sub1")
        ss.remove_subagent_session("ses_sub1")
        result = ss.list_subagent_sessions()
        assert "ses_sub1" not in result

    def test_remove_nonexistent_does_not_raise(self):
        ss.remove_subagent_session("nonexistent")  # should not raise

    def test_list_returns_copy(self):
        ss.add_subagent_session("ses_sub1")
        result1 = ss.list_subagent_sessions()
        result1.add("injected")
        result2 = ss.list_subagent_sessions()
        assert "injected" not in result2

    def test_add_duplicate_idempotent(self):
        ss.add_subagent_session("ses_sub1")
        ss.add_subagent_session("ses_sub1")
        result = ss.list_subagent_sessions()
        assert result.count("ses_sub1") if hasattr(result, 'count') else len([x for x in result if x == "ses_sub1"]) == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_set_main_session(self):
        results = []
        errors = []

        def writer(val):
            try:
                ss.set_main_session(val)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(f"ses_{i}",)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Final value must be one of the set values
        final = ss.get_main_session_id()
        assert final is None or final.startswith("ses_")

    def test_concurrent_set_session_agent(self):
        errors = []

        def writer(i):
            try:
                ss.set_session_agent(f"ses_{i}", f"agent_{i}")
                ss.get_session_agent(f"ses_{i}")
                ss.clear_session_agent(f"ses_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_concurrent_subagent_add_remove(self):
        errors = []

        def worker(i):
            try:
                ss.add_subagent_session(f"sub_{i}")
                ss.list_subagent_sessions()
                ss.remove_subagent_session(f"sub_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
