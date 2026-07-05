"""
Tests for flocks/session/features/reminders.py

Covers:
- ReminderConfig: defaults and customization
- ReminderContext: creation and fields
- SessionReminders.should_remind(): stub behavior
- SessionReminders.create_reminder(): stub behavior
- SessionReminders.extract_original_task(): extracts first user message
- SessionReminders.clear_session(): cleans state
- Constants: REMINDER_STEP_INTERVAL, etc.
"""

import pytest

from flocks.session.features.reminders import (
    REMINDER_MESSAGE_INTERVAL,
    REMINDER_STEP_INTERVAL,
    REMINDER_TIME_INTERVAL,
    ReminderConfig,
    ReminderContext,
    SessionReminders,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_step_interval_default(self):
        assert REMINDER_STEP_INTERVAL == 10

    def test_message_interval_default(self):
        assert REMINDER_MESSAGE_INTERVAL == 20

    def test_time_interval_default(self):
        assert REMINDER_TIME_INTERVAL == 300000  # 5 min in ms


# ---------------------------------------------------------------------------
# ReminderConfig
# ---------------------------------------------------------------------------

class TestReminderConfig:
    def test_defaults(self):
        config = ReminderConfig()
        assert config.step_interval == REMINDER_STEP_INTERVAL
        assert config.message_interval == REMINDER_MESSAGE_INTERVAL
        assert config.time_interval == REMINDER_TIME_INTERVAL
        assert config.enabled is True

    def test_custom_values(self):
        config = ReminderConfig(step_interval=5, message_interval=10, time_interval=60000, enabled=False)
        assert config.step_interval == 5
        assert config.enabled is False

    def test_can_disable(self):
        config = ReminderConfig(enabled=False)
        assert config.enabled is False


# ---------------------------------------------------------------------------
# ReminderContext
# ---------------------------------------------------------------------------

class TestReminderContext:
    def test_basic_creation(self):
        ctx = ReminderContext(
            session_id="ses_1",
            step_count=15,
            message_count=30,
            elapsed_ms=150000,
        )
        assert ctx.session_id == "ses_1"
        assert ctx.step_count == 15
        assert ctx.message_count == 30
        assert ctx.elapsed_ms == 150000

    def test_optional_fields_default_none(self):
        ctx = ReminderContext(session_id="ses_2", step_count=0, message_count=0, elapsed_ms=0)
        assert ctx.original_task is None
        assert ctx.current_focus is None

    def test_with_optional_fields(self):
        ctx = ReminderContext(
            session_id="ses_3",
            step_count=5,
            message_count=10,
            elapsed_ms=50000,
            original_task="Investigate suspicious login",
            current_focus="Checking logs",
        )
        assert ctx.original_task == "Investigate suspicious login"
        assert ctx.current_focus == "Checking logs"


# ---------------------------------------------------------------------------
# SessionReminders (stub behavior)
# ---------------------------------------------------------------------------

class TestSessionRemindersShouldRemind:
    def test_always_returns_false(self):
        ctx = ReminderContext(session_id="ses_x", step_count=100, message_count=200, elapsed_ms=999999)
        assert SessionReminders.should_remind("ses_x", ctx) is False

    def test_returns_false_regardless_of_config(self):
        ctx = ReminderContext(session_id="ses_y", step_count=5, message_count=5, elapsed_ms=1000)
        config = ReminderConfig(step_interval=1, message_interval=1, time_interval=100)
        assert SessionReminders.should_remind("ses_y", ctx, config) is False


class TestSessionRemindersCreateReminder:
    @pytest.mark.asyncio
    async def test_returns_none(self):
        ctx = ReminderContext(session_id="ses_r", step_count=10, message_count=20, elapsed_ms=60000)
        result = await SessionReminders.create_reminder("ses_r", ctx)
        assert result is None


class TestSessionRemindersExtractOriginalTask:
    @pytest.mark.asyncio
    async def test_returns_none_for_empty_messages(self):
        result = await SessionReminders.extract_original_task([])
        assert result is None

    @pytest.mark.asyncio
    async def test_extracts_first_user_message(self):
        from unittest.mock import AsyncMock, patch, MagicMock
        from flocks.session.message import MessageRole

        user_msg = MagicMock()
        user_msg.role = MessageRole.USER

        # Message is imported inside extract_original_task - patch at the source module
        with patch(
            "flocks.session.message.Message.get_text_content",
            new=AsyncMock(return_value="Find the security incident"),
        ):
            result = await SessionReminders.extract_original_task([user_msg])

        assert result is not None
        assert "Find the security incident" in result

    @pytest.mark.asyncio
    async def test_truncates_long_task_to_200_chars(self):
        from unittest.mock import AsyncMock, patch, MagicMock
        from flocks.session.message import MessageRole

        user_msg = MagicMock()
        user_msg.role = MessageRole.USER
        long_task = "x" * 300

        with patch(
            "flocks.session.message.Message.get_text_content",
            new=AsyncMock(return_value=long_task),
        ):
            result = await SessionReminders.extract_original_task([user_msg])

        assert result is not None
        assert len(result) <= 203  # 200 + "..."
        assert result.endswith("...")

    @pytest.mark.asyncio
    async def test_skips_non_user_messages(self):
        from unittest.mock import AsyncMock, patch, MagicMock
        from flocks.session.message import MessageRole, Message

        assistant_msg = MagicMock()
        assistant_msg.role = MessageRole.ASSISTANT

        # For non-user messages, get_text_content should never be called
        original = Message.get_text_content
        calls = []

        async def tracking_fn(*args, **kwargs):
            calls.append(args)
            return await original(*args, **kwargs)

        with patch("flocks.session.message.Message.get_text_content", new=AsyncMock(side_effect=tracking_fn)):
            result = await SessionReminders.extract_original_task([assistant_msg])

        assert not calls, "get_text_content should not be called for assistant messages"
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_text_content(self):
        from unittest.mock import AsyncMock, patch, MagicMock
        from flocks.session.message import MessageRole

        user_msg = MagicMock()
        user_msg.role = MessageRole.USER

        with patch(
            "flocks.session.message.Message.get_text_content",
            new=AsyncMock(return_value=None),
        ):
            result = await SessionReminders.extract_original_task([user_msg])

        assert result is None


class TestSessionRemindersClearSession:
    def test_clear_existing_session(self):
        # Manually inject state
        SessionReminders._last_reminder["ses_clear"] = 12345
        SessionReminders._last_step["ses_clear"] = 5

        SessionReminders.clear_session("ses_clear")

        assert "ses_clear" not in SessionReminders._last_reminder
        assert "ses_clear" not in SessionReminders._last_step

    def test_clear_nonexistent_session_does_not_raise(self):
        SessionReminders.clear_session("nonexistent_session")  # should not raise
