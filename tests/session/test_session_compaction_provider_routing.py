"""Regression tests for compaction model/provider routing."""

from types import SimpleNamespace

import pytest

from flocks.provider.provider import Provider
from flocks.session.lifecycle.compaction import SessionCompaction
from flocks.session.message import Message


@pytest.mark.asyncio
async def test_compaction_process_uses_provider_instance_chat(monkeypatch):
    """Compaction should call provider.chat(model_id) directly."""

    call_log = {"chat_called": False, "chat_model_id": None}
    created_payload = {}

    class FakeProvider:
        async def chat(self, model_id, messages, **kwargs):
            call_log["chat_called"] = True
            call_log["chat_model_id"] = model_id
            return SimpleNamespace(content="summary from fake provider")

    fake_provider = FakeProvider()

    async def fake_apply_config(cls, config=None, provider_id=None):
        return None

    async def fail_provider_chat(cls, *args, **kwargs):
        raise AssertionError("Provider.chat should not be used in compaction process")

    async def fake_list_with_parts(cls, session_id):
        msg = SimpleNamespace(
            info=SimpleNamespace(id="msg_user_1", role="user"),
            parts=[SimpleNamespace(type="text", text="hello from test")],
        )
        return [msg]

    async def fake_list(cls, session_id):
        return []

    async def fake_create(cls, **kwargs):
        created_payload.update(kwargs)
        return SimpleNamespace(id="msg_summary_1")

    async def fake_flush(cls, **kwargs):
        return None

    monkeypatch.setattr(
        Provider,
        "get",
        classmethod(lambda cls, provider_id: fake_provider if provider_id == "openai" else None),
    )
    monkeypatch.setattr(Provider, "apply_config", classmethod(fake_apply_config))
    monkeypatch.setattr(Provider, "chat", classmethod(fail_provider_chat))
    monkeypatch.setattr(Message, "list_with_parts", classmethod(fake_list_with_parts))
    monkeypatch.setattr(Message, "list", classmethod(fake_list))
    monkeypatch.setattr(Message, "create", classmethod(fake_create))
    monkeypatch.setattr(SessionCompaction, "_flush_memory_to_daily", classmethod(fake_flush))

    result = await SessionCompaction.process(
        session_id="ses_test_1",
        parent_id="msg_parent_1",
        messages=[{"id": "msg_user_1"}],
        model_id="siliconflow: Pro/MiniMaxAI/MiniMax-M2.5",
        provider_id="openai",
        auto=True,
    )

    assert result == "continue"
    assert call_log["chat_called"] is True
    assert call_log["chat_model_id"] == "siliconflow: Pro/MiniMaxAI/MiniMax-M2.5"
    assert created_payload["provider_id"] == "openai"
    assert created_payload["model_id"] == "siliconflow: Pro/MiniMaxAI/MiniMax-M2.5"
