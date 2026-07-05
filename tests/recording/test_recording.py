import os
from pathlib import Path

import pytest

from flocks.session.recorder import Recorder


@pytest.mark.asyncio
async def test_recorder_writes_session_jsonl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOCKS_RECORD_DIR", str(tmp_path / "records"))

    await Recorder.record_session_message(
        session_id="s1",
        message_id="m1",
        role="user",
        text="hello",
        extra={"k": "v"},
    )

    p = tmp_path / "records" / "session" / "s1.jsonl"
    assert p.exists()
    content = p.read_text(encoding="utf-8")
    assert '"type": "session.message"' in content
    assert '"text": "hello"' in content


@pytest.mark.asyncio
async def test_recorder_writes_workflow_jsonl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOCKS_RECORD_DIR", str(tmp_path / "records"))

    await Recorder.record_workflow_execution(
        exec_id="e1",
        workflow_id="wf1",
        run_result={
            "status": "success",
            "outputs": {"ok": True},
            "history": [
                {
                    "node_id": "n1",
                    "inputs": {"a": 1},
                    "outputs": {"b": 2},
                    "stdout": "x",
                    "error": None,
                    "traceback": None,
                    "duration_ms": 1.2,
                }
            ],
        },
    )

    p = tmp_path / "records" / "workflow" / "e1.jsonl"
    assert p.exists()
    content = p.read_text(encoding="utf-8")
    assert '"type": "workflow.summary"' in content
    assert '"type": "workflow.step"' in content

