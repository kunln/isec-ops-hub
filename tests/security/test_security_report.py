from pathlib import Path

import pytest

from flocks.security.report import generate_incident_report
from flocks.security.sample_data import SAMPLE_IDS, load_sample_data
from flocks.security.triage import triage_alert
from flocks.storage.storage import Storage


@pytest.fixture
async def initialized_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


@pytest.mark.asyncio
async def test_generate_incident_report_contains_customer_readable_sections(initialized_storage):
    await load_sample_data()
    triage = await triage_alert(SAMPLE_IDS["alert"], create_incident=True)

    report = await generate_incident_report(triage.incident_id)

    assert "# 安全事件研判报告" in report
    assert "## 二、影响资产" in report
    assert "Internet Portal" in report
    assert "不足以确认" in report or "证据" in report
