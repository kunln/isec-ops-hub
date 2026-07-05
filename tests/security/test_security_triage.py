from pathlib import Path

import pytest

from flocks.security.sample_data import SAMPLE_IDS, load_sample_data
from flocks.security.store import SecurityStore
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
async def test_triage_alert_creates_incident_idempotently(initialized_storage):
    await load_sample_data()

    first = await triage_alert(SAMPLE_IDS["alert"], create_incident=True)
    second = await triage_alert(SAMPLE_IDS["alert"], create_incident=True)

    assert first.should_create_incident is True
    assert first.incident_id
    assert second.incident_id == first.incident_id

    store = SecurityStore()
    alert = await store.get_alert(SAMPLE_IDS["alert"])
    assert alert is not None
    assert alert.status == "incident_created"
