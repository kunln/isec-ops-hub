from pathlib import Path

import pytest

from flocks.commercial.models import (
    CommercialAuditEvent,
    CommercialPackageManifest,
    PackageType,
    UpdatePolicyUpdate,
)
from flocks.commercial.store import CommercialStore
from flocks.storage.storage import Storage


@pytest.fixture
async def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield CommercialStore()
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


@pytest.mark.asyncio
async def test_commercial_defaults_are_local_and_private(store: CommercialStore):
    connectivity = await store.get_connectivity()
    telemetry = await store.get_telemetry()
    update_policy = await store.get_update_policy()

    assert connectivity.outbound_enabled is False
    assert telemetry.enabled is False
    assert telemetry.include_security_data is False
    assert update_policy.update_check_enabled is False
    assert update_policy.update_apply_enabled is False
    assert update_policy.legacy_flocks_update_sources_enabled is False
    assert update_policy.auto_check is False
    assert update_policy.auto_install is False
    assert update_policy.manual_approval is True
    assert update_policy.signature_required is True

    notification_policy = await store.get_notification_policy()
    assert notification_policy.local_notifications_enabled is True
    assert notification_policy.built_in_notifications_enabled is False
    assert notification_policy.benefit_notifications_enabled is False
    assert notification_policy.whats_new_notifications_enabled is False
    assert notification_policy.vendor_notifications_enabled is False


@pytest.mark.asyncio
async def test_update_policy_legacy_fields_stay_synchronized(store: CommercialStore):
    updated = await store.update_update_policy(
        UpdatePolicyUpdate(auto_check=True, auto_install=True, channel="beta")
    )
    assert updated.update_check_enabled is True
    assert updated.update_apply_enabled is True
    assert updated.update_channel == "beta"

    updated = await store.update_update_policy(
        UpdatePolicyUpdate(
            update_check_enabled=False,
            update_apply_enabled=False,
            update_channel="stable",
        )
    )
    assert updated.auto_check is False
    assert updated.auto_install is False
    assert updated.channel == "stable"


@pytest.mark.asyncio
async def test_package_install_sets_rollback_version(store: CommercialStore):
    first = await store.install_package(
        CommercialPackageManifest(
            id="sample-skill",
            type=PackageType.SKILL,
            name="Sample Skill",
            version="1.0.0",
        )
    )
    second = await store.install_package(
        CommercialPackageManifest(
            id="sample-skill",
            type=PackageType.SKILL,
            name="Sample Skill",
            version="1.1.0",
        )
    )

    assert first.rollback_version is None
    assert second.rollback_version == "1.0.0"

    rolled_back = await store.rollback_package("sample-skill")
    assert rolled_back is not None
    assert rolled_back.version == "1.0.0"
    assert rolled_back.rollback_version == "1.1.0"


def test_legacy_package_permissions_are_normalized():
    manifest = CommercialPackageManifest(
        id="legacy-tool",
        type=PackageType.TOOL,
        name="Legacy Tool",
        version="1.0.0",
        permissions=["bash"],
    )

    assert manifest.permissions[0].id == "bash"
    assert manifest.permissions[0].risk == "medium"


@pytest.mark.asyncio
async def test_audit_events_are_listed_newest_first(store: CommercialStore):
    first = await store.record_audit_event(
        CommercialAuditEvent(action="commercial.test.first", target="test", status="success")
    )
    second = await store.record_audit_event(
        CommercialAuditEvent(action="commercial.test.second", target="test", status="denied")
    )

    events = await store.list_audit_events()
    assert [event.id for event in events] == [second.id, first.id]
