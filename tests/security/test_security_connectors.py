import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from flocks.security.connectors.capabilities import capability_downgrade_message
from flocks.security.connectors.credential_bindings import load_connector_credential_binding_registry
from flocks.security.connectors.operations import load_connector_operations_registry
from flocks.security.connectors.package_loader import BUILTIN_CONNECTOR_PACKAGE_ROOT
from flocks.security.connectors.registry import connector_registry, get_mock_connector_id, get_replay_connector_id
from flocks.security.connectors.registry import (
    _customer_credential_summary,
    _customer_data_source_actions,
    _customer_sync_status,
    _customer_sync_summary,
)
from flocks.security.connectors.replay import FIXTURE_ROOT
from flocks.security.connectors.scheduler import load_connector_sync_schedule_registry
from flocks.security.connectors.sync_runtime import load_connector_sync_run_registry


@pytest.fixture(autouse=True)
def reset_connector_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.security import secrets as secrets_module

    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests(
        package_roots=[BUILTIN_CONNECTOR_PACKAGE_ROOT],
        installed_registry_path=tmp_path / "installed-packages.json",
        credential_binding_path=tmp_path / "credential-bindings.json",
        sync_run_registry_path=tmp_path / "sync-runs.json",
        sync_schedule_registry_path=tmp_path / "sync-schedules.json",
        operations_registry_path=tmp_path / "operations.json",
    )
    asyncio.run(connector_registry.install_package(FIXTURE_ROOT, enabled=True))
    yield
    connector_registry.reset_for_tests()
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None


def test_connector_registry_exposes_mock_manifest_and_capabilities():
    connectors = connector_registry.list()

    assert len(connectors) == 2
    connector = connector_registry.get(get_mock_connector_id())
    assert connector is not None
    assert connector.id == get_mock_connector_id()
    assert "asset.search" in connector.capabilities
    assert connector.normalized_data["assets"][0]["raw_data"]["connector_id"] == connector.id
    assert connector.normalized_data["alerts"][0]["normalized_data"]["mitre_technique"] == "T1059"


def test_connector_registry_exposes_fixture_replay_manifest():
    connector = connector_registry.get(get_replay_connector_id())

    assert connector is not None
    assert connector.deployment == "local_fixture"
    assert "asset.search" in connector.capabilities
    assert connector.raw_response["source"] == "builtin"
    assert "/connectors/installed/fixture-replay-demo/" in connector.raw_response["package_root"]
    assert connector.adapter_contracts["asset.search"]["version"] == "connector.adapter.v1"
    assert connector.mapping_contracts["asset.search"]["version"] == "connector.mapping.v1"


@pytest.mark.asyncio
async def test_mingjian_connector_customer_summary_exposes_asset_and_vulnerability_sync():
    package_root = BUILTIN_CONNECTOR_PACKAGE_ROOT / "dbappsecurity-mingjian-vuln-scanner-v5-0"

    await connector_registry.install_package(package_root, enabled=True)

    connector = connector_registry.get("dbappsecurity-mingjian-vuln-scanner-v5-0")
    assert connector is not None
    assert connector.product == "Mingjian Vuln Scanner"
    assert [str(getattr(item, "value", item)) for item in connector.capabilities] == [
        "asset.search",
        "vulnerability.search",
    ]

    summary = await connector_registry.customer_summary()
    source = next(
        item
        for item in summary["data_sources"]
        if item["id"] == "dbappsecurity-mingjian-vuln-scanner-v5-0"
    )

    assert source["name"] == "DBAPPSecurity Mingjian Vulnerability Scanner Connector"
    assert source["product"] == "Mingjian Vuln Scanner"
    assert source["sync_status"] == "not_synced"
    assert source["capabilities"] == ["asset.search", "vulnerability.search"]
    assert source["sync_targets"] == ["assets", "vulnerabilities"]


@pytest.mark.asyncio
async def test_asiainfo_tda_connector_customer_summary_exposes_asset_sync():
    package_root = BUILTIN_CONNECTOR_PACKAGE_ROOT / "asiainfo-tda-v7-0"

    await connector_registry.install_package(package_root, enabled=True)

    connector = connector_registry.get("asiainfo-tda-v7-0")
    assert connector is not None
    assert connector.product == "asiainfo_tda"
    assert [str(getattr(item, "value", item)) for item in connector.capabilities] == ["asset.search", "alert.search"]

    summary = await connector_registry.customer_summary()
    source = next(
        item
        for item in summary["data_sources"]
        if item["id"] == "asiainfo-tda-v7-0"
    )

    assert source["name"] == "AsiaInfo Xinwei TDA Connector"
    assert source["product"] == "asiainfo_tda"
    assert source["sync_status"] == "not_synced"
    assert source["capabilities"] == ["alert.search", "asset.search"]
    assert source["sync_targets"] == ["assets", "alerts"]


@pytest.mark.asyncio
async def test_connector_registry_only_loads_enabled_installed_packages(tmp_path):
    registry_path = tmp_path / "installed-packages-empty.json"
    connector_registry.reset_for_tests(
        package_roots=[BUILTIN_CONNECTOR_PACKAGE_ROOT],
        installed_registry_path=registry_path,
    )

    assert connector_registry.get(get_replay_connector_id()) is None
    diagnostics = await connector_registry.package_diagnostics()
    package = diagnostics["packages"][0]
    assert package["installed"] is False
    assert package["runtime_status"] == "not_installed"

    await connector_registry.install_package(FIXTURE_ROOT)
    assert connector_registry.get(get_replay_connector_id()) is None

    await connector_registry.enable_package(get_replay_connector_id())
    assert connector_registry.get(get_replay_connector_id()) is not None
    preview = await connector_registry.preview(get_replay_connector_id(), "asset.search")
    assert preview.success is True

    connector_registry.disable_package(get_replay_connector_id())
    assert connector_registry.get(get_replay_connector_id()) is None
    with pytest.raises(ValueError, match="Connector not found"):
        await connector_registry.preview(get_replay_connector_id(), "asset.search")


@pytest.mark.asyncio
async def test_connector_test_connection_returns_raw_and_normalized_payloads():
    result = await connector_registry.test_connection(get_mock_connector_id())

    assert result.success is True
    assert result.status == "ok"
    assert result.raw_response["assets"]
    assert result.normalized_data["vulnerabilities"][0]["cve_id"] == "CVE-MOCK-2026-0001"


@pytest.mark.asyncio
async def test_connector_preview_replays_fixture_with_warnings():
    result = await connector_registry.preview(get_replay_connector_id(), "asset.search")

    assert result.success is True
    assert result.source.endswith("assets_search.json")
    assert result.raw_response["items"]
    assert result.normalized_data["assets"][0]["name"] == "Replay Internet Portal"
    assert result.mapping_result == result.normalized_data
    assert result.adapter_contract["version"] == "connector.adapter.v1"
    assert result.adapter_contract["transport"] == "fixture"
    assert "items[1].ip" in result.missing_fields
    assert "items[1].ip" in result.missing_required_fields
    assert result.mapping_contract["version"] == "connector.mapping.v1"


@pytest.mark.asyncio
async def test_connector_validate_checks_adapter_and_mapping_contracts():
    result = await connector_registry.validate(get_replay_connector_id())

    assert result.success is True
    assert result.adapter_contracts["asset.search"]["version"] == "connector.adapter.v1"
    assert result.mapping_contracts["asset.search"]["version"] == "connector.mapping.v1"


@pytest.mark.asyncio
async def test_connector_preview_reports_missing_capability_without_failing_registry():
    result = await connector_registry.preview(get_replay_connector_id(), "endpoint.process_tree")

    assert result.success is False
    assert result.missing_capabilities == ["endpoint.process_tree"]


def test_capability_downgrade_message_reports_missing_capabilities():
    message = capability_downgrade_message(
        ["asset.search", "alert.search"],
        ["asset.search", "endpoint.process_tree"],
    )

    assert message is not None
    assert "endpoint.process_tree" in message


@pytest.mark.asyncio
async def test_expired_credential_profile_blocks_connector_sync():
    connector_id = get_replay_connector_id()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-expired", "VENDOR_TOKEN": "expired-token"},
        profile_id="expired-profile",
        expires_at="2000-01-01T00:00:00+00:00",
    )

    result = await connector_registry.sync(
        connector_id,
        "asset.search",
        credential_profile_id="expired-profile",
    )

    assert result["status"] == "blocked"
    assert result["source"] == "credential_health_gate"
    assert result["run_policy"]["version"] == "connector.run.policy.v1"
    assert result["run_policy"]["reason"] == "credential_profile_expired"
    assert result["credential_health"]["status"] == "expired"
    assert result["credential_health"]["reason_code"] == "expired"
    assert result["credential_health"]["severity"] == "critical"
    assert result["counts"] == {}
    assert result["cursor_updated"] is False
    rotate_action = next(action for action in result["run_policy"]["actions"] if action["kind"] == "rotate_credentials")
    assert rotate_action["profile_expires_at"] == "2000-01-01T00:00:00+00:00"
    assert connector_registry.list_sync_runs(connector_id)[0]["status"] == "blocked"

    diagnostics = await connector_registry.package_diagnostics()
    retention = diagnostics["sync_run_registry"]["blocked_run_retention"]
    assert retention["retained"] is True
    assert retention["reason"] == "audit_history"
    assert diagnostics["sync_run_registry"]["last_blocked_run"]["id"] == result["id"]
    assert diagnostics["sync_run_registry"]["audit_events"] == 1
    sync_run_registry = load_connector_sync_run_registry(connector_registry._sync_run_registry_path)
    assert sync_run_registry["audit"][0]["action"] == "connector_sync.blocked"
    assert sync_run_registry["audit"][0]["details"]["reason_code"] == "expired"
    events = connector_registry.list_operation_events(kind="sync_blocked")
    assert events[0]["run_id"] == result["id"]
    assert events[0]["reason_code"] == "expired"
    assert events[0]["status"] == "open"


def test_credential_health_reason_taxonomy():
    connector_id = get_replay_connector_id()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-pending", "VENDOR_TOKEN": "pending-token"},
        profile_id="pending-profile",
    )
    pending = connector_registry.credential_health(connector_id, "pending-profile")
    assert pending["blocking"] is True
    assert pending["reason"] == "credential_profile_pending_test"
    assert pending["reason_code"] == "pending_test"
    assert pending["severity"] == "medium"

    missing = connector_registry.credential_health(connector_id, "missing-profile")
    assert missing["blocking"] is True
    assert missing["reason_code"] == "missing"

    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-active", "VENDOR_TOKEN": "active-token"},
        profile_id="active-profile",
    )
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-secondary", "VENDOR_TOKEN": "secondary-token"},
        profile_id="secondary-profile",
        make_active=False,
        expires_at="2999-01-01T00:00:00+00:00",
    )
    connector_registry.record_credential_test_result(connector_id, "secondary-profile", success=True, message="ok")
    not_active = connector_registry.credential_health(connector_id, "secondary-profile")
    assert not_active["blocking"] is False
    assert not_active["reason_code"] == "not_active"
    assert not_active["profile_active"] is False


def test_existing_credential_profile_allows_metadata_only_update():
    connector_id = get_mock_connector_id()

    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-a"},
        profile_id="metadata-profile",
        profile_name="metadata",
    )
    updated = connector_registry.bind_credentials(
        connector_id,
        {},
        profile_id="metadata-profile",
        expires_at="2030-01-01T00:00:00+00:00",
    )

    assert updated["active_profile_id"] == "metadata_profile"
    assert updated["active_profile"]["expires_at"] == "2030-01-01T00:00:00+00:00"
    assert updated["active_profile"]["env"]["TENANT_ID"]["kind"] == "value"

    with pytest.raises(ValueError, match="requires at least one env value"):
        connector_registry.bind_credentials(connector_id, {}, profile_id="new-empty-profile")


def test_customer_data_source_actions_skip_update_credentials_for_system_only_fields():
    actions = _customer_data_source_actions(
        "asiainfo-tda-v7-0",
        {"profile_id": "device_tda_device_1"},
        {
            "state": "failed",
            "fields": [{"key": "FLOCKS_CONNECTOR_DEVICE_ID", "kind": "value", "configured": True}],
        },
        [],
    )

    assert [action["kind"] for action in actions] == ["test_connection"]

    editable_actions = _customer_data_source_actions(
        get_mock_connector_id(),
        {"profile_id": "default"},
        {
            "state": "failed",
            "fields": [{"key": "API_KEY", "kind": "secret", "configured": True}],
        },
        [],
    )

    assert [action["kind"] for action in editable_actions] == ["test_connection", "update_credentials"]


def test_customer_credential_summary_preserves_vendor_failure_message():
    summary = _customer_credential_summary(
        {
            "profile_id": "device_tda",
            "reason_code": "failed",
            "blocking": True,
            "message": "TDA Secret 未配置，请在 Device Integration 中更新凭据。",
            "profile": {
                "name": "测试TDA",
                "env": {"FLOCKS_CONNECTOR_DEVICE_ID": {"kind": "value", "configured": True}},
            },
        },
        {
            "active_profile_id": "device_tda",
            "active_profile": {
                "name": "测试TDA",
                "env": {"FLOCKS_CONNECTOR_DEVICE_ID": {"kind": "value", "configured": True}},
            },
        },
        checked_at=datetime.now(UTC),
        expiry_warning_days=14,
    )

    assert summary["state"] == "failed"
    assert summary["message"] == "TDA Secret 未配置，请在 Device Integration 中更新凭据。"


def test_customer_sync_status_marks_recovered_blocked_run_pending_sync():
    status = _customer_sync_status(
        {
            "status": "blocked",
            "source": "credential_health_gate",
            "finished_at": "2026-06-05T13:56:30+00:00",
        },
        [{"enabled": True, "status": "enabled"}],
        [],
        {
            "blocking": False,
            "profile": {
                "last_test_status": "success",
                "last_test_at": "2026-06-08T02:21:14+00:00",
            },
        },
    )

    assert status == "pending_sync"


def test_customer_sync_status_marks_schedule_failure_partial():
    schedules = [
        {
            "id": "connector:asset.search",
            "capability": "asset.search",
            "enabled": True,
            "status": "enabled",
            "last_status": "error",
            "last_error": "Cannot connect to host 192.168.31.200:8891",
            "last_run_at": "2026-06-08T14:48:56+00:00",
            "last_successful_run_at": None,
        },
        {
            "id": "connector:vulnerability.search",
            "capability": "vulnerability.search",
            "enabled": True,
            "status": "enabled",
            "last_status": "success",
            "last_error": None,
            "last_run_at": "2026-06-08T14:48:52+00:00",
            "last_successful_run_at": "2026-06-08T14:48:52+00:00",
        },
    ]
    latest_success_run = {
        "status": "success",
        "finished_at": "2026-06-08T14:48:52+00:00",
        "counts": {"vulnerabilities": 0},
    }

    status = _customer_sync_status(latest_success_run, schedules, [], {"blocking": False})
    summary = _customer_sync_summary(latest_success_run, schedules, status, {"blocking": False})

    assert status == "partial"
    assert summary["last_sync_at"] == "2026-06-08T14:48:56+00:00"
    assert summary["last_successful_sync_at"] == "2026-06-08T14:48:52+00:00"
    assert "asset.search" in summary["failure_reason"]
    assert "Cannot connect" in summary["failure_reason"]


def test_customer_sync_status_marks_all_schedule_failures_failed():
    schedules = [
        {"enabled": True, "status": "enabled", "last_status": "error", "last_run_at": "2026-06-08T14:49:27+00:00"},
        {"enabled": True, "status": "enabled", "last_status": "failed", "last_run_at": "2026-06-08T14:49:58+00:00"},
    ]

    status = _customer_sync_status({"status": "success"}, schedules, [], {"blocking": False})

    assert status == "failed"


def test_updating_schedule_interval_reschedules_next_run():
    connector_id = get_replay_connector_id()
    initial = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=3600,
    )
    updated = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=900,
    )

    initial_next = datetime.fromisoformat(initial["next_run_at"])
    updated_next = datetime.fromisoformat(updated["next_run_at"])

    assert updated["interval_seconds"] == 900
    assert updated_next < initial_next


@pytest.mark.asyncio
async def test_failed_credential_profile_pauses_sync_schedule():
    connector_id = get_replay_connector_id()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-failed", "VENDOR_TOKEN": "failed-token"},
        profile_id="failed-profile",
    )
    connector_registry.record_credential_test_result(
        connector_id,
        "failed-profile",
        success=False,
        message="Token rejected by vendor",
    )
    schedule = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=60,
        credential_profile_id="failed-profile",
    )

    result = await connector_registry.run_sync_schedule(schedule["id"], mode="full")

    assert result["status"] == "blocked"
    assert result["run"]["status"] == "blocked"
    assert result["run"]["run_policy"]["reason"] == "credential_profile_failed"
    assert result["run"]["credential_health"]["reason_code"] == "failed"
    assert result["schedule"]["enabled"] is False
    assert result["schedule"]["runtime_status"] == "policy_paused"
    assert result["schedule"]["policy_state"] == "paused"
    assert result["schedule"]["policy_reason_code"] == "failed"
    assert result["schedule"]["policy_message"] == "Token rejected by vendor"
    assert result["schedule"]["next_run_at"] is None
    assert any(action["kind"] == "test_profile" for action in result["schedule"]["policy_actions"])

    enabled = connector_registry.enable_sync_schedule(schedule["id"])

    assert enabled["enabled"] is True
    assert enabled["runtime_status"] == "enabled"
    assert enabled["policy_state"] is None
    assert enabled["policy_reason"] is None
    assert enabled["policy_message"] is None
    assert enabled["policy_actions"] == []
    assert enabled["policy_paused_at"] is None
    assert "run_policy" not in enabled
    assert enabled["next_run_at"] is not None
    schedule_registry = load_connector_sync_schedule_registry(connector_registry._sync_schedule_registry_path)
    actions = [event["action"] for event in schedule_registry["audit"]]
    assert "policy_pause" in actions
    assert "enable" in actions
    assert "policy_recovered" in actions
    pause_events = connector_registry.list_operation_events(kind="schedule_policy_paused")
    assert pause_events[0]["schedule_id"] == schedule["id"]
    assert pause_events[0]["reason_code"] == "failed"


@pytest.mark.asyncio
async def test_repaired_credential_profile_recovers_policy_paused_schedule():
    connector_id = get_replay_connector_id()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-repair", "VENDOR_TOKEN": "expired-token"},
        profile_id="repair-profile",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    schedule = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=60,
        mode="full",
        credential_profile_id="repair-profile",
    )
    blocked = await connector_registry.run_sync_schedule(schedule["id"], mode="full")

    assert blocked["status"] == "blocked"
    assert blocked["schedule"]["runtime_status"] == "policy_paused"

    await connector_registry.rotate_credentials(
        connector_id,
        "repair-profile",
        {"TENANT_ID": "tenant-repair", "VENDOR_TOKEN": "rotated-token"},
        expires_at="2999-01-01T00:00:00+00:00",
    )
    health = connector_registry.credential_health(connector_id, "repair-profile")
    assert health["blocking"] is False
    assert health["status"] == "ok"
    assert health["profile"]["last_failure_reason"] is None

    enabled = connector_registry.enable_sync_schedule(schedule["id"])
    assert enabled["runtime_status"] == "enabled"
    assert enabled["policy_state"] is None

    recovered = await connector_registry.run_sync_schedule(schedule["id"], mode="full")

    assert recovered["status"] == "partial"
    assert recovered["run"]["status"] == "partial"
    assert recovered["run"]["source"] != "credential_health_gate"
    assert recovered["run"].get("run_policy") is None
    assert recovered["run"]["credential_profile_id"] == "repair_profile"
    assert recovered["run"]["counts"]["assets"] == 1

    final_schedule = connector_registry.get_sync_schedule(schedule["id"])
    assert final_schedule["enabled"] is True
    assert final_schedule["runtime_status"] == "enabled"
    assert final_schedule["policy_state"] is None
    assert final_schedule["last_successful_run_at"] is not None
    assert final_schedule["last_error"] is None


@pytest.mark.asyncio
async def test_healthy_credential_can_auto_recover_policy_paused_schedule():
    connector_id = get_replay_connector_id()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-auto-repair", "VENDOR_TOKEN": "expired-token"},
        profile_id="auto-repair-profile",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    schedule = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=60,
        mode="full",
        credential_profile_id="auto-repair-profile",
    )
    blocked = await connector_registry.run_sync_schedule(schedule["id"], mode="full")
    assert blocked["schedule"]["runtime_status"] == "policy_paused"

    preview = connector_registry.recover_policy_paused_schedules(connector_id, "auto-repair-profile", mode="enable")
    assert preview["healthy"] is False
    assert preview["mode"] == "preview"
    assert preview["requires_confirmation"] is True
    assert preview["blocked_reason_code"] == "expired"

    binding = await connector_registry.rotate_credentials(
        connector_id,
        "auto-repair-profile",
        {"TENANT_ID": "tenant-auto-repair", "VENDOR_TOKEN": "rotated-token"},
        expires_at="2999-01-01T00:00:00+00:00",
        recover_policy_paused_schedules="enable",
    )

    assert binding["policy_recovery"]["healthy"] is True
    assert binding["policy_recovery"]["mode"] == "enable"
    assert binding["policy_recovery"]["recovered"] == 1
    recovered_schedule = connector_registry.get_sync_schedule(schedule["id"])
    assert recovered_schedule["enabled"] is True
    assert recovered_schedule["runtime_status"] == "enabled"
    assert recovered_schedule["policy_state"] is None

    schedule_registry = load_connector_sync_schedule_registry(connector_registry._sync_schedule_registry_path)
    schedule_actions = [event["action"] for event in schedule_registry["audit"]]
    assert "policy_pause" in schedule_actions
    assert "policy_recovered" in schedule_actions

    credential_registry = load_connector_credential_binding_registry(connector_registry._credential_binding_path)
    credential_actions = [event["action"] for event in credential_registry["audit"]]
    assert "connector_credential.rotate" in credential_actions
    assert "connector_credential.test" in credential_actions


def test_credential_expiry_monitor_emits_operational_events():
    connector_id = get_replay_connector_id()
    expires_at = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-expiring", "VENDOR_TOKEN": "expiring-token"},
        profile_id="expiring-profile",
        expires_at=expires_at,
    )

    result = connector_registry.monitor_credential_expiry(days=14, notify=True)

    assert result["matched"] == 1
    assert result["expiring_soon"] == 1
    assert result["expired"] == 0
    assert result["profiles"][0]["profile_id"] == "expiring_profile"
    assert result["events"][0]["kind"] == "credential_expiring_soon"
    assert result["events"][0]["reason_code"] == "expires_soon"

    repeated = connector_registry.monitor_credential_expiry(days=14, notify=True)
    assert repeated["events"][0]["seen_count"] == 2
    registry = load_connector_operations_registry(connector_registry._operations_registry_path)
    assert len(registry["events"]) == 1


@pytest.mark.asyncio
async def test_bulk_remediation_can_notify_test_and_enable_schedules():
    connector_id = get_replay_connector_id()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-bulk-expired", "VENDOR_TOKEN": "expired-token"},
        profile_id="bulk-expired-profile",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-bulk-failed", "VENDOR_TOKEN": "failed-token"},
        profile_id="bulk-failed-profile",
        make_active=False,
    )
    connector_registry.record_credential_test_result(
        connector_id,
        "bulk-failed-profile",
        success=False,
        message="Token rejected by vendor",
    )

    items = [
        {"connector_id": connector_id, "profile_id": "bulk-expired-profile"},
        {"connector_id": connector_id, "profile_id": "bulk-failed-profile"},
    ]
    notified = await connector_registry.bulk_remediate_credentials(items, action="notify")

    assert notified["requested"] == 2
    assert notified["succeeded"] == 2
    assert notified["failed"] == 0
    assert all(item["event"]["kind"] == "credential_remediation_requested" for item in notified["results"])

    tested = await connector_registry.bulk_remediate_credentials(items, action="test")
    assert tested["succeeded"] == 2
    assert all(item["result"]["success"] is True for item in tested["results"])

    schedule = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=60,
        mode="full",
        credential_profile_id="bulk-expired-profile",
    )
    blocked = await connector_registry.run_sync_schedule(schedule["id"], mode="full")
    assert blocked["schedule"]["runtime_status"] == "policy_paused"

    await connector_registry.rotate_credentials(
        connector_id,
        "bulk-expired-profile",
        {"TENANT_ID": "tenant-bulk-expired", "VENDOR_TOKEN": "rotated-token"},
        expires_at="2999-01-01T00:00:00+00:00",
        recover_policy_paused_schedules="preview",
    )
    enabled = await connector_registry.bulk_remediate_credentials(
        [{"connector_id": connector_id, "profile_id": "bulk-expired-profile"}],
        action="enable_schedules",
        recovery_mode="enable",
    )

    assert enabled["succeeded"] == 1
    assert enabled["results"][0]["result"]["recovered"] == 1
    assert connector_registry.get_sync_schedule(schedule["id"])["runtime_status"] == "enabled"

    registry = load_connector_operations_registry(connector_registry._operations_registry_path)
    assert len(registry["bulk_runs"]) == 3


@pytest.mark.asyncio
async def test_package_diagnostics_includes_operations_dashboard():
    connector_id = get_replay_connector_id()
    expires_at = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-dashboard-expiring", "VENDOR_TOKEN": "expiring-token"},
        profile_id="dashboard_expiring_profile",
        expires_at=expires_at,
    )
    connector_registry.monitor_credential_expiry(days=14, notify=False)

    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-dashboard-recover", "VENDOR_TOKEN": "failed-token"},
        profile_id="dashboard_recover_profile",
    )
    connector_registry.record_credential_test_result(
        connector_id,
        "dashboard_recover_profile",
        success=False,
        message="Token rejected by vendor",
    )
    recover_schedule = connector_registry.upsert_sync_schedule(
        connector_id,
        "asset.search",
        enabled=True,
        interval_seconds=60,
        credential_profile_id="dashboard_recover_profile",
    )
    blocked_recover = await connector_registry.run_sync_schedule(recover_schedule["id"], mode="full")
    assert blocked_recover["status"] == "blocked"

    connector_registry.bind_credentials(
        connector_id,
        {"TENANT_ID": "tenant-dashboard-paused", "VENDOR_TOKEN": "failed-token"},
        profile_id="dashboard_paused_profile",
    )
    connector_registry.record_credential_test_result(
        connector_id,
        "dashboard_paused_profile",
        success=False,
        message="Token rejected by vendor",
    )
    paused_schedule = connector_registry.upsert_sync_schedule(
        connector_id,
        "alert.search",
        enabled=True,
        interval_seconds=60,
        credential_profile_id="dashboard_paused_profile",
    )
    blocked_paused = await connector_registry.run_sync_schedule(paused_schedule["id"], mode="full")
    assert blocked_paused["schedule"]["runtime_status"] == "policy_paused"

    open_event = connector_registry.list_operation_events(status="open")[0]
    ack = connector_registry.acknowledge_operation_events([open_event["id"]])
    assert ack["acknowledged"] == 1

    await connector_registry.rotate_credentials(
        connector_id,
        "dashboard_recover_profile",
        {"TENANT_ID": "tenant-dashboard-recover", "VENDOR_TOKEN": "rotated-token"},
        expires_at="2999-01-01T00:00:00+00:00",
    )
    recovered = connector_registry.recover_policy_paused_schedules(
        connector_id,
        "dashboard_recover_profile",
        mode="enable",
    )
    assert recovered["recovered"] == 1

    bulk = await connector_registry.bulk_remediate_credentials(
        [
            {"connector_id": connector_id, "profile_id": "dashboard_recover_profile"},
            {"connector_id": connector_id, "profile_id": "dashboard_paused_profile"},
        ],
        action="notify",
    )
    assert bulk["requested"] == 2

    diagnostics = await connector_registry.package_diagnostics()
    dashboard = diagnostics["operations_dashboard"]
    current = dashboard["current"]
    assert dashboard["version"] == "connector.operations.dashboard.v1"
    assert current["expiry_risks"] >= 1
    assert current["blocked_runs"] >= 2
    assert current["policy_paused_schedules"] >= 1
    assert dashboard["mttr"]["samples"] >= 1
    assert dashboard["bulk"]["runs"] >= 1
    assert dashboard["bulk"]["requested"] >= 2
    assert dashboard["bulk"]["success_rate"] is not None
    assert diagnostics["summary"]["expiry_risks"] == current["expiry_risks"]
    assert diagnostics["summary"]["bulk_remediation_runs"] == dashboard["bulk"]["runs"]

    today = datetime.now(UTC).date().isoformat()
    today_bucket = next(bucket for bucket in dashboard["trend"] if bucket["date"] == today)
    assert today_bucket["expiry_risks"] >= 1
    assert today_bucket["blocked_runs"] >= 2
    assert today_bucket["policy_paused_schedules"] >= 2
    assert today_bucket["recoveries"] >= 1
    assert today_bucket["bulk_requested"] >= 2
