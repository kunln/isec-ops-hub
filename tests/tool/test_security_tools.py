from pathlib import Path
import json

import pytest

from flocks.security.connectors.package_loader import BUILTIN_CONNECTOR_PACKAGE_ROOT
from flocks.security.connectors.registry import connector_registry
from flocks.security.connectors.replay import FIXTURE_ROOT
from flocks.security.sample_data import SAMPLE_IDS, load_sample_data
from flocks.storage.storage import Storage
from flocks.tool.registry import ToolContext, ToolRegistry


@pytest.fixture
async def initialized_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    connector_registry.reset_for_tests(
        package_roots=[BUILTIN_CONNECTOR_PACKAGE_ROOT],
        installed_registry_path=tmp_path / "installed-packages.json",
    )
    await connector_registry.install_package(FIXTURE_ROOT, enabled=True)
    await Storage.init(tmp_path / "flocks.db")
    ToolRegistry._initialized = False
    yield
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    ToolRegistry._initialized = False
    connector_registry.reset_for_tests()


def _json_output(result):
    if isinstance(result.output, str):
        return json.loads(result.output)
    return result.output


@pytest.mark.asyncio
async def test_security_tools_search_triage_and_report(initialized_storage):
    await load_sample_data()
    ctx = ToolContext(session_id="test", message_id="test", agent="security-test")

    search = await ToolRegistry.execute("security_asset_search", ctx=ctx, keyword="Portal")
    assert search.success is True
    assert _json_output(search)["count"] == 1

    connectors = await ToolRegistry.execute("security_connector_list", ctx=ctx)
    assert connectors.success is True
    connector_ids = [item["id"] for item in _json_output(connectors)["items"]]
    assert "fixture-replay-demo" in connector_ids
    assert "mock-security-demo" in connector_ids
    connector_id = "mock-security-demo"
    replay_connector_id = "fixture-replay-demo"

    package_diagnostics = await ToolRegistry.execute("security_connector_package_diagnostics", ctx=ctx)
    assert package_diagnostics.success is True
    assert _json_output(package_diagnostics)["summary"]["active_packages"] >= 1

    connector = await ToolRegistry.execute(
        "security_connector_get",
        ctx=ctx,
        connector_id=connector_id,
    )
    assert connector.success is True
    assert _json_output(connector)["raw_response"]["assets"]

    connector_capabilities = await ToolRegistry.execute(
        "security_connector_list_capabilities",
        ctx=ctx,
        connector_id=connector_id,
    )
    assert connector_capabilities.success is True
    assert "asset.search" in _json_output(connector_capabilities)["capabilities"]

    connector_test = await ToolRegistry.execute(
        "security_connector_test_connection",
        ctx=ctx,
        connector_id=connector_id,
    )
    assert connector_test.success is True
    assert _json_output(connector_test)["normalized_data"]["assets"]

    connector_validation = await ToolRegistry.execute(
        "security_connector_validate",
        ctx=ctx,
        connector_id=replay_connector_id,
    )
    assert connector_validation.success is True
    assert _json_output(connector_validation)["adapter_contracts"]["asset.search"]["version"] == "connector.adapter.v1"

    connector_preview = await ToolRegistry.execute(
        "security_connector_preview",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="asset.search",
    )
    assert connector_preview.success is True
    preview_payload = _json_output(connector_preview)
    assert preview_payload["normalized_data"]["assets"][0]["name"] == "Replay Internet Portal"
    assert "items[1].ip" in preview_payload["missing_fields"]
    assert preview_payload["adapter_contract"]["transport"] == "fixture"
    assert preview_payload["mapping_result"] == preview_payload["normalized_data"]
    assert "items[1].ip" in preview_payload["missing_required_fields"]

    connector_asset_sync = await ToolRegistry.execute(
        "security_connector_sync",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="asset.search",
        mode="full",
    )
    assert connector_asset_sync.success is True
    asset_sync_payload = _json_output(connector_asset_sync)
    assert asset_sync_payload["status"] == "partial"
    assert asset_sync_payload["dead_letter_count"] == 1

    connector_alert_sync = await ToolRegistry.execute(
        "security_connector_sync",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="alert.search",
        mode="full",
        reset_cursor=True,
    )
    assert connector_alert_sync.success is True
    alert_sync_payload = _json_output(connector_alert_sync)
    assert alert_sync_payload["status"] == "success"
    assert alert_sync_payload["cursor_after"] == "2026-06-01T08:20:00Z"

    connector_incremental_sync = await ToolRegistry.execute(
        "security_connector_sync",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="alert.search",
        mode="incremental",
    )
    assert connector_incremental_sync.success is True
    incremental_payload = _json_output(connector_incremental_sync)
    assert incremental_payload["counts"]["alerts"] == 0
    assert incremental_payload["skipped_counts"]["alerts"] == 2

    connector_sync_cursors = await ToolRegistry.execute(
        "security_connector_sync_cursors",
        ctx=ctx,
        connector_id=replay_connector_id,
    )
    assert connector_sync_cursors.success is True
    assert _json_output(connector_sync_cursors)["items"][0]["capability"] == "alert.search"

    connector_dead_letters = await ToolRegistry.execute(
        "security_connector_sync_dead_letters",
        ctx=ctx,
        connector_id=replay_connector_id,
    )
    assert connector_dead_letters.success is True
    assert _json_output(connector_dead_letters)["items"][0]["target"] == "assets"

    connector_cursor_reset = await ToolRegistry.execute(
        "security_connector_sync_cursor_reset",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="alert.search",
    )
    assert connector_cursor_reset.success is True
    assert _json_output(connector_cursor_reset)["reset"] == 1

    schedule_upsert = await ToolRegistry.execute(
        "security_connector_sync_schedule_upsert",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="alert.search",
        enabled=True,
        interval_seconds=60,
        mode="incremental",
        retry_max_attempts=2,
        retry_backoff_seconds=0,
        timeout_seconds=5,
    )
    assert schedule_upsert.success is True
    schedule_id = _json_output(schedule_upsert)["id"]
    assert schedule_id == f"{replay_connector_id}:alert.search"

    schedules = await ToolRegistry.execute(
        "security_connector_sync_schedules",
        ctx=ctx,
        connector_id=replay_connector_id,
    )
    assert schedules.success is True
    assert _json_output(schedules)["items"][0]["id"] == schedule_id

    schedule_run = await ToolRegistry.execute(
        "security_connector_sync_schedule_run",
        ctx=ctx,
        schedule_id=schedule_id,
        mode="full",
    )
    assert schedule_run.success is True
    schedule_run_payload = _json_output(schedule_run)
    assert schedule_run_payload["status"] == "success"
    assert schedule_run_payload["run"]["orchestration"]["schedule_id"] == schedule_id

    schedule_disable = await ToolRegistry.execute(
        "security_connector_sync_schedule_disable",
        ctx=ctx,
        schedule_id=schedule_id,
    )
    assert schedule_disable.success is True
    assert _json_output(schedule_disable)["enabled"] is False

    schedule_enable = await ToolRegistry.execute(
        "security_connector_sync_schedule_enable",
        ctx=ctx,
        schedule_id=schedule_id,
    )
    assert schedule_enable.success is True
    assert _json_output(schedule_enable)["enabled"] is True

    scheduler_tick = await ToolRegistry.execute("security_connector_sync_scheduler_tick", ctx=ctx)
    assert scheduler_tick.success is True
    assert "due" in _json_output(scheduler_tick)

    evidence_graph_rebuild = await ToolRegistry.execute("security_evidence_graph_rebuild", ctx=ctx)
    assert evidence_graph_rebuild.success is True
    graph_payload = _json_output(evidence_graph_rebuild)
    assert graph_payload["version"] == "connector.evidence.graph.v1"
    assert graph_payload["summary"]["nodes"] > 0
    assert graph_payload["summary"]["asset_entities"] >= 1

    evidence_graph_get = await ToolRegistry.execute("security_evidence_graph_get", ctx=ctx)
    assert evidence_graph_get.success is True
    assert _json_output(evidence_graph_get)["summary"]["nodes"] == graph_payload["summary"]["nodes"]

    entity_candidates = await ToolRegistry.execute("security_entity_resolution_candidates", ctx=ctx)
    assert entity_candidates.success is True
    assert "conflicts" in _json_output(entity_candidates)

    schedule_delete = await ToolRegistry.execute(
        "security_connector_sync_schedule_delete",
        ctx=ctx,
        schedule_id=schedule_id,
    )
    assert schedule_delete.success is True
    assert _json_output(schedule_delete)["deleted_at"]

    package_disable = await ToolRegistry.execute(
        "security_connector_package_disable",
        ctx=ctx,
        package_id=replay_connector_id,
    )
    assert package_disable.success is True

    disabled_preview = await ToolRegistry.execute(
        "security_connector_preview",
        ctx=ctx,
        connector_id=replay_connector_id,
        capability="asset.search",
    )
    assert disabled_preview.success is False
    assert "Connector not found" in disabled_preview.error

    package_enable = await ToolRegistry.execute(
        "security_connector_package_enable",
        ctx=ctx,
        package_id=replay_connector_id,
    )
    assert package_enable.success is True

    profile = await ToolRegistry.execute(
        "security_asset_risk_profile",
        ctx=ctx,
        asset_id=SAMPLE_IDS["asset"],
    )
    assert profile.success is True
    assert _json_output(profile)["risk_score"]["score"] >= 55

    priorities = await ToolRegistry.execute(
        "security_vulnerability_prioritize",
        ctx=ctx,
        asset_id=SAMPLE_IDS["asset"],
    )
    assert priorities.success is True
    assert _json_output(priorities)["items"][0]["risk_score"]["score"] >= 80

    triage = await ToolRegistry.execute(
        "security_alert_triage",
        ctx=ctx,
        alert_id=SAMPLE_IDS["alert"],
        create_incident=True,
    )
    assert triage.success is True
    triage_payload = _json_output(triage)
    assert triage_payload["incident_id"]

    report = await ToolRegistry.execute(
        "security_report_generate",
        ctx=ctx,
        incident_id=triage_payload["incident_id"],
        format="markdown",
    )
    assert report.success is True
    assert "安全事件研判报告" in _json_output(report)["content"]
