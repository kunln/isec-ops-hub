import json
from pathlib import Path
import shutil
import zipfile

import pytest
from flocks.tool import ToolResult

from flocks.security.connectors.models import ConnectorCapability
from flocks.security.connectors.package_loader import (
    BUILTIN_CONNECTOR_PACKAGE_ROOT,
    PACKAGE_CONTRACT_VERSION,
    build_connector_package_diagnostics,
    build_package_manifest,
    disable_connector_package,
    discover_connector_packages,
    enable_connector_package,
    install_connector_package,
    load_connector_package,
    preview_connector_package,
    rollback_connector_package,
    test_connector_package as run_connector_package_test,
    uninstall_connector_package,
    validate_connector_package,
)
from flocks.security.connectors.installed_registry import load_installed_connector_package_registry
from flocks.security.connectors.package_staging import (
    discard_staged_connector_package,
    install_staged_connector_package,
    stage_connector_package_artifact,
    validate_staged_connector_package,
)
from flocks.security.connectors.replay import FIXTURE_ROOT


def _zip_package_bytes(package_root: Path, *, top_level: str | None = None) -> bytes:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package_root.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(package_root)
            archive_name = Path(top_level or package_root.name) / rel
            archive.write(path, archive_name.as_posix())
    return buffer.getvalue()


def test_connector_package_loads_manifest_adapters_and_mappings():
    package = load_connector_package(FIXTURE_ROOT, source="builtin")

    assert package.connector_id == "fixture-replay-demo"
    assert package.manifest_data["version"] == PACKAGE_CONTRACT_VERSION
    assert set(package.adapter_paths) == {
        ConnectorCapability.ASSET_SEARCH,
        ConnectorCapability.VULNERABILITY_SEARCH,
        ConnectorCapability.ALERT_SEARCH,
        ConnectorCapability.HONEYPOT_EVENT_SEARCH,
    }
    assert package.adapter_contracts[ConnectorCapability.ASSET_SEARCH]["version"] == "connector.adapter.v1"
    assert package.mapping_contracts[ConnectorCapability.ASSET_SEARCH]["version"] == "connector.mapping.v1"


def test_connector_package_builds_runtime_manifest():
    package = load_connector_package(FIXTURE_ROOT, source="builtin")
    manifest = build_package_manifest(package)

    assert manifest.id == "fixture-replay-demo"
    assert manifest.deployment == "local_fixture"
    assert manifest.raw_response["source"] == "builtin"
    assert manifest.raw_response["package_root"].endswith("fixture-replay-demo")
    assert manifest.normalized_data["package_contract_version"] == "connector.package.v1"
    assert "compatibility" in manifest.normalized_data
    assert "release" in manifest.raw_response
    assert manifest.adapter_contracts["asset.search"]["file"].endswith("asset.search.adapter.json")
    assert manifest.mapping_contracts["asset.search"]["file"].endswith("asset.search.mapping.json")
    assert manifest.field_mapping["asset.search"]["ip"] == "ip"


@pytest.mark.asyncio
async def test_connector_package_preview_uses_adapter_and_mapping_contracts():
    package = load_connector_package(FIXTURE_ROOT, source="builtin")

    preview = await preview_connector_package(package, ConnectorCapability.ASSET_SEARCH)

    assert preview.success is True
    assert preview.raw_response["items"][0]["name"] == "Replay Internet Portal"
    assert preview.mapping_result["assets"][0]["name"] == "Replay Internet Portal"
    assert preview.mapping_result == preview.normalized_data
    assert preview.adapter_contract["transport"] == "fixture"
    assert preview.mapping_contract["version"] == "connector.mapping.v1"
    assert "items[1].ip" in preview.missing_required_fields
    assert isinstance(preview.unmapped_fields, list)


@pytest.mark.asyncio
async def test_connector_package_test_and_validate_report_contract_diagnostics():
    package = load_connector_package(FIXTURE_ROOT, source="builtin")

    test_result = await run_connector_package_test(package)
    validate_result = await validate_connector_package(package)

    assert test_result.success is True
    assert test_result.normalized_data["previews"]["asset.search"]["items"] == 2
    assert validate_result.success is True
    assert validate_result.adapter_contracts["asset.search"]["version"] == "connector.adapter.v1"
    assert validate_result.mapping_contracts["asset.search"]["version"] == "connector.mapping.v1"


def test_connector_package_discovery_returns_later_duplicate_package(tmp_path):
    custom_root = tmp_path / "connectors"
    shutil.copytree(FIXTURE_ROOT, custom_root / "fixture-replay-demo")

    packages = discover_connector_packages([BUILTIN_CONNECTOR_PACKAGE_ROOT, custom_root])
    packages_by_id = {package.connector_id: package for package in packages}

    assert set(packages_by_id) >= {
        "asiainfo-tda-v7-0",
        "fixture-replay-demo",
        "sangfor-xdr-v2-2",
        "tdp-v3-3-10",
        "skyeye-v4-0-14-sp2",
        "dbappsecurity-mingjian-vuln-scanner-v5-0",
    }
    assert packages_by_id["fixture-replay-demo"].root == (custom_root / "fixture-replay-demo").resolve()
    assert packages_by_id["fixture-replay-demo"].source == "package"


@pytest.mark.asyncio
async def test_real_vendor_connector_packages_validate_without_executing_tools():
    packages = {package.connector_id: package for package in discover_connector_packages([BUILTIN_CONNECTOR_PACKAGE_ROOT])}

    for package_id in (
        "asiainfo-tda-v7-0",
        "sangfor-xdr-v2-2",
        "tdp-v3-3-10",
        "skyeye-v4-0-14-sp2",
        "dbappsecurity-mingjian-vuln-scanner-v5-0",
    ):
        package = packages[package_id]
        validation = await validate_connector_package(package)
        runtime_manifest = build_package_manifest(package)

        assert validation.success is True
        assert any(summary["transport"] == "tool" for summary in validation.adapter_contracts.values())
        assert runtime_manifest.raw_response["release"]["notes"]
        assert runtime_manifest.normalized_data["compatibility"]["adapter_contract"] == "connector.adapter.v1"


def test_mingjian_connector_package_declares_read_only_sync_tools():
    package = load_connector_package(
        BUILTIN_CONNECTOR_PACKAGE_ROOT / "dbappsecurity-mingjian-vuln-scanner-v5-0",
        source="builtin",
    )

    assert package.manifest_data["product"] == "Mingjian Vuln Scanner"
    assert package.manifest_data["capabilities"] == ["asset.search", "vulnerability.search"]
    assert package.manifest_data["health_tool"]["name"] == "mingjian_vuln_scanner_health"
    assert package.adapter_contracts[ConnectorCapability.ASSET_SEARCH]["tool"]["name"] == "mingjian_vuln_scanner_assets"
    assert (
        package.adapter_contracts[ConnectorCapability.VULNERABILITY_SEARCH]["tool"]["name"]
        == "mingjian_vuln_scanner_results"
    )
    assert package.adapter_contracts[ConnectorCapability.ASSET_SEARCH]["tool"]["params"]["action"] == "sync"
    assert package.adapter_contracts[ConnectorCapability.ASSET_SEARCH]["tool"]["params"]["modules"] == [0, 1, 5, 8]
    assert (
        package.adapter_contracts[ConnectorCapability.VULNERABILITY_SEARCH]["tool"]["params"]["action"]
        == "sync"
    )
    assert package.adapter_contracts[ConnectorCapability.VULNERABILITY_SEARCH]["tool"]["params"]["modules"] == [0, 1, 5, 8, 11]
    assert package.adapter_contracts[ConnectorCapability.VULNERABILITY_SEARCH]["tool"]["params"]["task_limit"] == 10


def test_asiainfo_tda_connector_package_declares_2025_signed_read_only_sync_tools():
    package = load_connector_package(
        BUILTIN_CONNECTOR_PACKAGE_ROOT / "asiainfo-tda-v7-0",
        source="builtin",
    )

    assert package.manifest_data["product"] == "asiainfo_tda"
    assert package.manifest_data["product_version"] == "2025.6"
    assert package.manifest_data["capabilities"] == ["asset.search", "alert.search"]
    assert package.manifest_data["health_tool"]["name"] == "asiainfo_tda_health"
    assert package.adapter_contracts[ConnectorCapability.ASSET_SEARCH]["tool"]["name"] == "asiainfo_tda_assets"
    assert package.adapter_contracts[ConnectorCapability.ALERT_SEARCH]["tool"]["name"] == "asiainfo_tda_alerts"
    assert package.adapter_contracts[ConnectorCapability.ASSET_SEARCH]["tool"]["params"]["time_type"] == 2
    assert package.adapter_contracts[ConnectorCapability.ALERT_SEARCH]["tool"]["params"]["time_type"] == 2


@pytest.mark.asyncio
async def test_mingjian_connector_package_test_uses_health_tool(monkeypatch):
    package = load_connector_package(
        BUILTIN_CONNECTOR_PACKAGE_ROOT / "dbappsecurity-mingjian-vuln-scanner-v5-0",
        source="builtin",
    )
    captured: dict[str, object] = {}

    async def fake_execute(name, *, ctx=None, **params):
        captured["name"] = name
        captured["params"] = params
        return ToolResult(success=True, output={"count": 1})

    from flocks.tool import ToolRegistry

    monkeypatch.setattr(ToolRegistry, "init", classmethod(lambda cls: None))
    monkeypatch.setattr(ToolRegistry, "execute", fake_execute)

    result = await run_connector_package_test(package, env={"FLOCKS_CONNECTOR_DEVICE_ID": "dev-mingjian-1"})

    assert result.success is True
    assert result.normalized_data["health_tool"] == "mingjian_vuln_scanner_health"
    assert captured == {
        "name": "mingjian_vuln_scanner_health",
        "params": {"device_id": "dev-mingjian-1"},
    }


@pytest.mark.asyncio
async def test_connector_package_diagnostics_reports_roots_and_contracts(tmp_path):
    diagnostics = await build_connector_package_diagnostics(
        [BUILTIN_CONNECTOR_PACKAGE_ROOT],
        registry_path=tmp_path / "installed-packages.json",
    )

    assert diagnostics["version"] == PACKAGE_CONTRACT_VERSION
    assert diagnostics["summary"]["packages"] == 7
    assert diagnostics["summary"]["active_packages"] == 0
    assert diagnostics["summary"]["installed_packages"] == 0
    assert diagnostics["roots"][0]["exists"] is True
    package = next(item for item in diagnostics["packages"] if item["id"] == "fixture-replay-demo")
    assert package["id"] == "fixture-replay-demo"
    assert package["active"] is False
    assert package["discovery_active"] is True
    assert package["runtime_status"] == "not_installed"
    assert package["valid"] is True
    assert package["release"]["notes"]
    assert package["compatibility"]["connector_package_contract"] == "connector.package.v1"
    assert package["adapters"]["asset.search"]["status"] == "ok"
    assert package["mappings"]["asset.search"]["summary"]["version"] == "connector.mapping.v1"
    apt_package = next(item for item in diagnostics["packages"] if item["id"] == "dbappsecurity-mingyu-apt-v2-0-r77")
    assert apt_package["valid"] is True
    assert apt_package["adapters"]["alert.search"]["status"] == "ok"
    mingjian_package = next(
        item for item in diagnostics["packages"] if item["id"] == "dbappsecurity-mingjian-vuln-scanner-v5-0"
    )
    assert mingjian_package["valid"] is True
    assert mingjian_package["adapters"]["vulnerability.search"]["status"] == "ok"
    asiainfo_package = next(item for item in diagnostics["packages"] if item["id"] == "asiainfo-tda-v7-0")
    assert asiainfo_package["valid"] is True
    assert asiainfo_package["product"] == "asiainfo_tda"
    assert asiainfo_package["adapters"]["asset.search"]["status"] == "ok"
    assert asiainfo_package["adapters"]["alert.search"]["status"] == "ok"


@pytest.mark.asyncio
async def test_connector_package_diagnostics_keeps_invalid_package_out_of_discovery(tmp_path):
    custom_root = tmp_path / "connectors"
    package_root = custom_root / "fixture-replay-demo"
    shutil.copytree(FIXTURE_ROOT, package_root)
    manifest_path = package_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "connector.package.v0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert discover_connector_packages([custom_root]) == []

    diagnostics = await build_connector_package_diagnostics(
        [custom_root],
        registry_path=tmp_path / "installed-packages.json",
    )
    package = diagnostics["packages"][0]
    assert package["valid"] is False
    assert package["status"] == "error"
    assert "unsupported package version" in package["errors"][0]


@pytest.mark.asyncio
async def test_connector_package_install_enable_disable_and_uninstall(tmp_path):
    registry_path = tmp_path / "installed-packages.json"

    installed = await install_connector_package(FIXTURE_ROOT, registry_path=registry_path)
    assert installed["id"] == "fixture-replay-demo"
    assert installed["enabled"] is False
    assert installed["version"] == "2026.06"
    assert installed["hash"].startswith("sha256:")
    assert installed["root"] != str(FIXTURE_ROOT.resolve())
    assert installed["installed_root"] == installed["root"]
    assert installed["source_root"] == str(FIXTURE_ROOT.resolve())
    assert installed["manifest"]["id"] == "fixture-replay-demo"
    assert installed["last_validation_result"]["success"] is True
    assert installed["release"]["notes"]
    assert installed["compatibility"]["connector_package_contract"] == "connector.package.v1"

    disabled_diagnostics = await build_connector_package_diagnostics(
        [BUILTIN_CONNECTOR_PACKAGE_ROOT],
        registry_path=registry_path,
    )
    disabled_package = next(item for item in disabled_diagnostics["packages"] if item["id"] == "fixture-replay-demo")
    assert disabled_package["installed"] is True
    assert disabled_package["runtime_status"] == "disabled"
    assert disabled_package["active"] is False

    enabled = await enable_connector_package("fixture-replay-demo", registry_path=registry_path)
    assert enabled["enabled"] is True
    enabled_diagnostics = await build_connector_package_diagnostics(
        [BUILTIN_CONNECTOR_PACKAGE_ROOT],
        registry_path=registry_path,
    )
    enabled_package = next(item for item in enabled_diagnostics["packages"] if item["id"] == "fixture-replay-demo")
    assert enabled_package["runtime_status"] == "enabled"
    assert enabled_package["active"] is True

    disabled = disable_connector_package("fixture-replay-demo", registry_path=registry_path)
    assert disabled["enabled"] is False

    uninstalled = uninstall_connector_package("fixture-replay-demo", registry_path=registry_path)
    assert uninstalled["uninstalled_at"]
    registry = load_installed_connector_package_registry(registry_path)
    assert registry["packages"] == {}
    assert registry["history"]["fixture-replay-demo"]
    assert [event["action"] for event in registry["audit"]] == [
        "connector_package.install",
        "connector_package.enable",
        "connector_package.disable",
        "connector_package.uninstall",
    ]


@pytest.mark.asyncio
async def test_connector_package_managed_copy_survives_source_removal(tmp_path):
    registry_path = tmp_path / "installed-packages.json"
    source_root = tmp_path / "source" / "fixture-replay-demo"
    shutil.copytree(FIXTURE_ROOT, source_root)

    installed = await install_connector_package(source_root, registry_path=registry_path)
    shutil.rmtree(source_root)

    enabled = await enable_connector_package("fixture-replay-demo", registry_path=registry_path)
    assert enabled["enabled"] is True
    assert enabled["root"] == installed["root"]

    package = load_connector_package(Path(enabled["root"]), source="managed")
    preview = await preview_connector_package(package, ConnectorCapability.ASSET_SEARCH)
    assert preview.success is True
    assert preview.normalized_data["assets"][0]["name"] == "Replay Internet Portal"

    diagnostics = await build_connector_package_diagnostics([tmp_path / "source"], registry_path=registry_path)
    diagnostic_package = diagnostics["packages"][0]
    assert diagnostic_package["active"] is True
    assert diagnostic_package["runtime_status"] == "enabled"
    assert diagnostic_package["status"] == "warning"


@pytest.mark.asyncio
async def test_connector_package_rollback_restores_previous_managed_version(tmp_path):
    registry_path = tmp_path / "installed-packages.json"
    v2_root = tmp_path / "source-v2" / "fixture-replay-demo"
    shutil.copytree(FIXTURE_ROOT, v2_root)
    manifest_path = v2_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["product_version"] = "2026.07"
    manifest["description"] = "Updated fixture replay connector."
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    v1 = await install_connector_package(FIXTURE_ROOT, registry_path=registry_path, enabled=True)
    v2 = await install_connector_package(v2_root, registry_path=registry_path, enabled=True)
    assert v1["version"] == "2026.06"
    assert v2["version"] == "2026.07"
    assert v1["root"] != v2["root"]
    assert v2["rollback_available"] is True

    rolled_back = await rollback_connector_package("fixture-replay-demo", registry_path=registry_path)
    assert rolled_back["version"] == "2026.06"
    assert rolled_back["enabled"] is True
    assert rolled_back["root"] == v1["root"]

    registry = load_installed_connector_package_registry(registry_path)
    assert registry["packages"]["fixture-replay-demo"]["version"] == "2026.06"
    assert any(event["action"] == "connector_package.rollback" for event in registry["audit"])


@pytest.mark.asyncio
async def test_connector_package_staging_upload_validate_install_and_discard(tmp_path):
    staging_registry_path = tmp_path / "staging-packages.json"
    installed_registry_path = tmp_path / "installed-packages.json"
    artifact = _zip_package_bytes(FIXTURE_ROOT)

    staged = await stage_connector_package_artifact(
        filename="fixture-replay-demo.zip",
        content=artifact,
        staging_registry_path=staging_registry_path,
    )
    assert staged["status"] == "validated"
    assert staged["package_id"] == "fixture-replay-demo"
    assert staged["artifact_hash"].startswith("sha256:")
    assert staged["package_hash"].startswith("sha256:")
    assert staged["validation_result"]["success"] is True
    assert staged["release"]["notes"]
    assert staged["compatibility"]["connector_package_contract"] == "connector.package.v1"

    revalidated = await validate_staged_connector_package(staged["id"], staging_registry_path=staging_registry_path)
    assert revalidated["status"] == "validated"

    installed = await install_staged_connector_package(
        staged["id"],
        enabled=True,
        installed_registry_path=installed_registry_path,
        staging_registry_path=staging_registry_path,
    )
    assert installed["id"] == "fixture-replay-demo"
    assert installed["enabled"] is True
    assert installed["source"] == "upload"
    assert installed["source_metadata"]["staging_id"] == staged["id"]
    assert installed["artifact_hash"] == staged["artifact_hash"]
    assert installed["validated_at"] == revalidated["validated_at"]
    assert installed["root"] != staged["package_root"]

    discarded = discard_staged_connector_package(staged["id"], staging_registry_path=staging_registry_path)
    assert discarded["discarded_at"]
    assert not Path(staged["staging_root"]).exists()


@pytest.mark.asyncio
async def test_connector_package_staging_invalid_manifest_is_retained(tmp_path):
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("readme.txt", "not a connector package")

    staged = await stage_connector_package_artifact(
        filename="invalid.zip",
        content=buffer.getvalue(),
        staging_registry_path=tmp_path / "staging-packages.json",
    )
    assert staged["status"] == "invalid"
    assert staged["validation_result"]["success"] is False
    assert "manifest.json" in staged["errors"][0]


@pytest.mark.asyncio
async def test_connector_package_staging_rejects_path_traversal(tmp_path):
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../manifest.json", "{}")

    with pytest.raises(ValueError, match="unsafe"):
        await stage_connector_package_artifact(
            filename="evil.zip",
            content=buffer.getvalue(),
            staging_registry_path=tmp_path / "staging-packages.json",
        )
