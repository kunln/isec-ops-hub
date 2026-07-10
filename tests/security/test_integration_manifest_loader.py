"""Tests for the declarative Integration Package manifest loader skeleton."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from flocks.security.integrations import (
    IntegrationRun,
    IntegrationRunCreate,
    IntegrationRunStore,
    IntegrationRunUpdate,
    SyncProfile,
    SyncProfileCreate,
    SyncProfileStore,
    SyncProfileUpdate,
    create_default_integration_registry,
    default_integration_run_store,
    default_sync_profile_store,
    register_manifest_dict,
    register_manifest_file,
)
from flocks.security.integrations.manifest_loader import (
    load_manifest_dict,
    load_manifest_file,
    load_package_from_manifest_dict,
    validate_manifest_dict,
)

FIXTURE_PATH = Path("tests/fixtures/integrations/asiainfo_tda_manifest.json")


def _manifest_data() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_load_manifest_dict_success() -> None:
    manifest = load_manifest_dict(_manifest_data())

    assert manifest.package_id == "asiainfo.tda.manifest_fixture"
    assert manifest.capabilities == ["alert.search"]


def test_load_manifest_file_json_success() -> None:
    manifest = load_manifest_file(FIXTURE_PATH)

    assert manifest.vendor == "AsiaInfo"
    assert manifest.raw_response_policy == "transient_only"


def test_load_manifest_file_yaml_success_or_graceful_skip(tmp_path: Path) -> None:
    yaml_path = tmp_path / "manifest.yaml"
    yaml_path.write_text(
        "package_id: yaml.fixture\n"
        "name: YAML Fixture\n"
        "vendor: TestVendor\n"
        "product: TestProduct\n"
        "version: v1\n"
        "category: security_monitoring\n"
        "capabilities:\n"
        "  - capability: alert.search\n"
        "    display_name: Search alerts\n"
        "    method: GET\n"
        "    path: /alerts\n",
        encoding="utf-8",
    )

    try:
        manifest = load_manifest_file(yaml_path)
    except ValueError as exc:
        if "optional 'yaml' module" in str(exc):
            pytest.skip("Optional yaml module is not installed")
        raise

    assert manifest.package_id == "yaml.fixture"
    assert manifest.raw_log_storage == "forbidden"


def test_yaml_without_module_returns_clear_value_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    yaml_path = tmp_path / "manifest.yaml"
    yaml_path.write_text("package_id: yaml.fixture\n", encoding="utf-8")
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "yaml":
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ValueError, match="optional 'yaml' module"):
        load_manifest_file(yaml_path)


def test_missing_required_fields_returns_validation_error() -> None:
    errors = validate_manifest_dict({"capabilities": []})

    assert "package_id is required" in errors
    assert "name is required" in errors


def test_empty_capabilities_returns_error() -> None:
    data = _manifest_data()
    data["capabilities"] = []

    assert "capabilities must be a non-empty list" in validate_manifest_dict(data)


def test_capability_missing_method_path_returns_error() -> None:
    data = _manifest_data()
    data["capabilities"] = [{"capability": "alert.search", "display_name": "Search alerts"}]

    errors = validate_manifest_dict(data)

    assert "capabilities[0].method is required" in errors
    assert "capabilities[0].path is required" in errors


def test_raw_log_storage_store_raw_returns_error() -> None:
    data = _manifest_data()
    data["raw_log_storage"] = "store_raw"

    assert any("raw_log_storage" in error for error in validate_manifest_dict(data))


def test_raw_response_policy_persist_full_response_returns_error() -> None:
    data = _manifest_data()
    data["raw_response_policy"] = "persist_full_response"

    assert any("raw_response_policy" in error for error in validate_manifest_dict(data))


def test_manifest_defaults_raw_response_and_raw_log_policies() -> None:
    data = _manifest_data()
    data.pop("raw_response_policy")
    data.pop("raw_log_storage")

    manifest = load_manifest_dict(data)

    assert manifest.raw_response_policy == "transient_only"
    assert manifest.raw_log_storage == "forbidden"


def test_register_manifest_dict_to_registry_success_and_get_package() -> None:
    registry = create_default_integration_registry()
    package = register_manifest_dict(registry, _manifest_data())

    assert registry.get_package(package.manifest.package_id) == package
    assert registry.require_package("asiainfo.tda.manifest_fixture") == package


def test_register_manifest_file_to_registry_success() -> None:
    registry = create_default_integration_registry()
    package = register_manifest_file(registry, FIXTURE_PATH)

    assert registry.get_package(package.manifest.package_id) == package


def test_mapping_field_is_preserved_as_metadata_not_executed() -> None:
    package = load_package_from_manifest_dict(_manifest_data())

    assert package.capabilities["alert.search"].mapping == {"event_type": "alert", "source_id": "$.id"}


def test_loader_does_not_call_connector_http_sync_or_create_security_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("manifest loader must not execute runtime side effects")

    monkeypatch.setattr("flocks.security.connectors.tda.TDAConnector", fail_if_called, raising=False)
    monkeypatch.setattr("http.client.HTTPConnection.request", fail_if_called, raising=False)
    monkeypatch.setattr("http.client.HTTPSConnection.request", fail_if_called, raising=False)
    monkeypatch.setattr("flocks.security.models.Alert", fail_if_called, raising=False)
    monkeypatch.setattr("flocks.security.models.EvidenceItem", fail_if_called, raising=False)
    monkeypatch.setattr("flocks.security.models.AnalysisCase", fail_if_called, raising=False)
    monkeypatch.setattr("flocks.security.models.Incident", fail_if_called, raising=False)

    package = load_package_from_manifest_dict(_manifest_data())

    assert package.manifest.package_id == "asiainfo.tda.manifest_fixture"


def test_builtin_registry_existing_packages_are_unaffected() -> None:
    registry = create_default_integration_registry()

    assert registry.get_package("asiainfo.tda") is not None
    assert registry.get_package("dbappsecurity.mingyu_apt") is not None


def test_init_exports_manifest_loader_sync_profile_and_integration_run_symbols() -> None:
    assert callable(register_manifest_dict)
    assert callable(register_manifest_file)
    assert SyncProfile is not None
    assert SyncProfileCreate is not None
    assert SyncProfileStore is not None
    assert SyncProfileUpdate is not None
    assert default_sync_profile_store is not None
    assert IntegrationRun is not None
    assert IntegrationRunCreate is not None
    assert IntegrationRunStore is not None
    assert IntegrationRunUpdate is not None
    assert default_integration_run_store is not None
