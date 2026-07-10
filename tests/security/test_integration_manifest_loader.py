"""Tests for declarative Integration Package manifest loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flocks.security.integrations import create_default_integration_registry
from flocks.security.integrations.manifest_loader import (
    load_manifest_dict,
    load_manifest_file,
    load_package_from_manifest_dict,
    load_package_from_manifest_file,
    validate_manifest_dict,
)
from flocks.security.integrations.registry import (
    IntegrationRegistry,
    register_manifest_dict,
    register_manifest_file,
)

FIXTURE = Path("tests/fixtures/integrations/asiainfo_tda_manifest.json")


def _manifest_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "package_id": "example.test_device",
        "name": "Test Device",
        "vendor": "Example",
        "product": "Test Device",
        "version": "1.0.0",
        "category": "security_device",
        "capabilities": [
            {
                "capability": "alert.search",
                "display_name": "Search alerts",
                "method": "POST",
                "path": "/alerts/search",
                "mapping": {"builtin": "TDA_ALERT_MAPPING"},
            }
        ],
    }
    data.update(overrides)
    return data


def test_load_manifest_dict_success() -> None:
    manifest = load_manifest_dict(_manifest_data())

    assert manifest.package_id == "example.test_device"
    assert manifest.capabilities == ["alert.search"]


def test_load_manifest_file_json_success() -> None:
    package = load_package_from_manifest_file(FIXTURE)

    assert package.manifest.package_id == "example.asiainfo_tda_manifest"
    assert package.capabilities["alert.search"].method == "POST"


def test_load_manifest_file_yaml_success_if_yaml_available(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    yaml_path = tmp_path / "manifest.yaml"
    yaml_path.write_text(
        "\n".join(
            [
                "package_id: example.yaml_device",
                "name: YAML Device",
                "vendor: Example",
                "product: YAML",
                'version: "1.0.0"',
                "category: security_device",
                "capabilities:",
                "  - capability: alert.search",
                "    display_name: Search alerts",
                "    method: GET",
                "    path: /alerts",
            ]
        ),
        encoding="utf-8",
    )

    manifest = load_manifest_file(yaml_path)

    assert manifest.package_id == "example.yaml_device"


def test_missing_required_fields_returns_validation_error() -> None:
    errors = validate_manifest_dict({"capabilities": []})

    assert "package_id is required" in errors
    assert "name is required" in errors


def test_empty_capabilities_returns_error() -> None:
    errors = validate_manifest_dict(_manifest_data(capabilities=[]))

    assert "capabilities must be a non-empty list" in errors


def test_capability_missing_method_and_path_returns_error() -> None:
    errors = validate_manifest_dict(
        _manifest_data(capabilities=[{"capability": "alert.search", "display_name": "Search alerts"}])
    )

    assert "capabilities[0].method is required" in errors
    assert "capabilities[0].path is required" in errors


def test_raw_log_storage_store_raw_returns_error() -> None:
    errors = validate_manifest_dict(_manifest_data(raw_log_storage="store_raw"))

    assert "raw_log_storage must not be store_raw" in errors


def test_raw_response_policy_persist_full_response_returns_error() -> None:
    errors = validate_manifest_dict(_manifest_data(raw_response_policy="persist_full_response"))

    assert "raw_response_policy must not be persist_full_response" in errors


def test_default_raw_response_policy_transient_only() -> None:
    manifest = load_manifest_dict(_manifest_data())

    assert manifest.raw_response_policy == "transient_only"


def test_default_raw_log_storage_forbidden() -> None:
    manifest = load_manifest_dict(_manifest_data())

    assert manifest.raw_log_storage == "forbidden"


def test_register_manifest_dict_to_registry_success() -> None:
    registry = IntegrationRegistry()
    package = register_manifest_dict(registry, _manifest_data())

    assert package.manifest.package_id == "example.test_device"


def test_registered_package_can_be_retrieved() -> None:
    registry = IntegrationRegistry()
    register_manifest_dict(registry, _manifest_data())

    assert registry.get_package("example.test_device") is not None


def test_register_manifest_file_to_registry_success() -> None:
    registry = IntegrationRegistry()
    package = register_manifest_file(registry, FIXTURE)

    assert package.manifest.package_id == "example.asiainfo_tda_manifest"
    assert registry.get_package("example.asiainfo_tda_manifest") is package


def test_mapping_field_is_preserved_as_metadata() -> None:
    package = load_package_from_manifest_dict(_manifest_data())

    assert package.capabilities["alert.search"].mapping == {"builtin": "TDA_ALERT_MAPPING"}


def test_loader_has_no_connector_http_or_security_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("manifest loader must not execute side-effect behavior")

    monkeypatch.setattr("flocks.security.connectors.tda.TDAConnector", fail_if_called, raising=False)
    monkeypatch.setattr("flocks.security.connectors.mingyu_apt.MingyuAPTConnector", fail_if_called, raising=False)
    monkeypatch.setattr("urllib.request.urlopen", fail_if_called)

    package = load_package_from_manifest_dict(_manifest_data())

    assert package.manifest.package_id == "example.test_device"


def test_builtin_registry_tda_and_mingyu_apt_are_unaffected() -> None:
    registry = create_default_integration_registry()

    assert registry.get_package("asiainfo.tda") is not None
    assert registry.get_package("dbappsecurity.mingyu_apt") is not None


def test_fixture_contains_no_secret_or_url() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    assert "base_url" not in fixture
    assert all("=" not in field for field in fixture["sensitive_fields"])
