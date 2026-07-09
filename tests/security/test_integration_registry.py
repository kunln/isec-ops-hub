"""Tests for the Integration Package Registry skeleton."""

from __future__ import annotations

import pytest

from flocks.security.integrations import (
    IntegrationRegistry,
    create_default_integration_registry,
    get_builtin_integration_packages,
)


def test_default_registry_loads_tda_and_mingyu_apt_packages() -> None:
    registry = create_default_integration_registry()

    package_ids = {package.manifest.package_id for package in registry.list_packages()}

    assert package_ids == {"asiainfo.tda", "dbappsecurity.mingyu_apt"}
    assert registry.get_package("asiainfo.tda") is not None
    assert registry.get_package("dbappsecurity.mingyu_apt") is not None


def test_list_packages_returns_two_builtin_packages() -> None:
    registry = create_default_integration_registry()

    assert len(registry.list_packages()) == 2


def test_tda_capabilities_include_alert_event_and_asset_search() -> None:
    registry = create_default_integration_registry()
    tda = registry.require_package("asiainfo.tda")

    assert {"alert.search", "event.search", "asset.search"}.issubset(tda.capabilities)


def test_mingyu_apt_capabilities_include_alert_risk_and_important_event_search() -> None:
    registry = create_default_integration_registry()
    mingyu_apt = registry.require_package("dbappsecurity.mingyu_apt")

    assert {"alert.search", "risk.search", "important_event.search"}.issubset(
        mingyu_apt.capabilities
    )


def test_find_packages_by_alert_search_capability_returns_tda_and_mingyu_apt() -> None:
    registry = create_default_integration_registry()

    package_ids = {
        package.manifest.package_id for package in registry.find_packages_by_capability("alert.search")
    }

    assert package_ids == {"asiainfo.tda", "dbappsecurity.mingyu_apt"}


def test_builtin_packages_validate_without_errors() -> None:
    registry = IntegrationRegistry()

    for package in get_builtin_integration_packages():
        assert registry.validate_package(package) == []


def test_duplicate_package_id_registration_is_rejected() -> None:
    package = get_builtin_integration_packages()[0]
    registry = IntegrationRegistry()

    registry.register_package(package)

    with pytest.raises(ValueError, match="duplicate package_id"):
        registry.register_package(package)


def test_sensitive_fields_are_field_names_not_secret_values() -> None:
    registry = create_default_integration_registry()
    forbidden_fragments = ("secret=", "token=", "password=", "apikey=", "api_key=")

    for package in registry.list_packages():
        assert package.manifest.sensitive_fields
        for field_name in package.manifest.sensitive_fields:
            assert " " not in field_name
            assert not any(fragment in field_name.lower() for fragment in forbidden_fragments)


def test_raw_response_and_raw_log_policies_are_safety_defaults() -> None:
    registry = create_default_integration_registry()

    for package in registry.list_packages():
        assert package.manifest.raw_response_policy == "transient_only"
        assert package.manifest.raw_log_storage == "forbidden"


def test_registry_skeleton_has_no_runtime_connector_or_security_side_effects(monkeypatch) -> None:
    """Building the registry must not call v1 connectors or create security objects."""

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Integration registry skeleton must not call runtime connector code")

    monkeypatch.setattr("flocks.security.connectors.tda.TDAConnector", fail_if_called, raising=False)
    monkeypatch.setattr(
        "flocks.security.connectors.mingyu_apt.MingyuAPTConnector",
        fail_if_called,
        raising=False,
    )

    registry = create_default_integration_registry()

    assert len(registry.list_packages()) == 2
    assert registry.list_capabilities("asiainfo.tda")
    assert registry.list_capabilities("dbappsecurity.mingyu_apt")
