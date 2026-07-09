"""Tests for Integration Instance skeleton exports and dry-run request building."""

from __future__ import annotations

import pytest

from flocks.security.integrations import (
    IntegrationInstance,
    IntegrationInstanceCreate,
    IntegrationInstanceStore,
    IntegrationInstanceUpdate,
    build_capability_run_request_from_instance,
    default_integration_instance_store,
)


def test_integration_instance_store_create_update_and_build_request() -> None:
    store = IntegrationInstanceStore()
    instance = store.create_instance(
        IntegrationInstanceCreate(
            instance_id="tda-prod",
            package_id="asiainfo.tda",
            name="TDA Prod",
            config={"base_url": "https://example.invalid", "api_key": "secret-value"},
            credential_ref="secret:tda-prod",
            allowed_capabilities=["alert.search"],
        )
    )

    assert isinstance(instance, IntegrationInstance)
    assert store.require_instance("tda-prod") == instance
    summary = instance.safe_summary()
    assert summary["config"]["api_key"] == "[REDACTED]"

    updated = store.update_instance("tda-prod", IntegrationInstanceUpdate(name="TDA Updated"))
    assert updated.name == "TDA Updated"
    request = build_capability_run_request_from_instance(updated, "alert.search", params={"limit": 10})
    assert request.package_id == "asiainfo.tda"
    assert request.capability == "alert.search"
    assert request.params["instance_id"] == "tda-prod"
    assert request.params["limit"] == 10
    assert request.dry_run is True


def test_integration_instance_rejects_unknown_package_and_disallowed_capability() -> None:
    store = IntegrationInstanceStore()
    with pytest.raises(ValueError, match="Unknown integration package"):
        store.create_instance(IntegrationInstanceCreate(package_id="missing", name="Missing"))

    instance = store.create_instance(
        IntegrationInstanceCreate(
            instance_id="mingyu-prod",
            package_id="dbappsecurity.mingyu_apt",
            name="Mingyu Prod",
            allowed_capabilities=["risk.search"],
        )
    )
    with pytest.raises(ValueError, match="not enabled"):
        build_capability_run_request_from_instance(instance, "alert.search")


def test_default_integration_instance_store_is_available() -> None:
    assert isinstance(default_integration_instance_store, IntegrationInstanceStore)
