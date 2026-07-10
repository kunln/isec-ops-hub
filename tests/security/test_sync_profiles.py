"""Tests for Integration Sync Profile skeleton exports and safety."""

from __future__ import annotations

import pytest

from flocks.security.integrations import (
    SyncProfile,
    SyncProfileCreate,
    SyncProfileStore,
    SyncProfileUpdate,
    default_sync_profile_store,
)
from flocks.security.integrations.registry import create_default_integration_registry
from flocks.security.integrations.sync_profile_store import validate_sync_profile_payload


def test_sync_profile_exports_are_available() -> None:
    assert SyncProfile
    assert SyncProfileCreate
    assert SyncProfileUpdate
    assert isinstance(default_sync_profile_store, SyncProfileStore)


def test_sync_profile_payload_validates_package_and_capability() -> None:
    payload = SyncProfileCreate(
        package_id="asiainfo.tda",
        capability="alert.search",
        display_name="TDA alert sync metadata",
    )

    assert validate_sync_profile_payload(payload, create_default_integration_registry()) == []


def test_sync_profile_rejects_secret_like_default_params() -> None:
    payload = SyncProfileCreate(
        package_id="asiainfo.tda",
        capability="alert.search",
        display_name="TDA alert sync metadata",
        default_params={"api_key": "api_key=secret"},
    )

    assert validate_sync_profile_payload(payload, create_default_integration_registry())


def test_sync_profile_store_does_not_execute_sync_or_connectors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Sync Profile metadata must not execute sync or connector behavior")

    monkeypatch.setattr("flocks.security.connectors.tda.TDAConnector", fail_if_called, raising=False)
    store = SyncProfileStore(create_default_integration_registry())

    errors = store.registry.validate_package(store.registry.require_package("asiainfo.tda"))

    assert errors == []
