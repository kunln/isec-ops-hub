"""Tests for Integration Run v2 skeleton exports and safe summaries."""

from __future__ import annotations

from flocks.security.integrations import (
    IntegrationRun,
    IntegrationRunCreate,
    IntegrationRunStore,
    IntegrationRunUpdate,
    build_integration_run_from_connector_sync_run,
    default_integration_run_store,
    finish_integration_run,
    integration_run_from_connector_run,
    record_integration_run,
)
from flocks.security.integrations.integration_run_store import validate_integration_run_payload
from flocks.security.models import ConnectorSyncRun


def test_integration_run_exports_are_available() -> None:
    assert IntegrationRun
    assert IntegrationRunCreate
    assert IntegrationRunUpdate
    assert isinstance(default_integration_run_store, IntegrationRunStore)
    assert record_integration_run
    assert finish_integration_run


def test_integration_run_payload_rejects_secret_like_summary() -> None:
    payload = IntegrationRunCreate(
        package_id="asiainfo.tda",
        capability="alert.search",
        request_summary={"api_key": "api_key=secret"},
    )

    assert validate_integration_run_payload(payload)


def test_build_integration_run_from_connector_sync_run_sanitizes_request_summary() -> None:
    connector_run = ConnectorSyncRun(
        id="connrun_1",
        connector_id="tda",
        connector_name="TDA",
        vendor="AsiaInfo",
        product="TDA",
        mode="manual",
        status="success",
        started_at="2026-01-01T00:00:00+00:00",
        request_summary={"base_url": "https://tda.example.local/api/path", "api_key": "secret"},
        result_summary={"items": 1},
        metadata={"package_id": "asiainfo.tda", "capability": "alert.search"},
    )

    run = build_integration_run_from_connector_sync_run(connector_run)

    assert run.package_id == "asiainfo.tda"
    assert run.capability == "alert.search"
    assert run.request_summary == {"base_url_host": "https://tda.example.local"}


def test_integration_run_from_connector_run_alias_is_preserved() -> None:
    assert integration_run_from_connector_run is build_integration_run_from_connector_sync_run
