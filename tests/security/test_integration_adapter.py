import json
import socket

import pytest
from pydantic import ValidationError

from flocks.security.integrations import (
    AdapterItemRef,
    FakeIntegrationAdapter,
    IntegrationAdapter,
    IntegrationAdapterRequest,
    IntegrationAdapterResult,
    IntegrationCapabilityRunRequest,
    SyncEnginePlanRequest,
    build_adapter_item_refs,
    dispatch_evidence_events,
    preview_evidence_events,
    register_manifest_dict,
    sanitize_adapter_mapping,
)


def _dump(value) -> str:
    return json.dumps(value.model_dump() if hasattr(value, "model_dump") else value, ensure_ascii=False).lower()


def test_adapter_request_defaults_to_dry_run():
    request = IntegrationAdapterRequest(package_id="pkg", capability="alert.search")

    assert request.dry_run is True


def test_adapter_request_rejects_credential_value_fields():
    with pytest.raises((ValidationError, ValueError)):
        IntegrationAdapterRequest(package_id="pkg", capability="alert.search", api_key="secret-value")


def test_secret_like_params_key_is_redacted():
    request = IntegrationAdapterRequest(package_id="pkg", capability="alert.search", params={"api_key": "secret-value"})

    assert request.params["api_key"] == "[REDACTED]"
    assert "secret-value" not in _dump(request)


def test_secret_like_params_value_is_redacted():
    request = IntegrationAdapterRequest(package_id="pkg", capability="alert.search", params={"query": "token=secret-value"})

    assert request.params["query"] == "[REDACTED]"
    assert "token=secret-value" not in _dump(request)


def test_raw_like_keys_are_removed_from_adapter_result_items():
    result = IntegrationAdapterResult(
        status="success",
        package_id="pkg",
        capability="alert.search",
        items=[{"id": "1", "raw_response": {"full": True}, "body": "raw", "title": "safe"}],
    )

    assert result.items == [{"id": "1", "title": "safe"}]
    assert "raw_response" not in _dump(result)
    assert "body" not in _dump(result)


def test_raw_like_keys_are_removed_from_summary_metadata_and_cursor():
    result = IntegrationAdapterResult(
        status="success",
        package_id="pkg",
        capability="alert.search",
        cursor={"next": "abc", "response_body": "raw"},
        summary={"count": 1, "packet": "raw"},
        metadata={"source": "fake", "pcap": "raw"},
    )

    assert result.cursor == {"next": "abc"}
    assert result.summary == {"count": 1}
    assert result.metadata == {"source": "fake"}


def test_secret_like_keys_and_values_are_not_exported_in_result_json():
    result = IntegrationAdapterResult(
        status="success",
        package_id="pkg",
        capability="alert.search",
        items=[{"id": "1", "authorization": "Bearer abc123", "note": "password=abc123"}],
        summary={"token": "abc123"},
        metadata={"message": "BEGIN PRIVATE KEY abc"},
        cursor={"next": "api_key=abc123"},
        warnings=["Bearer abc123"],
    )
    dumped = _dump(result)

    assert "bearer abc123" not in dumped
    assert "password=abc123" not in dumped
    assert "begin private key" not in dumped
    assert "api_key=abc123" not in dumped
    assert result.items[0]["authorization"] == "[REDACTED]"


def test_build_adapter_item_refs_only_generates_lightweight_references():
    refs = build_adapter_item_refs([
        {"id": "a1", "type": "alert", "source": "fake", "title": "Safe", "raw_payload": {"x": 1}, "token": "abc"}
    ])

    assert refs == [AdapterItemRef(item_id="a1", item_type="alert", source="fake", summary={"title": "Safe"})]
    assert "raw_payload" not in _dump(refs[0])
    assert "abc" not in _dump(refs[0])


@pytest.mark.asyncio
async def test_fake_adapter_success_returns_safe_result():
    adapter = FakeIntegrationAdapter(
        "pkg",
        {"alert.search"},
        fake_items=[{"id": "a1", "type": "alert", "raw": "full", "title": "Safe"}],
        summary={"count": 1, "secret": "hidden"},
    )

    result = await adapter.run_capability(IntegrationAdapterRequest(package_id="pkg", capability="alert.search"))

    assert result.status == "success"
    assert result.dry_run is True
    assert result.item_count == 1
    assert result.items == [{"id": "a1", "type": "alert", "title": "Safe"}]
    assert result.summary["secret"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_fake_adapter_unsupported_capability_returns_unsupported():
    adapter = FakeIntegrationAdapter("pkg", {"alert.search"})

    result = await adapter.run_capability(IntegrationAdapterRequest(package_id="pkg", capability="asset.search"))

    assert result.status == "unsupported_capability"
    assert result.dry_run is True


@pytest.mark.asyncio
async def test_dry_run_false_input_still_returns_dry_run_true():
    adapter = FakeIntegrationAdapter("pkg", {"alert.search"})

    result = await adapter.run_capability(IntegrationAdapterRequest(package_id="pkg", capability="alert.search", dry_run=False))

    assert result.dry_run is True


@pytest.mark.asyncio
async def test_fake_adapter_does_not_call_connector_http_credentials_mapping_or_dispatch(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("forbidden boundary crossed")

    monkeypatch.setattr(socket.socket, "connect", fail)
    import flocks.security.integrations.credential_store as credential_store
    import flocks.security.integrations.evidence_dispatcher as evidence_dispatcher
    import flocks.security.integrations.mapping as mapping
    import flocks.security.models as security_models

    monkeypatch.setattr(credential_store, "resolve_credential_profile_ref", fail)
    monkeypatch.setattr(evidence_dispatcher, "dispatch_evidence_events", fail)
    monkeypatch.setattr(mapping, "apply_mapping", fail)
    for name in ("Alert", "EvidenceItem", "AnalysisCase", "Incident"):
        if hasattr(security_models, name):
            monkeypatch.setattr(security_models, name, fail)

    adapter = FakeIntegrationAdapter("pkg", {"alert.search"}, fake_items=[{"id": "a1"}])
    result = await adapter.run_capability(
        IntegrationAdapterRequest(package_id="pkg", capability="alert.search", credential_ref="cred-ref")
    )

    assert result.status == "success"
    assert result.items == [{"id": "a1"}]


def test_sanitize_adapter_mapping_removes_raw_and_redacts_secret_values():
    assert sanitize_adapter_mapping({"request": "raw", "nested": {"token": "abc", "note": "Bearer abc"}}) == {
        "nested": {"token": "[REDACTED]", "note": "[REDACTED]"}
    }


def test_integration_exports_preserve_existing_runtime_sync_dispatch_mapping_manifest_symbols():
    assert issubclass(FakeIntegrationAdapter, IntegrationAdapter)
    assert IntegrationAdapterRequest
    assert IntegrationAdapterResult
    assert SyncEnginePlanRequest
    assert IntegrationCapabilityRunRequest
    assert dispatch_evidence_events
    assert preview_evidence_events
    assert register_manifest_dict
