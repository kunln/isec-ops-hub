from __future__ import annotations

import socket
import sys

import pytest

from flocks.security.integrations.adapter import FakeIntegrationAdapter, IntegrationAdapter
from flocks.security.integrations.adapter_registry import (
    AdapterRegistry,
    AdapterRegistryEntry,
    create_default_adapter_registry,
    default_adapter_registry,
)


def _factory() -> IntegrationAdapter:
    return FakeIntegrationAdapter("unit.package", {"alert.search"}, adapter_id="unit.adapter")


def test_register_adapter_factory_success() -> None:
    registry = AdapterRegistry()

    entry = registry.register_adapter_factory("unit.package", "alert.search", _factory, metadata={"owner": "security"})

    assert isinstance(entry, AdapterRegistryEntry)
    assert entry.package_id == "unit.package"
    assert entry.capability == "alert.search"
    assert entry.adapter_id == "unit.package.alert.search.adapter"
    assert entry.factory_name == "_factory"
    assert entry.metadata == {"owner": "security"}


def test_has_adapter_success() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    assert registry.has_adapter("unit.package", "alert.search") is True
    assert registry.has_adapter("unit.package", "asset.search") is False


def test_get_adapter_returns_integration_adapter() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    adapter = registry.get_adapter("unit.package", "alert.search")

    assert isinstance(adapter, IntegrationAdapter)
    assert adapter is not None
    assert adapter.package_id == "unit.package"


def test_require_adapter_returns_integration_adapter() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    adapter = registry.require_adapter("unit.package", "alert.search")

    assert isinstance(adapter, IntegrationAdapter)


def test_require_adapter_unknown_package_capability_raises_value_error() -> None:
    registry = AdapterRegistry()

    with pytest.raises(ValueError, match="No adapter registered"):
        registry.require_adapter("missing.package", "alert.search")


def test_list_adapters_returns_metadata_only_entries() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory, metadata={"team": "secops"})

    entries = registry.list_adapters()

    assert entries == [
        AdapterRegistryEntry(
            package_id="unit.package",
            capability="alert.search",
            adapter_id="unit.package.alert.search.adapter",
            factory_name="_factory",
            metadata={"team": "secops"},
        )
    ]
    assert "factory" not in entries[0].model_dump()
    assert "credential" not in entries[0].model_dump()
    assert "secret_ref" not in entries[0].model_dump()
    assert "raw" not in entries[0].model_dump()


def test_list_adapters_package_id_filter() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)
    registry.register_adapter_factory("other.package", "alert.search", lambda: FakeIntegrationAdapter("other.package"))

    entries = registry.list_adapters(package_id="unit.package")

    assert len(entries) == 1
    assert entries[0].package_id == "unit.package"


def test_metadata_secret_like_key_and_value_are_redacted() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory(
        "unit.package",
        "alert.search",
        _factory,
        metadata={"api_key": "abc", "nested": {"note": "token=abc"}},
    )

    metadata = registry.list_adapters()[0].metadata

    assert metadata["api_key"] == "[REDACTED]"
    assert metadata["nested"]["note"] == "[REDACTED]"


def test_metadata_raw_like_key_is_removed() -> None:
    registry = AdapterRegistry()
    registry.register_adapter_factory(
        "unit.package",
        "alert.search",
        _factory,
        metadata={"summary": "ok", "raw_response": {"payload": "not stored"}, "nested": {"body": "not stored"}},
    )

    metadata = registry.list_adapters()[0].metadata

    assert metadata == {"summary": "ok", "nested": {}}


def test_get_adapter_does_not_execute_run_capability() -> None:
    class ExplodingAdapter(FakeIntegrationAdapter):
        async def run_capability(self, request):  # type: ignore[no-untyped-def]
            raise AssertionError("run_capability must not execute")

    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", lambda: ExplodingAdapter("unit.package"))

    assert isinstance(registry.get_adapter("unit.package", "alert.search"), ExplodingAdapter)


def test_registry_does_not_call_connector_or_import_vendor_connectors() -> None:
    connector_modules_before = {name for name in sys.modules if name.startswith("flocks.security.connectors")}
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    registry.get_adapter("unit.package", "alert.search")

    connector_modules_after = {name for name in sys.modules if name.startswith("flocks.security.connectors")}
    assert connector_modules_after == connector_modules_before


def test_registry_does_not_do_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connect(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("HTTP/network must not be used")

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    assert registry.get_adapter("unit.package", "alert.search") is not None


def test_registry_does_not_read_credential_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    import flocks.security.integrations.credential_store as credential_store

    monkeypatch.setattr(
        credential_store,
        "resolve_credential_profile_ref",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("credential resolution must not run")),
    )
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    assert registry.get_adapter("unit.package", "alert.search") is not None


def test_registry_does_not_call_mapping_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    import flocks.security.integrations.mapping as mapping

    monkeypatch.setattr(mapping, "apply_mapping", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("mapping must not run")))
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    assert registry.get_adapter("unit.package", "alert.search") is not None


def test_registry_does_not_call_evidence_dispatcher(monkeypatch: pytest.MonkeyPatch) -> None:
    import flocks.security.integrations.evidence_dispatcher as evidence_dispatcher

    monkeypatch.setattr(
        evidence_dispatcher,
        "dispatch_evidence_events",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("evidence dispatch must not run")),
    )
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    assert registry.get_adapter("unit.package", "alert.search") is not None


@pytest.mark.parametrize("object_name", ["Alert", "Evidence", "AnalysisCase", "Incident"])
def test_registry_does_not_create_security_objects(monkeypatch: pytest.MonkeyPatch, object_name: str) -> None:
    import flocks.security.integrations.adapter_registry as adapter_registry

    monkeypatch.setattr(
        adapter_registry,
        object_name,
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError(f"{object_name} must not be created")),
        raising=False,
    )
    registry = AdapterRegistry()
    registry.register_adapter_factory("unit.package", "alert.search", _factory)

    assert registry.get_adapter("unit.package", "alert.search") is not None


def test_create_default_adapter_registry_include_fake_contains_fake_adapter() -> None:
    registry = create_default_adapter_registry(include_fake=True)

    assert registry.has_adapter("fake.integration", "alert.search") is True
    adapter = registry.require_adapter("fake.integration", "alert.search")
    assert isinstance(adapter, FakeIntegrationAdapter)
    assert adapter.package_id == "fake.integration"


def test_create_default_adapter_registry_include_fake_false_is_empty() -> None:
    registry = create_default_adapter_registry(include_fake=False)

    assert registry.list_adapters() == []


def test_init_exports_preserve_existing_adapter_sync_runtime_dispatcher_mapping_manifest_symbols() -> None:
    import flocks.security.integrations as integrations

    for symbol in [
        "AdapterFactory",
        "AdapterRegistryEntry",
        "AdapterRegistry",
        "default_adapter_registry",
        "create_default_adapter_registry",
        "IntegrationAdapter",
        "FakeIntegrationAdapter",
        "SyncEnginePlanRequest",
        "plan_sync_profile_run",
        "IntegrationCapabilityRuntime",
        "EvidenceDispatchRequest",
        "dispatch_evidence_events",
        "MappingRule",
        "apply_mapping",
        "IntegrationPackageManifest",
        "IntegrationRegistry",
        "register_manifest_dict",
    ]:
        assert hasattr(integrations, symbol)

    assert integrations.default_adapter_registry is default_adapter_registry
