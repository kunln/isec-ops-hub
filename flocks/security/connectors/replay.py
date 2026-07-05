"""Fixture replay connector for offline adapter and normalizer development."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from time import perf_counter
from typing import Any

from flocks.security.connectors.adapter import (
    ADAPTER_CONTRACT_VERSION,
    adapter_contract_summary,
    load_adapter_contract,
    preview_adapter_contract,
    resolve_mapping_path,
)
from flocks.security.connectors.models import (
    ConnectorCapability,
    ConnectorHealthCheckResult,
    ConnectorManifest,
    ConnectorPreviewResult,
    ConnectorTestResult,
    ConnectorValidateResult,
)
from flocks.security.connectors.mapping import (
    MAPPING_CONTRACT_VERSION,
    apply_mapping_contract,
    build_field_mapping,
    load_mapping_contract,
)


REPLAY_CONNECTOR_ID = "fixture-replay-demo"
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / REPLAY_CONNECTOR_ID
ADAPTER_ROOT = FIXTURE_ROOT / "adapters"
MAPPING_ROOT = FIXTURE_ROOT / "mappings"

CAPABILITY_FIXTURES = {
    ConnectorCapability.ASSET_SEARCH: "assets_search.json",
    ConnectorCapability.VULNERABILITY_SEARCH: "vulnerabilities_search.json",
    ConnectorCapability.ALERT_SEARCH: "alerts_search.json",
    ConnectorCapability.HONEYPOT_EVENT_SEARCH: "honeypot_events_search.json",
}

CAPABILITY_ADAPTERS = {
    ConnectorCapability.ASSET_SEARCH: "asset.search.adapter.json",
    ConnectorCapability.VULNERABILITY_SEARCH: "vulnerability.search.adapter.json",
    ConnectorCapability.ALERT_SEARCH: "alert.search.adapter.json",
    ConnectorCapability.HONEYPOT_EVENT_SEARCH: "honeypot.event.search.adapter.json",
}

CAPABILITY_MAPPINGS = {
    ConnectorCapability.ASSET_SEARCH: "asset.search.mapping.json",
    ConnectorCapability.VULNERABILITY_SEARCH: "vulnerability.search.mapping.json",
    ConnectorCapability.ALERT_SEARCH: "alert.search.mapping.json",
    ConnectorCapability.HONEYPOT_EVENT_SEARCH: "honeypot.event.search.mapping.json",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def build_replay_manifest() -> ConnectorManifest:
    adapter_contracts = {
        capability.value: adapter_contract_summary(
            load_adapter_contract_for_capability(capability),
            file=str(adapter_contract_path_for_capability(capability)),
        )
        for capability in CAPABILITY_ADAPTERS
    }
    mapping_contracts = {
        capability.value: _mapping_summary(load_mapping_contract_for_capability(capability))
        for capability in CAPABILITY_ADAPTERS
    }
    field_mapping = {
        capability.value: build_field_mapping(load_mapping_contract_for_capability(capability))
        for capability in CAPABILITY_ADAPTERS
    }
    return ConnectorManifest(
        id=REPLAY_CONNECTOR_ID,
        name="Fixture Replay Demo Connector",
        vendor="Flocks",
        product="Fixture Replay",
        product_version="2026.06",
        deployment="local_fixture",
        auth_methods=["none"],
        capabilities=list(CAPABILITY_ADAPTERS.keys()),
        field_mapping=field_mapping,
        severity_mapping={
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        },
        status_mapping={
            "new": "new",
            "open": "open",
            "confirmed": "confirmed",
            "closed": "closed",
            "false_positive": "false_positive",
        },
        adapter_contracts=adapter_contracts,
        mapping_contracts=mapping_contracts,
        pagination={"type": "fixture", "page_size": "all"},
        rate_limit={"mode": "offline", "requests_per_minute": None},
        permissions=["fixture:read"],
        risk_level="low",
        description=(
            "Offline fixture replay connector for developing and testing adapters, "
            "normalizers and capability downgrade behavior without vendor resources."
        ),
        raw_response={
            "fixture_root": str(FIXTURE_ROOT),
            "fixtures": list(CAPABILITY_FIXTURES.values()),
            "adapter_root": str(ADAPTER_ROOT),
            "adapters": list(CAPABILITY_ADAPTERS.values()),
            "mapping_root": str(MAPPING_ROOT),
            "mappings": list(CAPABILITY_MAPPINGS.values()),
        },
        normalized_data={
            "available_capabilities": [item.value for item in CAPABILITY_ADAPTERS],
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
            "mapping_contract_version": MAPPING_CONTRACT_VERSION,
        },
        health_check=ConnectorHealthCheckResult(
            status="ok",
            message="Fixture replay connector is available locally.",
            checked_at=utc_now(),
            latency_ms=0,
            details={"fixture_root": str(FIXTURE_ROOT)},
        ),
    )


def load_fixture_response(capability: ConnectorCapability) -> dict[str, Any]:
    filename = CAPABILITY_FIXTURES.get(capability)
    if filename is None:
        raise ValueError(f"No fixture is available for capability: {capability}")
    path = FIXTURE_ROOT / filename
    if not path.is_file():
        raise ValueError(f"Fixture file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def adapter_contract_path_for_capability(capability: ConnectorCapability) -> Path:
    filename = CAPABILITY_ADAPTERS.get(capability)
    if filename is None:
        raise ValueError(f"No adapter contract is available for capability: {capability}")
    return ADAPTER_ROOT / filename


def load_adapter_contract_for_capability(capability: ConnectorCapability) -> dict[str, Any]:
    path = adapter_contract_path_for_capability(capability)
    if not path.is_file():
        raise ValueError(f"Adapter contract file not found: {path}")
    return load_adapter_contract(path)


def load_mapping_contract_for_capability(capability: ConnectorCapability) -> dict[str, Any]:
    adapter_path = adapter_contract_path_for_capability(capability)
    adapter_contract = load_adapter_contract(adapter_path)
    path = resolve_mapping_path(adapter_contract, adapter_path.parent)
    return load_mapping_contract(path)


def _mapping_summary(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": contract["version"],
        "capability": contract["capability"],
        "target": contract["target"],
        "source": contract.get("source", {}),
        "required_fields": [
            field["target"]
            for field in contract.get("fields", [])
            if isinstance(field, dict) and field.get("required") is True
        ],
        "field_count": len(contract.get("fields", [])),
    }


def _items(raw_response: dict[str, Any]) -> list[dict[str, Any]]:
    items = raw_response.get("items", [])
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def normalize_fixture_response(
    capability: ConnectorCapability,
    raw_response: dict[str, Any],
) -> dict[str, Any]:
    contract = load_mapping_contract_for_capability(capability)
    return apply_mapping_contract(raw_response, contract, REPLAY_CONNECTOR_ID).mapping_result


async def preview_replay_connector(capability: ConnectorCapability) -> ConnectorPreviewResult:
    adapter_path = adapter_contract_path_for_capability(capability)
    adapter_contract = load_adapter_contract(adapter_path)
    return await preview_adapter_contract(
        REPLAY_CONNECTOR_ID,
        adapter_contract,
        base_dir=adapter_path.parent,
        contract_file=adapter_path,
    )


async def test_replay_connection() -> ConnectorTestResult:
    started = perf_counter()
    fixtures = {}
    warnings = []
    for capability in CAPABILITY_ADAPTERS:
        preview = await preview_replay_connector(capability)
        fixtures[capability.value] = {
            "source": preview.source,
            "transport": preview.adapter_contract.get("transport"),
            "items": len(_items(preview.raw_response)),
            "warnings": len(preview.warnings),
        }
        warnings.extend(preview.warnings)

    latency_ms = max(0, round((perf_counter() - started) * 1000))
    health = ConnectorHealthCheckResult(
        status="ok",
        message="Fixture replay test succeeded. No external network call was made.",
        checked_at=utc_now(),
        latency_ms=latency_ms,
        details={"fixture_root": str(FIXTURE_ROOT), "fixtures": fixtures},
    )
    manifest = build_replay_manifest()
    return ConnectorTestResult(
        connector_id=REPLAY_CONNECTOR_ID,
        success=True,
        status="ok",
        message=health.message,
        health_check=health,
        capabilities=manifest.capabilities,
        raw_response={
            "fixture_root": str(FIXTURE_ROOT),
            "fixtures": list(CAPABILITY_FIXTURES.values()),
            "adapter_root": str(ADAPTER_ROOT),
            "adapters": list(CAPABILITY_ADAPTERS.values()),
            "mapping_root": str(MAPPING_ROOT),
            "mappings": list(CAPABILITY_MAPPINGS.values()),
        },
        normalized_data={"fixtures": fixtures},
        warnings=warnings,
    )


async def validate_replay_connector() -> ConnectorValidateResult:
    warnings: list[str] = []
    errors: list[str] = []
    adapter_contracts: dict[str, Any] = {}
    mapping_contracts: dict[str, Any] = {}
    for capability in CAPABILITY_ADAPTERS:
        try:
            preview = await preview_replay_connector(capability)
            adapter_contracts[capability.value] = preview.adapter_contract
            mapping_contracts[capability.value] = preview.mapping_contract
            warnings.extend(preview.warnings)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{capability.value}: {exc}")
    success = not errors
    return ConnectorValidateResult(
        connector_id=REPLAY_CONNECTOR_ID,
        success=success,
        status="ok" if success else "error",
        message="Fixture replay adapter contracts validated." if success else "Fixture replay adapter validation failed.",
        capabilities=list(CAPABILITY_ADAPTERS.keys()),
        adapter_contracts=adapter_contracts,
        mapping_contracts=mapping_contracts,
        warnings=warnings,
        errors=errors,
    )
