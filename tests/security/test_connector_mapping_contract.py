from pathlib import Path

from flocks.security.connectors.mapping import apply_mapping_contract, load_mapping_contract
from flocks.security.connectors.models import ConnectorCapability
from flocks.security.connectors.replay import FIXTURE_ROOT, REPLAY_CONNECTOR_ID, load_fixture_response


def test_asset_mapping_contract_maps_fixture_and_reports_required_gaps():
    contract = load_mapping_contract(FIXTURE_ROOT / "mappings" / "asset.search.mapping.json")
    raw_response = load_fixture_response(ConnectorCapability.ASSET_SEARCH)

    result = apply_mapping_contract(raw_response, contract, REPLAY_CONNECTOR_ID)

    assert result.mapping_result["assets"][0]["name"] == "Replay Internet Portal"
    assert result.mapping_result["assets"][0]["asset_type"] == "web_app"
    assert result.mapping_result["assets"][0]["raw_data"]["connector_id"] == REPLAY_CONNECTOR_ID
    assert "items[1].ip" in result.missing_required_fields
    assert "items[0].controls.edr" not in result.unmapped_fields


def test_mapping_contract_normalizes_enums_defaults_and_transform_warnings():
    contract = {
        "version": "connector.mapping.v1",
        "capability": "alert.search",
        "target": "alerts",
        "source": {"items_path": "items"},
        "fields": [
            {"raw": "id", "target": "id", "required": True},
            {"raw": "severity", "target": "severity", "enum": {"high": "high"}, "enum_default": "medium"},
            {"raw": "iocs", "target": "ioc", "default": [], "transform": "list"},
            {"raw": "labels", "target": "labels", "default": {}, "transform": "dict"},
        ],
    }
    raw_response = {"items": [{"id": "a1", "severity": "vendor-critical", "iocs": "1.1.1.1", "labels": "bad"}]}

    result = apply_mapping_contract(raw_response, contract, "test-connector")
    alert = result.mapping_result["alerts"][0]

    assert alert["severity"] == "medium"
    assert alert["ioc"] == ["1.1.1.1"]
    assert result.transform_warnings
    assert "items[0].labels" not in alert


def test_mapping_contract_file_paths_exist_for_replay_capabilities():
    mapping_root = Path(FIXTURE_ROOT / "mappings")

    assert (mapping_root / "asset.search.mapping.json").is_file()
    assert (mapping_root / "vulnerability.search.mapping.json").is_file()
    assert (mapping_root / "alert.search.mapping.json").is_file()
    assert (mapping_root / "honeypot.event.search.mapping.json").is_file()
