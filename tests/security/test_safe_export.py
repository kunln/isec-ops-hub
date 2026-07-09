from copy import deepcopy

import pytest
from pydantic import BaseModel

from flocks.security.analysis_report import generate_analysis_case_brief
from flocks.security.models import AnalysisCase, AnalysisFact, EvidenceItem, Incident
from flocks.security.report import generate_incident_report, safe_incident_report_data
from flocks.security.store import SecurityStore
from flocks.storage.storage import Storage
from flocks.security.safe_export import safe_export_dict, safe_export_model, safe_export_value


@pytest.fixture
async def initialized_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False


def test_sensitive_keys_are_redacted():
    exported = safe_export_dict({"api_key": "a", "secret": "b", "token": "c", "password": "d"})
    assert exported == {"api_key": "[REDACTED]", "secret": "[REDACTED]", "token": "[REDACTED]", "password": "[REDACTED]"}


def test_nested_dict_sensitive_fields_are_redacted():
    assert safe_export_dict({"outer": {"client_secret": "hidden"}})["outer"]["client_secret"] == "[REDACTED]"


def test_list_nested_sensitive_fields_are_redacted():
    assert safe_export_value([{"refresh_token": "hidden"}])[0]["refresh_token"] == "[REDACTED]"


def test_raw_payload_fields_do_not_output_original_values():
    exported = safe_export_dict({"raw_payload": "RAW", "http_req_body": "BODY", "pcap": b"PCAP", "packet": "PACKET"})
    dumped = str(exported)
    for forbidden in ("RAW", "BODY", "PCAP", "PACKET"):
        assert forbidden not in dumped
    for value in exported.values():
        assert value["redacted"] is True
        assert value["reason"] == "raw_payload"


def test_long_string_is_summarized():
    value = "x" * 20
    assert safe_export_value(value, max_string_length=5) == {"type": "str", "length": 20, "truncated": True}


def test_long_list_is_truncated():
    assert safe_export_value([1, 2, 3], max_list_items=2) == [1, 2, {"type": "list_truncated", "length": 3}]


def test_bytes_do_not_output_original_value():
    exported = safe_export_value(b"secret-bytes")
    assert exported == {"type": "bytes", "length": 12, "redacted": True}
    assert "secret-bytes" not in str(exported)


def test_max_depth_is_enforced():
    exported = safe_export_dict({"a": {"b": {"c": "deep"}}}, max_depth=1)
    assert exported["a"]["b"] == {"type": "dict", "truncated": True, "reason": "max_depth"}


def test_safe_export_model_supports_pydantic_model():
    class Demo(BaseModel):
        name: str
        api_key: str

    assert safe_export_model(Demo(name="ok", api_key="hidden")) == {"name": "ok", "api_key": "[REDACTED]"}


def test_original_object_is_not_modified():
    original = {"nested": {"token": "hidden"}, "items": [{"password": "pw"}]}
    before = deepcopy(original)
    safe_export_dict(original)
    assert original == before


def _case_with_sensitive_details() -> AnalysisCase:
    return AnalysisCase(
        title="case",
        facts=[AnalysisFact(fact_type="observation", statement="fact", source_ref="ev-1", metadata={"api_key": "hidden"})],
        evidence_items=[
            EvidenceItem(
                title="ev",
                source_ref="ev-1",
                key_fields={"raw_payload": "do-not-show", "token": "hidden"},
                metadata={"secret": "hidden"},
            )
        ],
    )


def test_analysis_case_brief_does_not_contain_raw_case_json():
    assert "Raw Case JSON" not in generate_analysis_case_brief(_case_with_sensitive_details())


def test_analysis_case_brief_does_not_contain_sensitive_or_raw_field_names():
    brief = generate_analysis_case_brief(_case_with_sensitive_details()).lower()
    for forbidden in ("raw_payload", "api_key", "secret", "token", "password", "do-not-show", "hidden"):
        assert forbidden not in brief


def test_incident_report_data_does_not_contain_sensitive_values_or_raw_payload_values():
    incident = Incident(
        title="incident",
        evidence=["safe evidence"],
        timeline=[{"timestamp": "now", "raw_payload": "do-not-show", "description": {"token": "hidden", "text": "safe"}}],
        raw_data={"raw_payload": "do-not-show", "api_key": "hidden"},
        normalized_data={"packet": "do-not-show", "summary": "ok"},
    )
    dumped = str(safe_incident_report_data(incident)).lower()
    for forbidden in ("do-not-show", "hidden"):
        assert forbidden not in dumped


def test_empty_and_plain_fields_are_preserved():
    assert safe_export_dict({"none": None, "count": 1, "ratio": 1.5, "enabled": True, "name": "ok"}) == {
        "none": None,
        "count": 1,
        "ratio": 1.5,
        "enabled": True,
        "name": "ok",
    }


@pytest.mark.asyncio
async def test_incident_report_does_not_contain_sensitive_or_raw_field_names(initialized_storage):
    store = SecurityStore()
    incident = await store.create_incident({
        "title": "incident",
        "evidence": ["safe evidence"],
        "timeline": [
            {"timestamp": "now", "raw_payload": "do-not-show", "description": {"token": "hidden", "text": "safe"}}
        ],
        "raw_data": {"raw_payload": "do-not-show", "api_key": "hidden"},
        "normalized_data": {"packet": "do-not-show", "summary": "ok"},
    })

    report = (await generate_incident_report(incident.id, store=store)).lower()

    for forbidden in ("raw_payload", "api_key", "secret", "token", "password", "do-not-show", "hidden"):
        assert forbidden not in report
