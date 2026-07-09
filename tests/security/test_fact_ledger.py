import copy
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.fact_ledger import summarize_fact_ledger
from flocks.security.models import AnalysisCase
from flocks.security.connectors.package_loader import BUILTIN_CONNECTOR_PACKAGE_ROOT
from flocks.security.connectors.registry import connector_registry
from flocks.security.connectors.replay import FIXTURE_ROOT
from flocks.storage.storage import Storage


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config
    from flocks.security import secrets as secrets_module

    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    Storage._db_path = None
    Storage._initialized = False
    import flocks.tool.device.models  # noqa: F401

    connector_registry.reset_for_tests(
        package_roots=[BUILTIN_CONNECTOR_PACKAGE_ROOT],
        installed_registry_path=tmp_path / "installed-packages.json",
    )
    await connector_registry.install_package(FIXTURE_ROOT, enabled=True)
    await Storage.init(tmp_path / "flocks.db")

    from fastapi import FastAPI, Request
    from flocks.auth.context import AuthUser
    from flocks.server.routes.security import router as security_router

    app = FastAPI()

    @app.middleware("http")
    async def inject_admin(request: Request, call_next):
        request.state.auth_user = AuthUser(
            id="admin-user",
            username="admin-user",
            role="admin",
            status="active",
            must_reset_password=False,
        )
        return await call_next(request)

    app.include_router(security_router, prefix="/api/security")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None
    secrets_module._secret_manager = None
    connector_registry.reset_for_tests()


def _case(**overrides):
    payload = {
        "id": "acase_test",
        "title": "Fact ledger test",
        "verdict": "insufficient_evidence",
        "facts": [
            {
                "id": "fact_supported",
                "fact_type": "alert_signal",
                "statement": "Alert fired for blocked request",
                "source_ref": "alert:test",
                "metadata": {"evidence_item_ids": ["evd_cited"]},
            },
            {
                "id": "fact_unsupported",
                "fact_type": "analysis_conclusion",
                "statement": "Actor intent is malicious",
                "source_ref": "analysis:rule",
            },
        ],
        "evidence_items": [
            {"id": "evd_cited", "title": "Normalized alert", "source_ref": "alert:test"},
            {
                "id": "evd_uncited",
                "title": "External reference",
                "source_ref": "external:test",
                "metadata": {"raw_payload": {"api_key": "SHOULD_NOT_APPEAR", "token": "NOPE"}},
            },
        ],
        "evidence_gaps": [
            {"id": "egap_open", "gap_type": "missing_endpoint", "description": "Endpoint data unavailable"},
            {"id": "egap_closed", "gap_type": "missing_waf", "description": "WAF query completed", "metadata": {"status": "resolved"}},
        ],
    }
    payload.update(overrides)
    return AnalysisCase.model_validate(payload)


def test_supported_unsupported_uncited_open_gaps_and_safety():
    summary = summarize_fact_ledger(_case())

    assert summary.coverage.supported_facts == 1
    assert summary.coverage.unsupported_facts == 1
    assert summary.unsupported_fact_ids == ["fact_unsupported"]
    assert summary.cited_evidence_ids == ["evd_cited"]
    assert summary.uncited_evidence_ids == ["evd_uncited"]
    assert summary.coverage.open_evidence_gaps == 1
    rendered = summary.model_dump_json()
    assert "raw_payload" not in rendered
    assert "SHOULD_NOT_APPEAR" not in rendered
    assert all(secret not in rendered.lower() for secret in ["api_key", "secret", "token", "password"])


def test_false_positive_without_contradiction_finding():
    summary = summarize_fact_ledger(_case(verdict="false_positive_rule_noise"))
    assert any(f.finding_type == "false_positive_without_contradiction" for f in summary.findings)


def test_false_positive_with_negative_observation_is_supported():
    case = _case(
        verdict="false_positive_rule_noise",
        facts=[
            {
                "id": "fact_negative",
                "fact_type": "negative_observation",
                "statement": "No matching endpoint process was observed in scoped telemetry.",
                "source_ref": "edr:test",
                "metadata": {"evidence_item_ids": ["evd_cited"]},
            }
        ],
    )
    summary = summarize_fact_ledger(case)
    assert not any(f.finding_type == "false_positive_without_contradiction" for f in summary.findings)


def test_high_risk_verdict_weak_support_and_statuses():
    weak = summarize_fact_ledger(_case(verdict="confirmed_incident", facts=[{"id": "fact_missing", "fact_type": "analysis", "statement": "Unreferenced high-risk conclusion", "source_ref": "analysis:test"}]))
    assert any(f.finding_type == "weak_verdict_support" for f in weak.findings)
    assert weak.coverage.discipline_status == "weak"

    strong = summarize_fact_ledger(_case(facts=[{
        "id": "fact_supported",
        "fact_type": "alert_signal",
        "statement": "Alert fired for blocked request",
        "source_ref": "alert:test",
        "metadata": {"evidence_item_ids": ["evd_cited"]},
    }]))
    assert strong.coverage.discipline_status == "strong"

    partial = summarize_fact_ledger(_case(facts=[
        {
            "id": "fact_supported",
            "fact_type": "alert_signal",
            "statement": "Alert fired for blocked request",
            "source_ref": "alert:test",
            "metadata": {"evidence_item_ids": ["evd_cited"]},
        },
        {"id": "fact_missing", "fact_type": "analysis", "statement": "Needs more proof", "source_ref": "analysis:test"},
    ]))
    assert partial.coverage.discipline_status == "partial"


def test_legacy_case_missing_reference_fields_is_compatible():
    legacy_payload = {
        "id": "legacy",
        "title": "Legacy case",
        "facts": [{"id": "fact_old", "fact_type": "analysis", "statement": "Old conclusion", "source_ref": "legacy"}],
        "evidence_items": [{"id": "evd_old", "title": "Old evidence", "source_ref": "legacy"}],
    }
    summary = summarize_fact_ledger(AnalysisCase.model_validate(legacy_payload))
    assert summary.unsupported_fact_ids == ["fact_old"]
    assert summary.uncited_evidence_ids == ["evd_old"]


@pytest.mark.asyncio
async def test_api_returns_summary_does_not_modify_case_and_404(client: AsyncClient):
    payload = _case().model_dump(mode="json")
    payload.pop("id")
    before_payload = copy.deepcopy(payload)
    created = await client.post("/api/security/analysis-cases", json=payload)
    assert created.status_code == 201, created.text
    case = created.json()

    summary_response = await client.get(f"/api/security/analysis-cases/{case['id']}/fact-ledger-summary")
    assert summary_response.status_code == 200, summary_response.text
    summary = summary_response.json()
    assert summary["case_id"] == case["id"]
    assert summary["coverage"]["supported_facts"] == 1
    assert summary["uncited_evidence_ids"]

    after = (await client.get(f"/api/security/analysis-cases/{case['id']}")).json()
    assert after == case
    assert payload == before_payload

    missing = await client.get("/api/security/analysis-cases/missing/fact-ledger-summary")
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_brief_includes_fact_evidence_discipline_section(client: AsyncClient):
    payload = _case().model_dump(mode="json")
    payload.pop("id")
    created = await client.post("/api/security/analysis-cases", json=payload)
    assert created.status_code == 201, created.text
    markdown = (await client.get(f"/api/security/analysis-cases/{created.json()['id']}/brief")).json()["markdown"]
    assert "## Fact / Evidence Discipline" in markdown
    assert "total facts" in markdown
    assert "discipline status" in markdown
