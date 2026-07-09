from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from flocks.security.analysis_report import generate_analysis_case_brief
from flocks.security.fact_ledger import summarize_fact_ledger
from flocks.security.models import AnalysisCase, AnalysisFact, EvidenceGap, EvidenceItem
from flocks.storage.storage import Storage


def _case(**kwargs):
    data = {"title": "case"}
    data.update(kwargs)
    return AnalysisCase(**data)


def _fact(fid="fact-1", *, fact_type="observation", supports=None, strength="medium", metadata=None):
    return AnalysisFact(
        id=fid,
        fact_type=fact_type,
        statement="statement",
        source_ref=f"src-{fid}",
        supports=supports or [],
        strength=strength,
        metadata=metadata or {},
    )


def _evidence(eid="ev-1", *, related_fact_ids=None, metadata=None):
    return EvidenceItem(
        id=eid,
        title="evidence",
        source_ref=f"src-{eid}",
        related_fact_ids=related_fact_ids or [],
        metadata=metadata or {},
        key_fields={"raw_payload": "do-not-show", "api_key": "secret-token-password"},
    )


def test_supported_fact_strong_status():
    case = _case(facts=[_fact(supports=["ev-1"])], evidence_items=[_evidence()])
    summary = summarize_fact_ledger(case)
    assert summary.coverage.supported_facts == 1
    assert summary.coverage.cited_evidence_items == 1
    assert summary.discipline_status == "strong"


def test_unsupported_fact_and_weak_status():
    summary = summarize_fact_ledger(_case(facts=[_fact()], evidence_items=[_evidence()]))
    assert summary.coverage.unsupported_facts == 1
    assert any(f.finding_type == "unsupported_fact" for f in summary.findings)
    assert summary.discipline_status == "weak"


def test_uncited_evidence_partial_status():
    case = _case(facts=[_fact(supports=["ev-1"])], evidence_items=[_evidence(), _evidence("ev-2")])
    summary = summarize_fact_ledger(case)
    assert summary.coverage.uncited_evidence_items == 1
    assert any(f.finding_type == "uncited_evidence" for f in summary.findings)
    assert summary.discipline_status == "partial"


def test_false_positive_without_contradiction_finding():
    case = _case(verdict="false_positive_rule_noise", facts=[_fact(supports=["ev-1"])], evidence_items=[_evidence()])
    assert any(f.finding_type == "false_positive_missing_contradiction" for f in summarize_fact_ledger(case).findings)


def test_false_positive_with_negative_observation_no_finding():
    case = _case(
        verdict="false_positive_rule_noise",
        facts=[_fact(fact_type="negative_observation", supports=["ev-1"])],
        evidence_items=[_evidence()],
    )
    assert not any(f.finding_type == "false_positive_missing_contradiction" for f in summarize_fact_ledger(case).findings)


def test_high_risk_verdict_weak_support_finding():
    case = _case(verdict="confirmed_incident", severity="critical", facts=[_fact(strength="weak")], evidence_items=[_evidence()])
    assert any(f.finding_type == "high_risk_verdict_weak_support" for f in summarize_fact_ledger(case).findings)


def test_open_evidence_gaps():
    case = _case(evidence_gaps=[EvidenceGap(id="gap-1", gap_type="missing", description="need more")])
    summary = summarize_fact_ledger(case)
    assert summary.coverage.total_evidence_gaps == 1
    assert summary.coverage.open_evidence_gaps == 1


def test_summary_does_not_include_sensitive_raw_fields():
    case = _case(facts=[_fact(supports=["ev-1"])], evidence_items=[_evidence()])
    dumped = summarize_fact_ledger(case).model_dump_json()
    assert "raw_payload" not in dumped
    for forbidden in ("api_key", "secret", "token", "password"):
        assert forbidden not in dumped.lower()


def test_legacy_case_missing_reference_fields_compatible():
    case = _case(facts=[_fact(fid="legacy")], evidence_items=[])
    summary = summarize_fact_ledger(case)
    assert summary.coverage.total_facts == 1
    assert summary.coverage.unsupported_facts == 1


def test_metadata_reference_fields_are_honored():
    case = _case(facts=[_fact(metadata={"evidence_refs": ["src-ev-1"]})], evidence_items=[_evidence()])
    assert summarize_fact_ledger(case).coverage.supported_facts == 1


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
    await Storage.init(tmp_path / "flocks.db")

    from fastapi import FastAPI, Request
    from flocks.auth.context import AuthUser
    from flocks.server.routes.security import router as security_router

    app = FastAPI()

    @app.middleware("http")
    async def inject_admin(request: Request, call_next):
        request.state.auth_user = AuthUser(id="admin-user", username="admin-user", role="admin", status="active")
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


@pytest.mark.asyncio
async def test_api_returns_fact_ledger_summary_and_does_not_modify_case(client: AsyncClient):
    payload = {
        "title": "api case",
        "facts": [{"id": "fact-1", "fact_type": "observation", "statement": "s", "source_ref": "src", "supports": ["ev-1"]}],
        "evidence_items": [{"id": "ev-1", "title": "e", "source_ref": "ev-src"}],
    }
    created = (await client.post("/api/security/analysis-cases", json=payload)).json()
    before = (await client.get(f"/api/security/analysis-cases/{created['id']}")).json()
    response = await client.get(f"/api/security/analysis-cases/{created['id']}/fact-ledger-summary")
    after = (await client.get(f"/api/security/analysis-cases/{created['id']}")).json()
    assert response.status_code == 200
    assert response.json()["coverage"]["supported_facts"] == 1
    assert after == before


@pytest.mark.asyncio
async def test_api_fact_ledger_summary_404(client: AsyncClient):
    response = await client.get("/api/security/analysis-cases/missing/fact-ledger-summary")
    assert response.status_code == 404


def test_brief_contains_fact_evidence_discipline_section():
    brief = generate_analysis_case_brief(_case(facts=[_fact(supports=["ev-1"])], evidence_items=[_evidence()]))
    assert "## Fact / Evidence Discipline" in brief
    assert "total facts" in brief
    assert "## Raw Case JSON" not in brief
    assert "raw_payload" not in brief
    for forbidden in ("api_key", "secret", "token", "password"):
        assert forbidden not in brief.lower()
