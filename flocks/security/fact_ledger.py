"""Read-only Fact Ledger discipline helpers for Analysis Cases."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from flocks.security.models import AnalysisCase, EvidenceGap


EVIDENCE_REFERENCE_FIELDS = (
    "evidence_refs",
    "evidence_ref_ids",
    "evidence_item_ids",
    "source_evidence_ids",
    "related_evidence_ids",
)

SECRET_FIELD_TOKENS = ("api_key", "secret", "token", "password")
HIGH_RISK_VERDICT_TOKENS = ("true_positive", "malicious", "confirmed", "incident")
FALSE_POSITIVE_VERDICT_TOKENS = ("false_positive", "benign")
CONTRADICTION_TOKENS = ("contradiction", "contradicts", "negative_observation", "benign", "false_positive")
OPEN_GAP_CLOSED_VALUES = ("closed", "resolved", "done", "false", "no")


class FactLedgerCoverageSummary(BaseModel):
    case_id: str
    total_facts: int = 0
    supported_facts: int = 0
    unsupported_facts: int = 0
    total_evidence_items: int = 0
    cited_evidence_items: int = 0
    uncited_evidence_items: int = 0
    total_evidence_gaps: int = 0
    open_evidence_gaps: int = 0
    evidence_coverage_ratio: float = 0.0
    fact_support_ratio: float = 0.0
    discipline_status: str = "weak"
    warnings: list[str] = Field(default_factory=list)


class FactLedgerFinding(BaseModel):
    finding_type: str
    severity: str
    message: str
    fact_id: str | None = None
    evidence_id: str | None = None


class FactLedgerSummary(BaseModel):
    case_id: str
    coverage: FactLedgerCoverageSummary
    findings: list[FactLedgerFinding] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    uncited_evidence_ids: list[str] = Field(default_factory=list)
    unsupported_fact_ids: list[str] = Field(default_factory=list)


def _string_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _unique(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(v for v in values if v))


def _iter_reference_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        refs: list[str] = []
        for item in value:
            refs.extend(_iter_reference_values(item))
        return refs
    if isinstance(value, dict):
        refs: list[str] = []
        for key in ("id", "evidence_id", "evidence_item_id"):
            if key in value:
                refs.extend(_iter_reference_values(value.get(key)))
        return refs
    return [str(value)]


def _fact_evidence_refs(fact: Any) -> list[str]:
    refs: list[str] = []
    for field in EVIDENCE_REFERENCE_FIELDS:
        refs.extend(_iter_reference_values(getattr(fact, field, None)))
    metadata = getattr(fact, "metadata", {}) or {}
    if isinstance(metadata, dict):
        for field in EVIDENCE_REFERENCE_FIELDS:
            refs.extend(_iter_reference_values(metadata.get(field)))
    return _unique([ref for ref in refs if not any(token in ref.lower() for token in SECRET_FIELD_TOKENS)])


def _gap_is_open(gap: EvidenceGap) -> bool:
    metadata = gap.metadata or {}
    status = _string_id(metadata.get("status") if isinstance(metadata, dict) else None)
    if status and status.lower() in OPEN_GAP_CLOSED_VALUES:
        return False
    resolved = metadata.get("resolved") if isinstance(metadata, dict) else None
    if resolved is True:
        return False
    return True


def build_fact_to_evidence_index(case: AnalysisCase) -> dict[str, list[str]]:
    """Return explicit fact -> evidence references without guessing by text similarity."""

    index: dict[str, list[str]] = {}
    known_evidence_ids = {e.id for e in case.evidence_items if e.id}
    for fact in case.facts:
        fact_id = fact.id or fact.source_ref or fact.statement
        refs = [ref for ref in _fact_evidence_refs(fact) if not known_evidence_ids or ref in known_evidence_ids]
        index[fact_id] = _unique(refs)
    for evidence in case.evidence_items:
        if not evidence.id:
            continue
        for fact_id in evidence.related_fact_ids:
            if fact_id in index:
                index[fact_id] = _unique([*index[fact_id], evidence.id])
    return index


def build_evidence_to_fact_index(case: AnalysisCase) -> dict[str, list[str]]:
    fact_to_evidence = build_fact_to_evidence_index(case)
    index = {e.id: [] for e in case.evidence_items if e.id}
    for fact_id, evidence_ids in fact_to_evidence.items():
        for evidence_id in evidence_ids:
            if evidence_id in index:
                index[evidence_id].append(fact_id)
    return {evidence_id: _unique(fact_ids) for evidence_id, fact_ids in index.items()}


def _case_verdict(case: AnalysisCase) -> str:
    verdict = getattr(case.verdict, "value", case.verdict)
    return str(verdict or "").lower()


def _has_false_positive_support(case: AnalysisCase) -> bool:
    for fact in case.facts:
        haystack = " ".join([
            str(fact.fact_type),
            fact.statement,
            " ".join(fact.contradicts),
            " ".join(fact.limitations),
        ]).lower()
        if any(token in haystack for token in CONTRADICTION_TOKENS):
            return True
    for gap in case.evidence_gaps:
        haystack = " ".join([gap.gap_type, gap.description, gap.impact or ""]).lower()
        if any(token in haystack for token in CONTRADICTION_TOKENS):
            return True
    return False


def validate_fact_evidence_discipline(case: AnalysisCase) -> list[FactLedgerFinding]:
    fact_to_evidence = build_fact_to_evidence_index(case)
    findings: list[FactLedgerFinding] = []
    for fact_id, evidence_ids in fact_to_evidence.items():
        if not evidence_ids:
            findings.append(FactLedgerFinding(
                finding_type="unsupported_fact",
                severity="medium",
                message="Fact has no explicit evidence reference.",
                fact_id=fact_id,
            ))

    total_facts = len(case.facts)
    supported_facts = sum(1 for evidence_ids in fact_to_evidence.values() if evidence_ids)
    fact_support_ratio = supported_facts / total_facts if total_facts else 0.0
    verdict = _case_verdict(case)
    if any(token in verdict for token in HIGH_RISK_VERDICT_TOKENS) and fact_support_ratio < 0.5:
        findings.append(FactLedgerFinding(
            finding_type="weak_verdict_support",
            severity="high",
            message="High-risk verdict has weak fact support below the required threshold.",
        ))
    if any(token in verdict for token in FALSE_POSITIVE_VERDICT_TOKENS) and not _has_false_positive_support(case):
        findings.append(FactLedgerFinding(
            finding_type="false_positive_without_contradiction",
            severity="medium",
            message="False-positive verdict lacks contradiction, negative observation, or benign explanation support.",
        ))
    return findings


def summarize_fact_ledger(case: AnalysisCase) -> FactLedgerSummary:
    fact_to_evidence = build_fact_to_evidence_index(case)
    evidence_to_fact = build_evidence_to_fact_index(case)
    findings = validate_fact_evidence_discipline(case)

    cited_evidence_ids = _unique([evidence_id for evidence_id, fact_ids in evidence_to_fact.items() if fact_ids])
    uncited_evidence_ids = _unique([evidence_id for evidence_id, fact_ids in evidence_to_fact.items() if not fact_ids])
    unsupported_fact_ids = _unique([fact_id for fact_id, evidence_ids in fact_to_evidence.items() if not evidence_ids])

    total_facts = len(case.facts)
    total_evidence_items = len(case.evidence_items)
    supported_facts = total_facts - len(unsupported_fact_ids)
    open_evidence_gaps = sum(1 for gap in case.evidence_gaps if _gap_is_open(gap))
    fact_support_ratio = supported_facts / total_facts if total_facts else 0.0
    evidence_coverage_ratio = len(cited_evidence_ids) / total_evidence_items if total_evidence_items else 0.0
    has_high = any(f.severity == "high" for f in findings)
    if has_high or fact_support_ratio < 0.5:
        discipline_status = "weak"
    elif fact_support_ratio >= 0.8:
        discipline_status = "strong"
    else:
        discipline_status = "partial"

    warnings = [finding.message for finding in findings[:5]]
    coverage = FactLedgerCoverageSummary(
        case_id=case.id,
        total_facts=total_facts,
        supported_facts=supported_facts,
        unsupported_facts=len(unsupported_fact_ids),
        total_evidence_items=total_evidence_items,
        cited_evidence_items=len(cited_evidence_ids),
        uncited_evidence_items=len(uncited_evidence_ids),
        total_evidence_gaps=len(case.evidence_gaps),
        open_evidence_gaps=open_evidence_gaps,
        evidence_coverage_ratio=round(evidence_coverage_ratio, 4),
        fact_support_ratio=round(fact_support_ratio, 4),
        discipline_status=discipline_status,
        warnings=warnings,
    )
    return FactLedgerSummary(
        case_id=case.id,
        coverage=coverage,
        findings=findings,
        cited_evidence_ids=cited_evidence_ids,
        uncited_evidence_ids=uncited_evidence_ids,
        unsupported_fact_ids=unsupported_fact_ids,
    )
