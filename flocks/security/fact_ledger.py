"""Fact Ledger evidence discipline helpers for Analysis Cases.

The helpers in this module are intentionally read-only and deterministic. They
only inspect explicit fact/evidence references already embedded in an Analysis
Case; they do not infer citations from text similarity, call LLMs, call
connectors, or persist any data.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from flocks.security.models import AnalysisCase, AnalysisFact, EvidenceItem

DisciplineStatus = Literal["strong", "partial", "weak"]
FindingType = Literal[
    "unsupported_fact",
    "high_risk_verdict_weak_support",
    "false_positive_missing_contradiction",
    "uncited_evidence",
]

_EXPLICIT_FACT_METADATA_KEYS = (
    "evidence_refs",
    "evidence_ref",
    "evidence_ids",
    "evidence_id",
    "related_evidence_ids",
    "related_evidence_id",
    "source_evidence_refs",
    "source_evidence_ref",
)
_EXPLICIT_EVIDENCE_METADATA_KEYS = (
    "fact_refs",
    "fact_ref",
    "fact_ids",
    "fact_id",
    "related_fact_ids",
    "related_fact_id",
)
_NEGATIVE_OR_BENIGN_FACT_TYPES = {"contradiction", "negative_observation", "benign_explanation"}
_FALSE_POSITIVE_VERDICTS = {"false_positive_rule_noise", "benign_business_activity"}
_HIGH_RISK_VERDICTS = {"confirmed_incident", "confirmed_attack_attempt_blocked", "suspicious_true_positive"}
_HIGH_RISK_SEVERITIES = {"high", "critical"}
_SUPPORTIVE_STRENGTHS = {"medium", "strong", "critical"}


class FactLedgerCoverageSummary(BaseModel):
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


class FactLedgerFinding(BaseModel):
    finding_type: FindingType
    severity: Literal["info", "low", "medium", "high"] = "medium"
    message: str
    fact_id: str | None = None
    evidence_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FactLedgerSummary(BaseModel):
    coverage: FactLedgerCoverageSummary
    discipline_status: DisciplineStatus
    findings: list[FactLedgerFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _as_values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, (list, tuple, set)):
        refs: set[str] = set()
        for item in value:
            refs.update(_as_values(item))
        return refs
    return set()


def _fact_keys(fact: AnalysisFact) -> set[str]:
    return {value for value in (fact.id, fact.source_ref) if value}


def _evidence_keys(evidence: EvidenceItem) -> set[str]:
    return {value for value in (evidence.id, evidence.source_ref, evidence.external_event_id) if value}


def _metadata_refs(metadata: dict[str, Any], keys: tuple[str, ...]) -> set[str]:
    refs: set[str] = set()
    for key in keys:
        refs.update(_as_values(metadata.get(key)))
    return refs


def _explicit_evidence_refs_for_fact(fact: AnalysisFact) -> set[str]:
    refs = set(fact.supports)
    refs.update(_metadata_refs(fact.metadata, _EXPLICIT_FACT_METADATA_KEYS))
    return {ref for ref in refs if ref}


def build_fact_to_evidence_index(case: AnalysisCase) -> dict[str, list[str]]:
    """Map fact IDs to explicitly cited evidence IDs.

    Only explicit fields are honored: fact.supports, selected fact metadata
    reference fields, evidence.related_fact_ids, and selected evidence metadata
    reference fields.
    """

    evidence_by_ref: dict[str, str] = {}
    for evidence in case.evidence_items:
        if not evidence.id:
            continue
        for key in _evidence_keys(evidence):
            evidence_by_ref[key] = evidence.id

    index: dict[str, set[str]] = {fact.id: set() for fact in case.facts if fact.id}
    fact_by_ref: dict[str, str] = {}
    for fact in case.facts:
        if not fact.id:
            continue
        for key in _fact_keys(fact):
            fact_by_ref[key] = fact.id
        for ref in _explicit_evidence_refs_for_fact(fact):
            evidence_id = evidence_by_ref.get(ref)
            if evidence_id:
                index[fact.id].add(evidence_id)

    for evidence in case.evidence_items:
        if not evidence.id:
            continue
        fact_refs = set(evidence.related_fact_ids)
        fact_refs.update(_metadata_refs(evidence.metadata, _EXPLICIT_EVIDENCE_METADATA_KEYS))
        for ref in fact_refs:
            fact_id = fact_by_ref.get(ref)
            if fact_id:
                index.setdefault(fact_id, set()).add(evidence.id)

    return {fact_id: sorted(evidence_ids) for fact_id, evidence_ids in index.items()}


def build_evidence_to_fact_index(case: AnalysisCase) -> dict[str, list[str]]:
    fact_to_evidence = build_fact_to_evidence_index(case)
    index: dict[str, set[str]] = {evidence.id: set() for evidence in case.evidence_items if evidence.id}
    for fact_id, evidence_ids in fact_to_evidence.items():
        for evidence_id in evidence_ids:
            index.setdefault(evidence_id, set()).add(fact_id)
    return {evidence_id: sorted(fact_ids) for evidence_id, fact_ids in index.items()}


def _is_gap_open(gap: Any) -> bool:
    status = str(getattr(gap, "metadata", {}).get("status", "open")).lower()
    return status not in {"closed", "resolved", "accepted", "waived"}


def validate_fact_evidence_discipline(case: AnalysisCase) -> list[FactLedgerFinding]:
    fact_to_evidence = build_fact_to_evidence_index(case)
    evidence_to_fact = build_evidence_to_fact_index(case)
    findings: list[FactLedgerFinding] = []

    for fact in case.facts:
        if fact.id and not fact_to_evidence.get(fact.id):
            findings.append(FactLedgerFinding(
                finding_type="unsupported_fact",
                severity="medium",
                fact_id=fact.id,
                message=f"Fact '{fact.id}' has no explicit supporting evidence reference.",
            ))

    for evidence in case.evidence_items:
        if evidence.id and not evidence_to_fact.get(evidence.id):
            findings.append(FactLedgerFinding(
                finding_type="uncited_evidence",
                severity="low",
                evidence_id=evidence.id,
                message=f"Evidence '{evidence.id}' is not explicitly cited by any fact.",
            ))

    verdict = str(case.verdict)
    severity = str(case.severity)
    high_risk = verdict in _HIGH_RISK_VERDICTS or severity in _HIGH_RISK_SEVERITIES
    if high_risk:
        strong_supported = [
            fact for fact in case.facts
            if fact.id and fact_to_evidence.get(fact.id) and str(fact.strength) in _SUPPORTIVE_STRENGTHS
        ]
        if not strong_supported:
            findings.append(FactLedgerFinding(
                finding_type="high_risk_verdict_weak_support",
                severity="high",
                message="High-risk verdict/severity has no medium-or-strong fact with explicit evidence support.",
            ))

    if verdict in _FALSE_POSITIVE_VERDICTS:
        has_counter_evidence = any(
            str(fact.fact_type).lower() in _NEGATIVE_OR_BENIGN_FACT_TYPES
            and fact.id
            and fact_to_evidence.get(fact.id)
            for fact in case.facts
        )
        if not has_counter_evidence:
            findings.append(FactLedgerFinding(
                finding_type="false_positive_missing_contradiction",
                severity="high",
                message="False-positive or benign verdict requires a cited contradiction, negative observation, or benign explanation fact.",
            ))

    return findings


def summarize_fact_ledger(case: AnalysisCase) -> FactLedgerSummary:
    fact_to_evidence = build_fact_to_evidence_index(case)
    evidence_to_fact = build_evidence_to_fact_index(case)
    total_facts = len(case.facts)
    total_evidence = len(case.evidence_items)
    supported = sum(1 for fact in case.facts if fact.id and fact_to_evidence.get(fact.id))
    cited = sum(1 for evidence in case.evidence_items if evidence.id and evidence_to_fact.get(evidence.id))
    open_gaps = sum(1 for gap in case.evidence_gaps if _is_gap_open(gap))
    coverage = FactLedgerCoverageSummary(
        total_facts=total_facts,
        supported_facts=supported,
        unsupported_facts=max(total_facts - supported, 0),
        total_evidence_items=total_evidence,
        cited_evidence_items=cited,
        uncited_evidence_items=max(total_evidence - cited, 0),
        total_evidence_gaps=len(case.evidence_gaps),
        open_evidence_gaps=open_gaps,
        evidence_coverage_ratio=round(cited / total_evidence, 4) if total_evidence else 0.0,
        fact_support_ratio=round(supported / total_facts, 4) if total_facts else 0.0,
    )
    findings = validate_fact_evidence_discipline(case)
    warnings = [finding.message for finding in findings if finding.severity in {"medium", "high"}]
    if total_facts == 0 or total_evidence == 0 or coverage.fact_support_ratio == 0:
        status: DisciplineStatus = "weak"
    elif findings or open_gaps or coverage.fact_support_ratio < 1 or coverage.evidence_coverage_ratio < 1:
        status = "partial"
    else:
        status = "strong"
    return FactLedgerSummary(coverage=coverage, discipline_status=status, findings=findings, warnings=warnings)
