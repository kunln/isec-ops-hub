"""Markdown brief generation for Analysis Cases."""

from __future__ import annotations

import json
from typing import Any

from flocks.security.fact_ledger import summarize_fact_ledger
from flocks.security.models import AnalysisCase


def _value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else ""
    return str(value)


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None._"
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_value(cell).replace("\n", "<br>") for cell in row) + " |")
    return "\n".join(lines)


def generate_analysis_case_brief(case: AnalysisCase) -> str:
    """Return a Markdown brief for a single Analysis Case.

    The brief is intentionally evidence-led and includes raw JSON for demo and
    smoke-test debugging. It does not call external LLMs or notification systems.
    """

    raw_json = json.dumps(case.model_dump(mode="json"), ensure_ascii=False, indent=2)
    fact_ledger = summarize_fact_ledger(case)
    coverage = fact_ledger.coverage
    return "\n".join([
        "# Analysis Case Brief",
        "",
        f"- case id: {case.id}",
        f"- title: {case.title}",
        f"- created_at: {case.created_at}",
        f"- updated_at: {case.updated_at}",
        "",
        "## Conclusion Summary",
        "",
        _table(["field", "value"], [["verdict", case.verdict], ["severity", case.severity], ["confidence", case.confidence], ["evidence_coverage", case.evidence_coverage], ["analysis_mode", case.analysis_mode], ["notification_decision", case.notification_decision], ["incident_decision", case.incident_decision], ["disposition", case.disposition], ["case_status", case.case_status]]),
        "",
        "## Related Objects",
        "",
        _table(["field", "value"], [["primary_asset_id", case.primary_asset_id], ["related_asset_ids", case.related_asset_ids], ["related_alert_ids", case.related_alert_ids], ["related_vulnerability_ids", case.related_vulnerability_ids], ["related_incident_id", case.related_incident_id]]),
        "",
        "## Key Facts",
        "",
        _table(["fact_type", "statement", "source_ref", "confidence", "strength", "observed_at"], [[f.fact_type, f.statement, f.source_ref, f.confidence, f.strength, f.observed_at] for f in case.facts]),
        "",
        "## Evidence Items",
        "",
        _table(["title", "source_ref", "external_event_id", "connector_id", "payload_hash", "description"], [[e.title, e.source_ref, e.external_event_id, e.connector_id, e.payload_hash, e.description] for e in case.evidence_items]),
        "",
        "## Evidence Gaps",
        "",
        _table(["gap_type", "missing_source_type", "description", "impact", "suggested_connector_capability"], [[g.gap_type, g.missing_source_type, g.description, g.impact, g.suggested_connector_capability] for g in case.evidence_gaps]),
        "",
        "## Fact / Evidence Discipline",
        "",
        _table(["metric", "value"], [
            ["total facts", coverage.total_facts],
            ["supported facts", coverage.supported_facts],
            ["unsupported facts", coverage.unsupported_facts],
            ["cited evidence", coverage.cited_evidence_items],
            ["uncited evidence", coverage.uncited_evidence_items],
            ["open evidence gaps", coverage.open_evidence_gaps],
            ["discipline status", coverage.discipline_status],
        ]),
        "",
        "### Top Warnings",
        "",
        "\n".join(f"- {warning}" for warning in coverage.warnings[:3]) if coverage.warnings else "_None._",
        "",
        "## Hypotheses",
        "",
        _table(["name", "status", "reason"], [[h.get("name"), h.get("status"), h.get("reason")] for h in case.hypotheses]),
        "",
        "## Notification Records",
        "",
        _table(["notification_type", "channel", "status", "title", "recipients", "created_at", "sent_at", "acknowledged_at"], [[n.notification_type, n.channel, n.status, n.title, n.recipients, n.created_at, n.sent_at, n.acknowledged_at] for n in case.notification_records]),
        "",
        "## Confirmation Records",
        "",
        _table(["confirmation_type", "decision", "reviewer", "comment", "created_at"], [[c.confirmation_type, c.decision, c.reviewer, c.comment, c.created_at] for c in case.confirmation_records]),
        "",
        "## Recommendations",
        "",
        "\n".join(f"- {item}" for item in case.recommendations) if case.recommendations else "_None._",
        "",
        "## Raw Case JSON",
        "",
        "```json",
        raw_json,
        "```",
    ])
