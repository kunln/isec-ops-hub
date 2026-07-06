# Analysis Case Model

## Definition

An Analysis Case is the investigation and confirmation object between Alert and Incident in iSecOps Hub. It groups security signals, raw evidence, normalized evidence, embedded Fact Ledger entries, Evidence Gaps, Hypotheses, AI analysis, verdict, severity, notification decision, incident decision, confirmation records, and closure disposition.

Analysis Case is not a replacement for Alert. It is not a replacement for Incident. It is the structured place where alerts and evidence are evaluated before operational escalation.

## Lifecycle

```text
Signal Intake
  -> Raw Log Preservation
  -> Fact Extraction
  -> Case Candidate
  -> Case Created
  -> Evidence Coverage Check
  -> Investigation Planning
  -> Evidence Collection
  -> AI Analysis
  -> Decision
  -> Notification / Confirmation
  -> Resolution
  -> Reopen / Update
```

### 1. Signal Intake

The platform receives or references an Alert, raw log, connector result, normalized security object, or manually supplied signal.

### 2. Raw Log Preservation

High-fidelity raw logs and vendor responses relevant to the case are preserved as source evidence. Raw evidence should remain available for later review and audit.

### 3. Fact Extraction

Objective, source-backed Facts are extracted from raw and normalized evidence. Extracted Facts must retain source references.

### 4. Case Candidate

Signals are grouped into a potential Analysis Case using asset, source, identity, vulnerability, business context, time window, or rule correlation.

### 5. Case Created

A formal Analysis Case is created with status, owner context, linked alerts, preserved evidence, and an embedded Fact Ledger.

### 6. Evidence Coverage Check

The case records which evidence types are present and which are missing. Missing evidence becomes an Evidence Gap, not a negative conclusion.

### 7. Investigation Planning

The platform identifies additional evidence needed to increase confidence, such as WAF logs, EDR process records, authentication events, vulnerability status, backend access logs, or owner confirmation.

### 8. Evidence Collection

Additional evidence is collected through existing security connectors and `/api/security` workflows as device API coverage permits.

### 9. AI Analysis

AI evaluates Facts, Evidence Gaps, Hypotheses, and source references. AI conclusions must cite the supporting Facts and explicitly state uncertainty.

### 10. Decision

The case receives verdict, severity, confidence, notification decision, incident decision, and disposition recommendations.

### 11. Notification / Confirmation

The platform notifies the responsible owner or requests confirmation when needed. Notification is used to close evidence gaps or confirm business context.

### 12. Resolution

The case is closed, escalated to Incident, stored for digest-only reporting, or marked for continued monitoring.

### 13. Reopen / Update

New evidence can reopen or update the case. Revised analysis must preserve prior evidence and decision history.

## Field Definitions

### `case_status`

Represents the workflow state of the Analysis Case. Suggested v1 values include `candidate`, `open`, `collecting_evidence`, `analyzing`, `awaiting_confirmation`, `escalated`, `closed`, and `reopened`.

### `verdict`

Represents the evidence-backed conclusion for the case. Verdicts must be derived from Facts, Evidence Gaps, and source references.

### `severity`

Represents potential or confirmed business and security impact. Severity should consider asset criticality, exploitability, protection outcome, backend impact, sensitive data access, identity impact, and confidence.

### `confidence`

Represents how strongly the available evidence supports the verdict. Confidence is not the same as severity. A severe hypothesis with weak evidence should not be presented as a high-confidence conclusion.

### `evidence_coverage`

Represents which evidence categories are present, missing, partial, or not applicable. Missing categories must be recorded as Evidence Gaps unless the query scope supports a Negative Observation.

### `analysis_mode`

Represents how analysis was performed, such as AI-assisted, manual, rule-assisted, connector-assisted, or hybrid. AI-assisted analysis must cite Facts and source references.

### `incident_decision`

Represents whether the case should become an Incident, remain under monitoring, require human confirmation, or not be escalated.

### `notification_decision`

Represents whether and how responsible owners should be notified.

### `disposition`

Represents the final operational outcome of the case, such as escalated, closed as benign, closed as blocked attempt, stored for digest, or monitoring continued.

## Verdict v1

- `confirmed_incident`: Evidence confirms malicious or unauthorized activity with material impact or required response.
- `confirmed_attack_attempt_blocked`: Evidence confirms an attack attempt, and available evidence indicates protective controls blocked it.
- `suspicious_true_positive`: Evidence supports suspicious or malicious intent, but impact or completeness remains uncertain.
- `false_positive_rule_noise`: Evidence shows the alert was caused by noisy detection logic, parsing error, duplicate signal, or irrelevant rule match.
- `benign_business_activity`: Evidence supports a legitimate business explanation.
- `insufficient_evidence`: Available evidence does not support a reliable positive or benign conclusion.

## Severity v1

- `critical`: Confirmed or highly likely severe impact to critical assets, sensitive data, privileged identity, production availability, or active compromise.
- `high`: Significant security impact or strong evidence of attack requiring prompt response.
- `medium`: Meaningful risk or suspicious activity requiring investigation or owner confirmation.
- `low`: Limited scope, blocked activity, low-value target, or weak impact evidence.
- `informational`: Useful security context with no current response requirement.

## Notification Decision v1

- `realtime_notify`: Notify the responsible owner immediately.
- `confirmation_request`: Ask an owner or stakeholder to confirm business context or observed activity.
- `daily_digest`: Include in a scheduled summary without immediate interruption.
- `no_notify_store_only`: Store the case without notifying because no action is currently needed.
- `escalation_reminder`: Remind stakeholders when confirmation or escalation remains pending.

## Incident Decision v1

- `escalate_to_incident`: Create or link an Incident because evidence and impact justify operational response.
- `do_not_escalate`: Do not create an Incident based on current evidence.
- `needs_human_confirmation`: Require human confirmation before escalation.
- `continue_monitoring`: Keep the case open or watchlisted for additional evidence.
