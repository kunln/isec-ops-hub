# Fact Ledger Model

## Definition

A Fact Ledger is the structured, evidence-backed record of what is known, what is unknown, and how conclusions were reached inside an Analysis Case. In the first stage, the Fact Ledger should be embedded in the Analysis Case rather than implemented as an independent large subsystem.

The Fact Ledger is designed to prevent unsupported AI conclusions. Every AI judgment should cite Facts, Evidence Gaps, and source references. Missing evidence must not be treated as proof that nothing happened.

## Raw Log, Evidence Item, Fact, Hypothesis, and Verdict

| Concept | Meaning | Example | Rule |
|---|---|---|---|
| Raw Log | Original high-fidelity device or platform record | WAF event JSON, EDR process event, auth log line | Preserve source fidelity when relevant |
| Evidence Item | Referenced evidence attached to a case | Raw log, connector response, screenshot metadata, normalized record | Must have source reference and timestamp when available |
| Fact | Objective statement derived from evidence | `WAF observed request to /login with SQL injection pattern at 10:03 UTC` | Must cite source evidence |
| Hypothesis | Possible explanation connecting facts | `The actor attempted SQL injection against the login endpoint` | Must cite supporting facts and gaps |
| Verdict | Case-level conclusion | `confirmed_attack_attempt_blocked` | Must be derived from facts, gaps, and hypotheses |

## Fact Types v1

- `attack_request_observed`: A request or activity consistent with an attack was observed.
- `attack_pattern_matched`: A detection rule, signature, model, or pattern matched attack-like behavior.
- `protection_action_observed`: A control blocked, challenged, quarantined, alerted, or otherwise acted on the activity.
- `backend_request_observed`: Backend service, application, or server logs show the request reached or did not reach a backend component within a defined scope.
- `vulnerability_condition_present`: The affected asset has a vulnerability, exposure, misconfiguration, or risky condition relevant to the case.
- `threat_intel_match`: Indicator, source, artifact, or infrastructure matched threat-intelligence data.
- `process_execution_observed`: Endpoint or workload telemetry observed process execution.
- `file_artifact_observed`: A file, hash, path, or artifact was observed.
- `network_connection_observed`: Network telemetry observed a connection, flow, DNS lookup, or related activity.
- `database_query_observed`: Database telemetry observed a query or database access event.
- `sensitive_data_access_observed`: Evidence indicates access to sensitive data, secrets, regulated data, or high-value records.
- `authentication_event_observed`: Authentication, login, token, MFA, or session activity was observed.
- `privilege_change_observed`: Permission, role, group, policy, or privilege state changed.
- `lateral_movement_observed`: Evidence suggests movement across assets, identities, network segments, or systems.
- `business_context_observed`: Business owner, application role, maintenance window, release activity, or other context was observed.
- `negative_observation`: A scoped query found no matching evidence in a defined source, time range, and filter set.
- `evidence_gap`: Required or useful evidence is missing, unavailable, unsupported by current APIs, or not yet collected.
- `correlation_observed`: Two or more facts, alerts, or evidence items correlate by asset, identity, source, time, vulnerability, or business context.

## Fact to Hypothesis to Verdict Reasoning Model

1. Preserve raw evidence and source references.
2. Extract objective Facts from the evidence.
3. Record Evidence Gaps for missing or unavailable evidence.
4. Generate one or more Hypotheses that explain the Facts.
5. Evaluate each Hypothesis against supporting Facts, contradicting Facts, Negative Observations, and Evidence Gaps.
6. Select a Verdict that best reflects the evidence and uncertainty.
7. Assign severity and confidence separately.
8. Record notification and incident decisions.

AI must not skip directly from raw alert text to verdict. It must show the chain from evidence to Facts, from Facts to Hypotheses, and from Hypotheses to Verdict.

## Missing Evidence vs. Negative Observation

Missing evidence means the platform does not have the evidence needed to answer a question. It may be caused by missing connector capability, unavailable logs, time-window mismatch, permission limits, retention limits, or investigation not yet performed. Missing evidence is an Evidence Gap.

A Negative Observation is a fact-like statement that no matching evidence was found in a clearly defined query scope. It must state:

- Source system.
- Time range.
- Query filters.
- Data coverage or retention assumptions.
- Limitations of the query.

For example, `No backend request was found` is invalid by itself. A valid Negative Observation would say that no matching backend access log entry was found in a specific service log, for a specific asset, request path, source IP, and time window.

## Single-device High-fidelity Logs

A single device can confirm a local objective Fact when the log is authoritative for that observation. For example:

- A WAF can confirm that it observed a request and applied a block action.
- An EDR can confirm that it observed a process execution event.
- An identity provider can confirm that an authentication event occurred.

Single-device facts are valid local facts, but they may not prove end-to-end impact. Multi-device evidence improves completeness and confidence, especially for backend reachability, data access, lateral movement, or business impact.

## First-stage Embedding in Analysis Case

In the first stage, Fact Ledger should be implemented as part of Analysis Case data rather than a standalone system. This keeps the design aligned with the current FLOCKS Security Extension and avoids creating a separate evidence platform before the case workflow is proven.

The embedded ledger should support:

- Facts with type, statement, timestamp, source reference, confidence, and related entities.
- Evidence Gaps with missing source, reason, impact on verdict, and proposed collection step.
- Hypotheses with supporting facts, contradicting facts, and unresolved gaps.
- Verdict derivation with citations to facts and gaps.
