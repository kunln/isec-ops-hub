# Security Analysis Domain

## Overall Business Flow

The iSecOps Hub security-analysis domain follows an evidence-first workflow:

```text
Alert / Raw Log / Security Object
  -> Analysis Case
  -> Fact Ledger
  -> Hypothesis
  -> Verdict
  -> Severity
  -> Notification Decision
  -> Incident Decision
  -> Notification / Confirmation
  -> Incident / Report / Closure
```

The workflow intentionally places Analysis Case between Alert and Incident. Alerts and raw logs are signals and evidence sources. Analysis Cases are investigation containers. Incidents are escalated security records that require operational tracking and response.

## Domain Objects

### Alert

An Alert is a security device, platform, rule, detection, or connector output indicating potentially suspicious or malicious activity. It may contain vendor-specific `raw_data`, normalized fields, severity labels, source identifiers, timestamps, affected assets, indicators, and rule metadata.

An Alert is not automatically an Incident. It is a signal that may start or enrich an Analysis Case.

### Raw Log

A Raw Log is high-fidelity evidence returned by a security product, endpoint, WAF, IDS/IPS, identity system, database platform, cloud service, or other telemetry source. Raw logs should be preserved when they materially support an Analysis Case.

Raw logs are evidence sources, not conclusions.

### Security Object

A Security Object is a normalized representation of a security-domain entity such as an asset, vulnerability, alert, incident, connector result, identity, business system, or evidence item. First-stage implementations can carry Security Signal concepts through existing Alert fields plus `raw_data` and `normalized_data`.

### Analysis Case

An Analysis Case is the investigation object between Alert and Incident. It gathers related security signals, raw evidence, extracted Facts, Evidence Gaps, Hypotheses, AI analysis, verdict, severity, notification decision, incident decision, owner confirmation, and final disposition.

An Analysis Case does not replace Alert and does not replace Incident.

### Fact Ledger

A Fact Ledger is the structured list of evidence-backed Facts and Evidence Gaps embedded in an Analysis Case. It records what is objectively known, where it came from, and what remains unknown.

### Hypothesis

A Hypothesis is a possible explanation of the observed Facts. It must cite supporting Facts, contradicting Facts, and Evidence Gaps.

### Verdict

A Verdict is the case-level conclusion derived from Facts, Evidence Gaps, and Hypotheses. It should express whether the case is a confirmed incident, blocked attack attempt, suspicious true positive, false positive, benign business activity, or insufficiently evidenced.

### Incident

An Incident is an escalated security record used for operational response, tracking, communication, reporting, and closure. Incidents may be created from Analysis Cases when the incident decision is `escalate_to_incident` or when human confirmation authorizes escalation.

## Alert, Analysis Case, and Incident Differences

| Concept | Primary role | Created from | Contains | Does not do |
|---|---|---|---|---|
| Alert | Detection signal | Security tools, rules, connectors, SIEM, devices | Alert metadata, raw data, normalized data | Does not prove an incident by itself |
| Analysis Case | Investigation and confirmation object | One or more alerts, raw logs, or security objects | Facts, evidence gaps, hypotheses, verdict, severity, decisions, confirmation | Does not replace Alert or Incident |
| Incident | Operational security event | Confirmed or escalated Analysis Case, manual creation | Response tracking, owner, status, report, closure | Does not store every raw signal |

## Security Signal

Security Signal is a business concept representing information that may indicate security-relevant activity. It can be sourced from Alerts, raw logs, connector results, user reports, asset risk changes, vulnerability findings, or threat-intelligence matches.

In the first stage, Security Signal does not require a new standalone model. It can be carried by existing Alert records plus `raw_data` and `normalized_data`, with Analysis Case providing the investigation layer.

## Investigation Perspectives

### Primary perspective: asset

The asset is the primary lens for investigation. The case should answer what happened to the asset, what evidence supports that assessment, and what owner action or confirmation is needed.

### Supporting perspectives

Supporting perspectives enrich the case and improve confidence:

- Attack source: IP, domain, ASN, region, reputation, or source system.
- Identity: user, service account, role, session, authentication context.
- Vulnerability: CVE, exposure, exploitability, patch state, compensating controls.
- Business system: service criticality, owner, environment, customer impact.
- Timeline: sequence of observations, protection actions, backend effects, and confirmations.

A single device can confirm local objective Facts. Multi-device evidence chains improve completeness and confidence but are not mandatory for every local finding.
