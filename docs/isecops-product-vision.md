# iSecOps Hub Product Vision

## Product Positioning

iSecOps Hub is the product name for the security operations experience delivered by the FLOCKS Security Extension. The repository name remains `isec-ops-hub`, the internal core platform remains FLOCKS, and the Python package name remains `flocks`.

iSecOps Hub extends the existing FLOCKS architecture instead of creating a separate security analysis platform. New security capabilities should continue to reuse the existing Security Extension building blocks, including `flocks/security`, `/api/security`, security tools, security connectors, evidence graph capabilities, and the existing WebUI security page.

## Current Stage: AI Security Incident Confirmation and Notification Platform

The current stage is an AI security incident confirmation and notification platform. Its primary job is to help operators confirm whether security signals represent real attacks, blocked attack attempts, suspicious activity, benign business behavior, rule noise, or insufficiently evidenced cases.

The platform focuses on the workflow from security-device alerts and high-fidelity raw logs to:

1. Analysis Case creation.
2. Fact Ledger extraction.
3. Evidence coverage review.
4. AI-assisted investigation and verdict generation.
5. Severity assessment.
6. Owner notification and confirmation.
7. Incident escalation when justified.
8. Report and closure.

This makes iSecOps Hub a confirmation, evidence, and communication layer between Alerts and Incidents, not an automatic remediation engine.

## What iSecOps Hub Does Not Do in the Current Stage

### It does not replace a SIEM

iSecOps Hub should integrate with security devices and existing systems, but it is not intended to replace SIEM ingestion, correlation, retention, query languages, or enterprise-scale monitoring workflows.

### It does not become a full log lake

The platform preserves high-fidelity raw evidence needed for an Analysis Case, but it does not aim to store every enterprise log, rebuild a data lake, or compete with long-term log analytics platforms.

### It does not rush into automatic remediation

Current-stage workflows must not perform real blocking, host isolation, account disabling, deletion, firewall/WAF/EDR policy changes, or other destructive or operationally risky actions. Future remediation may be modeled as Remediation Action, Approval, and Audit concepts, but it is not the current mainline capability.

### It is not an AI alert robot

The product is not a chatbot that merely restates alerts. AI outputs must cite Facts, Evidence Gaps, raw evidence sources, and source references. Missing evidence must not be treated as proof of safety. Negative observations must explicitly describe the query scope.

## Core Value

### Multi-vendor API access

iSecOps Hub should progressively connect to security devices and platforms through the existing connector architecture. Device API coverage may mature incrementally; the product does not require every vendor and every API capability on day one.

### Asset-centered view

The primary investigation perspective is the asset. Attack sources, identities, vulnerabilities, business systems, and timelines are supporting perspectives that enrich the asset-centered case narrative.

### Raw-log fact extraction

High-fidelity raw logs are preserved and used to extract objective Facts. A single device can confirm a local objective fact when the log is sufficiently authoritative. Multiple devices improve evidence completeness and confidence.

### AI integrated analysis

AI analysis synthesizes Facts, Hypotheses, Evidence Gaps, and source references. It should distinguish confirmed facts from hypotheses, make uncertainty explicit, and avoid conclusions unsupported by evidence.

### Owner notification and confirmation

The platform helps decide who should be notified, whether human confirmation is required, and whether the case should be escalated to an Incident. Notifications are part of the confirmation loop rather than a substitute for evidence.

## Current-stage Boundary

Current-stage capabilities include:

- Ingesting or referencing Alerts, raw logs, and normalized security objects.
- Creating Analysis Cases between Alerts and Incidents.
- Embedding a Fact Ledger in each Analysis Case.
- Checking evidence coverage and documenting evidence gaps.
- Producing AI-assisted verdict, severity, incident decision, and notification decision.
- Requesting owner confirmation and recording closure or escalation.

Current-stage capabilities exclude:

- Real automatic remediation.
- Replacing Alert or Incident data models.
- Replacing SIEM or full log-lake systems.
- Creating a separate security analysis service outside the existing FLOCKS Security Extension.

## Future-stage Boundary

Future stages may add:

- Remediation Action planning.
- Human approval workflows.
- Audit trails for approved remediation.
- Safer integrations with SOAR or device-control APIs.
- Richer case correlation across assets, identities, vulnerabilities, business systems, and timelines.

Those capabilities should remain compatible with the current evidence-first model and should not bypass Analysis Case, Fact Ledger, approval, or audit requirements.
