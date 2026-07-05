---
name: security-alert-triage-sop
description: SOP for security alert triage using assets, vulnerabilities, exposure, IOC, MITRE and honeypot signals.
---

# Security Alert Triage SOP

Use this SOP when triaging security alerts in Flocks Security Extension.

## Decision Inputs

- Asset importance: low, medium, high, critical.
- Exposure level: internal, external, unknown.
- Alert severity and source.
- Related vulnerabilities, especially high/critical, KEV, exploit_available, high EPSS.
- IOC overlap across alerts and honeypot events.
- MITRE Technique overlap.
- Evidence quality: endpoint, network, application, vulnerability and honeypot evidence.

## Triage Rules

- External critical assets with high/critical alerts should be treated as high priority.
- High/critical vulnerability plus exploit evidence or KEV strongly increases escalation priority.
- Honeypot hit from the same source IP or same target asset increases confidence, but does not prove compromise alone.
- Multiple independent evidence sources increase confidence.
- If only a single weak alert exists, state that evidence is insufficient.

## Output

Always return:

- Severity.
- Confidence.
- Evidence.
- Whether to create or link an Incident.
- Recommended actions.

Never execute real blocking, isolation, deletion or exploit actions.
