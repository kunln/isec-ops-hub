# Flocks Security Extension

This package contains the MVP security operations layer for Flocks.

It adds lightweight models, Storage-backed CRUD, connector manifests, fixture
replay previews, risk profiles, vulnerability prioritization, scoring, alert
correlation, alert triage, sample data, and Markdown incident reports for an AI
resident security expert workflow.

The extension is intentionally non-destructive:

- It does not run exploit code.
- It does not block IPs, isolate hosts, delete files, or change firewall rules.
- It retains compact `raw_data` payloads on domain objects and emits
  `normalized_data`; it still does not store high-volume raw logs.
- Honeypot support is limited to event modeling and correlation.

Existing secret management exports in `flocks.security` remain compatible.
