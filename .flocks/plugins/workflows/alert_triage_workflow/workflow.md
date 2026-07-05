# Alert Triage Workflow

Inputs:

- `alert_id`
- `create_incident`，默认 `true`

The workflow calls `security_alert_triage`, returns the triage result, and creates or reuses an Incident when escalation is recommended.
