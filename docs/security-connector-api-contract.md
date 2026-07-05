# Security Connector API Contract

This document records the operational API contract for connector credential health, run policy, policy pause and remediation events.

## Compatibility Rules

- New fields are additive. Existing clients can ignore unknown fields.
- Long-form `reason` remains stable enough for display, but automation should use `reason_code`.
- `reason_code` is the stable taxonomy for health gates, UI state, audit and alert routing.
- Historical blocked runs are retained. Recovery creates later healthy records instead of mutating old runs.
- Missing registries load with empty defaults, so existing installations do not need migration before first use.

## Credential Health

Endpoint:

`GET /api/security/connectors/{connector_id}/credentials/health?profile_id={profile_id}`

Contract:

```json
{
  "version": "connector.credential.health.v1",
  "connector_id": "fixture-replay-demo",
  "profile_id": "default",
  "status": "expired",
  "healthy": false,
  "blocking": true,
  "reason": "credential_profile_expired",
  "reason_code": "expired",
  "reason_taxonomy": "credential_health_reason.v1",
  "severity": "critical",
  "message": "Credential profile expired at 2026-01-01T00:00:00Z",
  "profile_active": true,
  "profile": {},
  "actions": []
}
```

Reason codes:

- `expired`: blocking, critical.
- `failed`: blocking, high.
- `missing`: blocking, critical.
- `pending_test`: blocking, medium.
- `not_active`: non-blocking, low.
- `not_configured`: non-blocking, info.
- `healthy`: non-blocking, info.

## Run Policy

Blocked sync runs include:

```json
{
  "status": "blocked",
  "source": "credential_health_gate",
  "run_policy": {
    "version": "connector.run.policy.v1",
    "decision": "block",
    "state": "blocked",
    "reason": "credential_profile_expired",
    "message": "Credential profile expired at ...",
    "actions": [],
    "credential_health": {}
  },
  "credential_health": {}
}
```

Semantics:

- `decision: block` means adapter execution did not start.
- `cursor_updated` is `false`.
- `counts` is empty.
- `run_policy.actions` are remediation actions clients can render.

## Policy-Paused Schedules

Schedule fields:

- `runtime_status`: one of `enabled`, `disabled`, `running`, `policy_paused`.
- `policy_state`: `paused` when run policy stopped the schedule.
- `policy_reason`: long-form reason.
- `policy_reason_code`: stable reason taxonomy value.
- `policy_message`: display text.
- `policy_actions`: remediation actions from run policy.
- `policy_paused_at`: ISO timestamp for the pause.

Recovery endpoint:

`POST /api/security/connectors/{connector_id}/credentials/profiles/{profile_id}/policy-pauses/recover`

Payload:

```json
{ "mode": "preview" }
```

Modes:

- `preview`: returns matching schedules and `requires_confirmation`.
- `clear`: clears policy pause metadata without enabling schedules.
- `enable`: clears policy pause metadata and enables schedules.

## Operational Events

List:

`GET /api/security/connectors/operations/events?status=open&kind=sync_blocked&connector_id=fixture-replay-demo&limit=100`

Ack:

`POST /api/security/connectors/operations/events/{event_id}/ack`

Event contract:

```json
{
  "id": "connector-operation-event-...",
  "version": "connector.operation.event.v1",
  "kind": "sync_blocked",
  "status": "open",
  "severity": "critical",
  "connector_id": "fixture-replay-demo",
  "profile_id": "default",
  "schedule_id": null,
  "run_id": "connector-sync-blocked-...",
  "reason_code": "expired",
  "title": "Connector sync blocked",
  "message": "Credential profile expired at ...",
  "created_at": "2026-06-02T00:00:00Z",
  "last_seen_at": "2026-06-02T00:00:00Z",
  "acknowledged_at": null,
  "seen_count": 1,
  "dedupe_key": "sync_blocked:...",
  "metadata": {}
}
```

Kinds:

- `credential_expiring_soon`
- `credential_expired`
- `sync_blocked`
- `schedule_policy_paused`
- `credential_remediation_requested`

## Credential Expiry Monitor

Endpoint:

`POST /api/security/connectors/credentials/expiry-monitor`

Payload:

```json
{
  "days": 14,
  "notify": true
}
```

Response:

```json
{
  "version": "connector.credential.expiry_monitor.v1",
  "checked_at": "2026-06-02T00:00:00Z",
  "days": 14,
  "notify": true,
  "matched": 1,
  "expired": 0,
  "expiring_soon": 1,
  "profiles": [],
  "events": []
}
```

## Bulk Remediation

Endpoint:

`POST /api/security/connectors/credentials/bulk-remediation`

Payload:

```json
{
  "action": "notify",
  "recovery_mode": "enable",
  "notify": true,
  "items": [
    { "connector_id": "fixture-replay-demo", "profile_id": "default" }
  ]
}
```

Actions:

- `test`: runs credential profile tests.
- `enable_schedules`: recovers policy-paused schedules for healthy profiles.
- `notify`: creates operational remediation events.

Response includes `requested`, `succeeded`, `failed`, per-item `results` and a retained `bulk_run` record.
