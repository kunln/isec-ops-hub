# Security Connector Operator Runbook

This runbook covers connector credential health gates, blocked syncs, policy-paused schedules, operational events and recovery.

## Where to Look

- Connector package diagnostics: `GET /api/security/connectors/package-diagnostics`
- Credential bindings: `GET /api/security/connectors/credential-bindings`
- Credential health: `GET /api/security/connectors/{connector_id}/credentials/health?profile_id={profile_id}`
- Sync runs: `GET /api/security/connectors/sync-runs`
- Schedules: `GET /api/security/connectors/sync-schedules`
- Operational events: `GET /api/security/connectors/operations/events?status=open`

## Why Sync Was Blocked

Connector sync checks `credential_health` before adapter execution.

Blocking reason codes:

- `expired`: the profile has `expires_at` in the past. Rotate credentials and set a future expiry.
- `failed`: the profile failed a connection test or sync health update. Test or rotate the profile.
- `missing`: the requested profile id is not present. Bind the profile or switch schedules to an existing profile.
- `pending_test`: the profile was newly bound or rotated and has not passed a connection test. Run the profile test.

Non-blocking reason codes:

- `not_active`: the profile is healthy but not active for default connector sync. Activate it if it should be the default.
- `not_configured`: no credential profile exists. No-auth and fixture connectors can still run.
- `healthy`: the profile can run.

Blocked runs are stored with `status: blocked`, `source: credential_health_gate`, `credential_health` and `run_policy`. They do not write Security Store objects and do not advance cursors.

## How to Fix Credentials

1. Read the health payload for the affected connector/profile.
2. Follow the actions in `credential_health.actions`.
3. For `expired` or `failed`, rotate or re-bind credentials.
4. Run `POST /api/security/connectors/{connector_id}/credentials/profiles/{profile_id}/test`.
5. Confirm `credential_health.blocking` is `false`.

## How to Recover Schedules

When a scheduled run is blocked, the schedule becomes:

- `enabled: false`
- `runtime_status: policy_paused`
- `policy_state: paused`
- `policy_reason_code`: usually `expired`, `failed`, `missing` or `pending_test`

Recovery options:

- Preview: `POST /api/security/connectors/{connector_id}/credentials/profiles/{profile_id}/policy-pauses/recover` with `{"mode":"preview"}`
- Clear pause metadata only: use `{"mode":"clear"}`
- Resume the schedule: use `{"mode":"enable"}`
- Manual enable: `POST /api/security/connectors/sync-schedules/{schedule_id}/enable`

If the credential is still blocking, recovery returns preview data and does not resume schedules.

## Operational Events

Events are stored in `security/connector-operations.json` and are available via:

`GET /api/security/connectors/operations/events`

Important event kinds:

- `credential_expiring_soon`: expiry monitor found a profile expiring within the configured window.
- `credential_expired`: expiry monitor found an already expired profile.
- `sync_blocked`: a sync run was blocked by the health gate.
- `schedule_policy_paused`: a schedule was paused by run policy.
- `credential_remediation_requested`: an operator or automation requested bulk remediation notification.

Events are deduplicated by kind and target context. Repeated monitor runs update `last_seen_at` and `seen_count`.

To acknowledge:

`POST /api/security/connectors/operations/events/{event_id}/ack`

## Bulk Remediation

Endpoint:

`POST /api/security/connectors/credentials/bulk-remediation`

Actions:

- `test`: tests all requested connector/profile pairs.
- `enable_schedules`: recovers policy-paused schedules for healthy profiles. Use `recovery_mode: enable`.
- `notify`: creates remediation-request operational events.

Bulk runs are retained in the operations registry for audit.

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

The monitor scans all profiles with `expires_at`, returns expired and soon-expiring matches, and optionally writes operational events.

## History Retention

- Blocked sync runs are retained in `security/connector-sync-runs.json`.
- Credential audit events are retained in `security/connector-credential-bindings.json`.
- Schedule pause and recovery audit events are retained in `security/connector-sync-schedules.json`.
- Operational notification and bulk remediation events are retained in `security/connector-operations.json`.

Recovery does not delete historical blocked runs. A later healthy run proves recovery while preserving prior evidence.
