# Security Connector Release Checklist

Use this checklist before releasing connector credential health gate, schedule policy recovery and operational remediation changes.

## Tests

- Run connector backend tests:

```bash
.venv/bin/python -m pytest tests/security/test_security_connectors.py tests/security/test_security_routes.py -q
```

- Run the commercial admin WebUI build:

```bash
npm run build:commercial-admin
```

- For UI changes, run targeted WebUI tests:

```bash
npm test -- webui/src/pages/Security/index.test.tsx --runInBand
```

## Build

- Confirm `npm run build:commercial-admin` completes without TypeScript errors.
- Confirm generated assets do not require local-only absolute paths.
- Keep the local admin dev server pointed at the same mode when validating manually.

## Migration Compatibility

- Existing `security/connector-credential-bindings.json` files load with default `audit: []`.
- Existing `security/connector-sync-runs.json` files load with default `audit: []`.
- Existing `security/connector-sync-schedules.json` files load with default `audit: []`.
- New `security/connector-operations.json` is created lazily and does not require a migration.
- Clients that do not understand `reason_code`, `policy_reason_code` or operation events can continue reading older fields.

## Existing Schedule Impact

- Healthy enabled schedules keep running.
- Schedules only become `policy_paused` after a run is blocked by credential health.
- Policy-paused schedules have `enabled: false` and `next_run_at: null`.
- Recovery with `preview` is read-only.
- Recovery with `clear` removes pause metadata but does not enable schedules.
- Recovery with `enable` resumes matched schedules.

## Existing Credential Impact

- Profiles with no `expires_at` are ignored by the expiry monitor.
- Newly bound or rotated profiles remain `pending_test` until a test passes.
- `not_active` profiles do not block explicit syncs, but are reported so operators can activate them when needed.
- Expired or failed profiles can create operational events and blocked run history.

## Operational Alerting

- Run the expiry monitor with the desired warning window:

```bash
POST /api/security/connectors/credentials/expiry-monitor
```

- Confirm open events are visible:

```bash
GET /api/security/connectors/operations/events?status=open
```

- Confirm blocked syncs create `sync_blocked` events.
- Confirm policy-paused schedules create `schedule_policy_paused` events.
- Confirm bulk notification creates `credential_remediation_requested` events.

## Rollback

- Disable or pause affected schedules before rollback if they depend on newly rotated credentials.
- Restore the previous application version.
- Leave JSON registries in place. New fields are additive and old code should ignore unknown fields.
- If a rollback target cannot tolerate `connector-operations.json`, move that file aside; it is not required by credential, sync run or schedule registries.
- To manually resume ingestion after rollback, enable schedules only after confirming the active profile is healthy.

## Release Notes

Include:

- Credential health reason taxonomy.
- Schedule policy pause and recovery behavior.
- Operational event registry and expiry monitor.
- Bulk remediation actions.
- Blocked run retention policy.
- Runbook and API contract links.
