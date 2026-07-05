# Security Connector Standard

This document describes the first Security Extension connector standardization layer.

## Goal

Agents and workflows should depend on standardized security capabilities, not vendor-specific APIs.

The intended path is:

Agent / Workflow -> Security Capability Model -> Connector Adapter -> Vendor Product API

## Manifest

Every connector exposes a `ConnectorManifest`:

- `id`
- `vendor`
- `product`
- `product_version`
- `deployment`
- `auth_methods`
- `capabilities`
- `field_mapping`
- `severity_mapping`
- `status_mapping`
- `adapter_contracts`
- `mapping_contracts`
- `pagination`
- `rate_limit`
- `permissions`
- `risk_level`
- `raw_response`
- `normalized_data`
- `health_check`

## Capabilities

The initial capability vocabulary includes:

- `asset.search`
- `asset.get`
- `asset.sync`
- `vulnerability.search`
- `vulnerability.get`
- `vulnerability.sync`
- `alert.search`
- `alert.get`
- `alert.triage_context`
- `event.search`
- `event.timeline`
- `endpoint.query`
- `endpoint.process_tree`
- `traffic.query`
- `flow.query`
- `threat_intel.lookup`
- `honeypot.event.search`
- `case.create`
- `case.update`
- `notification.send`
- `report.generate`

Workflows must treat missing optional capabilities as evidence gaps, not fatal errors. For example, if a connector does not support `endpoint.process_tree`, the workflow should state that endpoint process-tree evidence is unavailable and continue with available alerts, assets, vulnerabilities, flow data, or honeypot events.

## Raw and Normalized Data

Connectors must preserve compact vendor payloads under `raw_data` or `raw_response`, then expose standardized `normalized_data`.

## Connector Mapping Contract v1

Connector Mapping Contract v1 moves vendor-field normalization into JSON configuration so new adapters can map real vendor responses without adding one-off Python normalizers.

Mapping files use the suffix `*.mapping.json`. For fixture replay they live under:

- `flocks/security/connectors/fixtures/fixture-replay-demo/mappings/asset.search.mapping.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/mappings/vulnerability.search.mapping.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/mappings/alert.search.mapping.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/mappings/honeypot.event.search.mapping.json`

Minimal shape:

```json
{
  "version": "connector.mapping.v1",
  "capability": "asset.search",
  "target": "assets",
  "source": { "items_path": "items" },
  "fields": [
    { "raw": "id", "target": "id", "required": true },
    { "raw": "name", "target": "name", "required": true },
    { "raw": "ip", "target": "ip", "required": true },
    {
      "raw": "criticality",
      "target": "importance",
      "default": "medium",
      "enum_default": "medium",
      "enum": { "low": "low", "medium": "medium", "high": "high", "critical": "critical" }
    },
    { "raw": "ports", "target": "open_ports", "default": [], "transform": "list" }
  ]
}
```

Field entries support:

- `raw`: Vendor field path. Dot paths are supported; `$` means the whole source item. A list of paths may be used for fallback lookup.
- `target`: Flocks standard object field.
- `required`: Reports missing required vendor fields in preview diagnostics.
- `default`: Value used when the vendor field is absent or empty.
- `enum`: Case-insensitive enum normalization map.
- `enum_default`: Fallback when an enum value is unknown.
- `transform`: Simple transform name, or `transforms` for an ordered list. V1 supports `copy`, `identity`, `string`, `strip`, `lower`, `list`, `dict`, `bool`, `int`, and `float`.

The mapping engine emits:

- `mapping_result`: Flocks normalized collection payload.
- `missing_required_fields`: Required raw paths missing from source items.
- `unmapped_fields`: Raw item fields not consumed by explicit mapping entries.
- `transform_warnings`: Enum and transform conversion warnings.

## Connector Adapter Runtime v1

Connector Adapter Runtime v1 fetches raw vendor payloads before they enter the mapping engine. It lets fixture replay and future real vendor adapters use the same contract shape:

`adapter contract -> raw response -> mapping contract -> normalized Flocks objects`

Adapter files use the suffix `*.adapter.json`. For fixture replay they live under:

- `flocks/security/connectors/fixtures/fixture-replay-demo/adapters/asset.search.adapter.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/adapters/vulnerability.search.adapter.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/adapters/alert.search.adapter.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/adapters/honeypot.event.search.adapter.json`

Fixture adapter shape:

```json
{
  "version": "connector.adapter.v1",
  "capability": "asset.search",
  "transport": "fixture",
  "fixture": { "path": "../assets_search.json" },
  "mapping": "../mappings/asset.search.mapping.json",
  "request": {
    "method": "GET",
    "path": "/assets/search",
    "auth": { "type": "none" }
  },
  "pagination": { "type": "fixture", "page_size": "all" }
}
```

HTTP adapter shape:

```json
{
  "version": "connector.adapter.v1",
  "capability": "asset.search",
  "transport": "http",
  "mapping": "../mappings/asset.search.mapping.json",
  "request": {
    "method": "GET",
    "base_url_env": "VENDOR_BASE_URL",
    "path": "/api/assets",
    "query": { "page": 1 },
    "headers": { "Accept": "application/json" },
    "auth": { "type": "bearer", "token_env": "VENDOR_TOKEN" }
  },
  "pagination": { "type": "none" }
}
```

V1 transports:

- `fixture`: Reads a local fixture JSON object and is safe for offline adapter and mapping validation.
- `http`: Builds and executes an HTTP request, parses a JSON object response, then passes it to mapping. V1 supports `none`, `bearer`, and `api_key_header` auth declarations, with secrets read from environment variables instead of hardcoded files.

Preview now returns adapter diagnostics as well as mapping diagnostics:

- `adapter_contract`
- `adapter_request`
- `raw_response`
- `mapping_result`
- `missing_required_fields`
- `unmapped_fields`
- `transform_warnings`

Validation entrypoints verify adapter and mapping contracts without writing Security Extension business objects:

- `POST /api/security/connectors/{connector_id}/validate`
- `security_connector_validate`

## Connector Package Loader v1

Connector Package Loader v1 makes connector registration data-driven. A connector package is a directory with a `manifest.json` file plus adapter and mapping contracts:

```text
<connector-id>/
  manifest.json
  adapters/
    asset.search.adapter.json
  mappings/
    asset.search.mapping.json
```

Default discovery roots are loaded in this order:

- Built-in fixtures: `flocks/security/connectors/fixtures/<id>/manifest.json`
- User packages: `~/.flocks/connectors/<id>/manifest.json`
- Workspace packages: `<workspace>/.flocks/connectors/<id>/manifest.json`

When the same connector id appears in multiple roots, the later root wins. This keeps built-in examples available while allowing user-level and project-level packages to override them without Python code changes.

Package manifest shape:

```json
{
  "version": "connector.package.v1",
  "id": "fixture-replay-demo",
  "name": "Fixture Replay Demo Connector",
  "vendor": "Flocks",
  "product": "Fixture Replay",
  "product_version": "2026.06",
  "deployment": "local_fixture",
  "auth_methods": ["none"],
  "capabilities": ["asset.search"],
  "adapters": {
    "asset.search": "adapters/asset.search.adapter.json"
  },
  "pagination": { "type": "fixture", "page_size": "all" },
  "rate_limit": { "mode": "offline", "requests_per_minute": null },
  "permissions": ["fixture:read"],
  "risk_level": "low",
  "description": "Offline fixture replay connector.",
  "enabled": true
}
```

The loader validates that:

- The package uses `connector.package.v1`.
- Each declared capability has an adapter.
- Each adapter declares the same capability as the package entry.
- Each adapter points to a mapping contract.
- Each mapping declares the same capability as the package entry.

The registry still exposes each loaded package as a normal `ConnectorManifest`. Runtime package manifests include the managed `package_root`, adapter file paths, mapping file paths, contract summaries and generated `field_mapping` data. The original source package path is retained in the installed registry for diagnostics and audit.

Package diagnostics are available separately from connector registration. They scan every package root, report invalid manifests without registering them, and show static adapter/mapping contract checks plus fixture validation warnings:

- Root source and existence.
- Package manifest path, id, active/shadowed state and status.
- Adapter and mapping file existence and summaries.
- Manifest, adapter, mapping and runtime validation errors.
- Fixture replay warnings such as missing required mapped fields.

Invalid packages are skipped during registry initialization so one broken local package does not make the connector list unavailable.

## Connector Package Install / Activation v1

Connector packages are no longer registered into the runtime simply because they are discoverable. Discovery and diagnostics remain read-only; runtime registration is controlled by an installed package registry.

Install flow:

- `Install` accepts a local connector package directory.
- The package manifest, adapter contracts and mapping contracts are validated first.
- The package tree is copied into the managed install store at `security/connectors/installed/<package-id>/<version>-<hash-prefix>`.
- The installed registry records package id, display metadata, package/product version, managed package hash, manifest snapshot, source path, managed install path, install time and the last validation result.
- Installed packages start disabled unless the caller explicitly requests enable-on-install.

Activation flow:

- `Enable` re-checks the managed package hash and validates the installed package copy before loading it.
- The connector registry loads only enabled installed packages whose current package hash matches the installed hash.
- Disabled, uninstalled, missing or hash-changed managed copies are not registered, so preview/test/sync/adapter execution cannot run through that package id.
- `Disable` removes the package from runtime registration without deleting install history.
- `Uninstall` removes the active installed record and appends a history/audit snapshot.

Managed store and rollback flow:

- Runtime is bound to the managed install path, not the original source directory. The source path is kept only for diagnostics and audit.
- Reinstalling a package version/hash moves the previous active record into install history.
- `Rollback` restores the latest history record whose managed copy still exists and whose hash still matches the recorded hash.
- Rollback re-validates and re-enables the restored managed copy. If validation fails, the package remains unavailable for runtime execution.
- Install and rollback audit entries are retained even after uninstall.

Diagnostics now merge discovered package state with installed package state:

- Discovered package validity and shadowing status.
- Installed version, installed hash and install time.
- Runtime status such as `not_installed`, `disabled`, `enabled`, `stale_source`, `installed_missing`, `missing`, `invalid` or `installed_elsewhere`.
- Last validation result stored at install/enable time.
- Rollback availability based on restorable managed install history.

Lifecycle APIs:

- `POST /api/security/connectors/packages/install`
- `POST /api/security/connectors/packages/{package_id}/enable`
- `POST /api/security/connectors/packages/{package_id}/disable`
- `POST /api/security/connectors/packages/{package_id}/rollback`
- `DELETE /api/security/connectors/packages/{package_id}`

## Package Upload / Staging Validation v1

Uploaded connector packages enter a staging store before they can affect runtime. Staging accepts `.zip`, `.tar.gz`, and `.tgz` artifacts.

Upload and staging flow:

- `Upload` stores the archive under `security/connectors/staging/<staging-id>/artifact/`.
- The archive is extracted under `security/connectors/staging/<staging-id>/extract/`.
- Extraction rejects path traversal, symlinks, unsupported archive entries, unsupported archive types, too many archive entries, over-large upload artifacts, and over-large expanded trees.
- A staged artifact must contain exactly one connector package manifest, either at archive root or under one top-level package directory.
- Staging records filename, archive format, artifact size, artifact hash, extracted package root, package hash, upload time and validation result.

Validation flow:

- Staging validation loads the staged package manifest, adapter contracts, mapping contracts and fixture previews.
- Invalid staged packages stay in the staging registry with validation errors so the UI can show why installation is blocked.
- `Install from staging` is allowed only when the latest staging validation succeeded and the staged package hash still matches the validation-time hash.
- Installing from staging still copies the package into the managed install store; runtime never executes directly from the staging directory.
- Installed records created from staging retain upload filename, artifact hash, archive format, staging id and validation time as source metadata.
- `Discard` removes the extracted staging files and the active staging record while preserving staging audit events.

Package Diagnostics now also includes staging registry summary and staged package records so the WebUI can show upload, validate, install and discard controls in the same connector lifecycle panel.

## Connector Live Data Pipeline v1

Installed and enabled connector packages can now participate in the Security Extension data plane. The core runtime path is:

`credential binding -> adapter env -> preview -> mapping result -> Security Store sync -> sync run audit`

Credential binding:

- Connector credentials are bound by connector id and stored in `security/connector-credential-bindings.json`.
- Sensitive keys such as token, key, secret, password and credential values are written through the Flocks secret manager; diagnostics return masked values and metadata, not plaintext.
- Non-sensitive values such as tenant id or base URL can be retained directly in the binding registry.
- Deleting a credential binding stops future adapter previews and syncs from receiving those environment values.

Runtime binding:

- Package adapter runtime receives bound credential values as the adapter environment for the matching connector id.
- HTTP adapters continue to declare `base_url_env`, `token_env` or API-key env names in adapter contracts; the runtime supplies those values from the credential binding instead of requiring hardcoded files.
- Runtime loading still depends on the enabled installed package registry. Disabled, uninstalled or invalid packages cannot execute preview, sync or adapter calls.

Sync flow:

- `Sync` runs connector preview for a selected capability, then writes mapped results into the Security Store.
- V1 supports mapped targets for `assets`, `vulnerabilities`, `alerts` and `honeypot_events`.
- Synced objects retain connector sync metadata under `raw_data.connector_sync` and `normalized_data.connector_sync`, including connector id, capability, sync run id and source.
- Sync is inbound only. It does not perform vendor-side blocking, isolation, remediation or case mutations.

Sync audit:

- Sync run records are stored in `security/connector-sync-runs.json`.
- Each run records connector id, capability, status, object counts, object ids, warnings, errors, start/end time and duration.
- Status can be `success`, `partial` or `error`; partial runs preserve successful writes while surfacing per-object errors.

Package diagnostics and the WebUI now surface credential binding state, installed/runtime status, latest validation result and recent sync runs in the connector lifecycle panel.

## Connector Incremental Sync + Evidence Quality v1

Incremental Sync + Evidence Quality v1 turns connector sync into a resumable, quality-gated ingestion path.

Sync mode:

- `full` runs the selected capability and evaluates every mapped item.
- `incremental` uses the stored connector/capability cursor to skip items whose source timestamp is older than or equal to the cursor.
- `reset_cursor` clears the selected connector/capability cursor before the run.
- Cursor state is stored in `security/connector-sync-runs.json` under `cursors`.

Source identity and dedup:

- Each synced item receives `source_system`, `source_object_id`, `source_fingerprint` and `source_timestamp`.
- The source fingerprint is stable for the connector id, capability, target and vendor object identity.
- If a mapped item has no Flocks id, sync assigns a deterministic connector-derived id from the fingerprint.
- If an existing object already has the same source fingerprint, sync reuses that object id to keep writes idempotent.

Evidence envelope:

- Synced objects receive `connector_evidence` under both `raw_data` and `normalized_data`.
- The envelope records connector id, capability, target, sync run id, sync mode, source system, source object id, source fingerprint, source timestamp, ingest time, confidence, quality status and raw reference.
- `connector_sync` is still retained as compact operational metadata for existing UI and workflow consumers.

Quality gate:

- Mapping-contract required field misses are treated as invalid items.
- Pydantic domain validation failures are treated as invalid items.
- Invalid items are not written to the Security Store.
- Items that pass validation but lack recommended evidence such as source timestamp are written as `partial`.
- Items with source identity and timestamp and no item diagnostics are written as `complete`.

Dead-letter:

- Invalid mapped items are stored in `security/connector-sync-runs.json` under `dead_letters`.
- Each dead-letter record includes run id, connector id, capability, target, item index, errors, warnings, evidence and the rejected payload.
- Sync run status is `partial` when at least one item is rejected while other items are written.

Sync run records now include sync mode, cursor before/after, cursor update flag, skipped counts, quality summary, object ids and dead-letter count.

## Connector Scheduler + Run Orchestration v1

Connector Scheduler + Run Orchestration v1 makes enabled connector syncs run continuously without requiring an operator to click `Sync` every time.

Schedule registry:

- Sync schedules are stored in `security/connector-sync-schedules.json`.
- Each schedule is scoped to one connector id and one capability.
- Schedule records include enabled state, interval seconds, sync mode, optional full-sync interval, retry settings, timeout, next run time, last run status, last successful run, last failed run and consecutive failure count.
- Package diagnostics exposes schedule counts, enabled schedule counts, due schedule counts and per-schedule runtime status.

Run orchestration:

- The orchestrator runs schedules through the existing connector sync runtime, so cursor, evidence, quality and dead-letter behavior remain unchanged.
- One in-process lock is held per connector/capability schedule id. A second run for the same schedule returns `busy` instead of starting duplicate adapter calls.
- `Run now` can execute a disabled schedule manually; scheduled ticks skip disabled schedules.
- The background scheduler starts with the server and periodically runs due schedules.
- `Tick` executes currently due schedules once and is useful for tests, diagnostics and manual operations.

Retry and timeout:

- Each run attempt has a configurable timeout.
- Error runs can retry up to `retry_max_attempts`.
- Retry wait uses `retry_backoff_seconds * attempt`.
- Only `error` runs increment consecutive failure count. `partial` runs are treated as successful ingestion with degraded quality because they may still write valid evidence while retaining invalid items as dead-letter records.

Credential Health Gate + Connector Run Policy v1:

- Credential health is evaluated before sync preview or adapter execution.
- Credential health exposes a stable `reason_code` taxonomy for UI, audit and alert consumers: `expired`, `failed`, `missing`, `pending_test`, `not_active`, `not_configured` and `healthy`. The long-form `reason` remains for backward-compatible integrations.
- Credential profiles with runtime status `expired`, `failed`, `missing` or `pending_test` block sync. `not_active` is non-blocking and prompts activation when the profile should become the default.
- Connectors without configured credential profiles remain eligible so local fixture and no-auth connectors continue to work.
- Blocked syncs are persisted in `security/connector-sync-runs.json` with `status: blocked`, `source: credential_health_gate`, `credential_health`, `run_policy` and a `connector_sync.blocked` audit event.
- A blocked run never writes Security Store objects, never advances cursors, and records remediation actions such as bind, test, rotate, or activate profile.
- Blocked run history is retained for audit. Credential repair and schedule recovery create later non-blocked runs; they do not delete prior blocked run records. Demo or validation-only profiles should be removed from credential bindings and schedules, while blocked run history remains available for audit interpretation.
- Scheduled runs that hit the gate are treated as policy failures. The schedule is set to `enabled: false`, `runtime_status: policy_paused`, `policy_state: paused`, and carries `policy_reason`, `policy_reason_code`, `policy_message`, `policy_actions`, and `policy_paused_at`.
- Schedule policy recovery supports `preview`, `clear` and `enable` modes. `preview` returns candidates for UI confirmation, `clear` removes policy pause metadata without enabling the schedule, and `enable` clears policy pause metadata and resumes the schedule.
- Re-enabling or reconfiguring a schedule clears policy pause metadata; if the credential problem still exists, the next run pauses it again. Manual enable and recovery modes emit `policy_recovered` audit events.
- Audit trails cover credential `test` and `rotate`, sync `blocked`, schedule `policy_pause`, manual `enable`, and schedule `policy_recovered` events.
- Package diagnostics includes blocked run and policy-paused schedule counts so the WebUI can surface degraded background ingestion clearly.

Connector Operations v1:

- Operational events are stored in `security/connector-operations.json` and exposed through `GET /api/security/connectors/operations/events`.
- Event kinds include `credential_expiring_soon`, `credential_expired`, `sync_blocked`, `schedule_policy_paused` and `credential_remediation_requested`.
- `POST /api/security/connectors/credentials/expiry-monitor` scans credential profiles with `expires_at` and can create expiring or expired events before sync is blocked.
- `POST /api/security/connectors/credentials/bulk-remediation` supports bulk `test`, `enable_schedules` and `notify` actions across connector/profile pairs.
- Package diagnostics includes connector operation event and open event counts.
- Operator guidance lives in `docs/security-connector-operator-runbook.md`; API field semantics live in `docs/security-connector-api-contract.md`; release checks live in `docs/security-connector-release-checklist.md`.

Operational status:

- Schedule status includes `enabled`, `disabled`, `running` or `policy_paused`.
- Schedule health includes next run time, last status, last mode, last trigger, last duration and consecutive failure count.
- The WebUI shows schedule status next to connector sync status and supports configure, enable, pause and run-now actions.

## Cross-Connector Entity Resolution + Evidence Graph v1

Cross-Connector Entity Resolution + Evidence Graph v1 turns synced connector objects into a shared analysis graph.

Graph registry:

- The graph snapshot is stored in `security/connector-evidence-graph.json`.
- The graph version is `connector.evidence.graph.v1`.
- The snapshot includes nodes, edges, asset entities, merge candidates, conflicts and indexes.
- Package diagnostics exposes graph node, edge, entity and conflict counts.

Entity resolution:

- V1 resolves asset entities across connectors by stable identity keys: IP, hostname, domain, cloud resource id, instance id, serial number and MAC address.
- Assets that share one or more identity keys are grouped under a canonical `entity:asset:*` node.
- Source-specific connector fingerprints are retained for ingestion idempotency, but cross-connector grouping is based on shared asset identity keys.
- The resolver emits merge candidates instead of automatically overwriting user-maintained asset fields.

Evidence graph:

- Asset, vulnerability, alert, incident and honeypot records become object nodes.
- Alert IOC values and honeypot source/target IP values become indicator nodes.
- Edges capture relationships such as `same_entity_as`, `affects`, `observed_on`, `contains_ioc`, `resolves_to`, `involves` and `uses_evidence`.
- Edges preserve connector evidence where available, including connector id, capability, sync run id, source object id, source fingerprint and source timestamp.

Conflict detection:

- V1 detects asset-field conflicts for importance, exposure level, environment, business owner and business system.
- Conflicts are reported as unresolved records with field, values, asset ids, sources and severity.
- No automatic merge or rollback is performed in V1.

Object annotations:

- Rebuild writes `normalized_data.evidence_graph` back to Security Store objects.
- Object annotations include graph version, node id, entity ids, edge ids, related node ids, merge candidate ids, conflict ids and rebuild time.
- Connector sync automatically rebuilds the graph after non-error runs; manual rebuild is also available through API, tool and WebUI.

The MVP includes `mock-security-demo`, a local connector that performs no external network calls. It validates:

- Manifest rendering.
- Capability declaration.
- Test connection behavior.
- Raw-to-normalized mapping for assets, vulnerabilities, alerts, and honeypot events.

The MVP also includes `fixture-replay-demo`, a local fixture replay connector. Fixture files live under:

- `flocks/security/connectors/fixtures/fixture-replay-demo/manifest.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/assets_search.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/vulnerabilities_search.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/alerts_search.json`
- `flocks/security/connectors/fixtures/fixture-replay-demo/honeypot_events_search.json`

Replay preview returns:

- Raw fixture response.
- Mapping result / normalized domain payload.
- Missing required fields.
- Unmapped fields.
- Transform warnings.
- Missing capability downgrade result when a capability is not declared.

Preview does not write to the Security Extension object store.

## API

- `GET /api/security/evidence-graph`
- `POST /api/security/evidence-graph/rebuild`
- `GET /api/security/connectors`
- `GET /api/security/connectors/package-diagnostics`
- `POST /api/security/connectors/packages/install`
- `GET /api/security/connectors/packages/staging`
- `POST /api/security/connectors/packages/staging/upload`
- `POST /api/security/connectors/packages/staging/{staging_id}/validate`
- `POST /api/security/connectors/packages/staging/{staging_id}/install`
- `DELETE /api/security/connectors/packages/staging/{staging_id}`
- `POST /api/security/connectors/packages/{package_id}/enable`
- `POST /api/security/connectors/packages/{package_id}/disable`
- `POST /api/security/connectors/packages/{package_id}/rollback`
- `DELETE /api/security/connectors/packages/{package_id}`
- `GET /api/security/connectors/credential-bindings`
- `GET /api/security/connectors/sync-runs`
- `GET /api/security/connectors/sync-cursors`
- `GET /api/security/connectors/sync-dead-letters`
- `GET /api/security/connectors/sync-schedules`
- `GET /api/security/connectors/sync-schedules/{schedule_id}`
- `POST /api/security/connectors/sync-schedules/{schedule_id}/enable`
- `POST /api/security/connectors/sync-schedules/{schedule_id}/disable`
- `POST /api/security/connectors/sync-schedules/{schedule_id}/run`
- `DELETE /api/security/connectors/sync-schedules/{schedule_id}`
- `GET /api/security/connectors/scheduler/status`
- `POST /api/security/connectors/scheduler/tick`
- `GET /api/security/connectors/{connector_id}`
- `GET /api/security/connectors/{connector_id}/capabilities`
- `PUT /api/security/connectors/{connector_id}/credentials`
- `GET /api/security/connectors/{connector_id}/credentials`
- `DELETE /api/security/connectors/{connector_id}/credentials`
- `POST /api/security/connectors/{connector_id}/preview?capability=asset.search`
- `POST /api/security/connectors/{connector_id}/sync`
- `POST /api/security/connectors/{connector_id}/sync-cursor/reset`
- `PUT /api/security/connectors/{connector_id}/sync-schedule`
- `POST /api/security/connectors/{connector_id}/validate`
- `POST /api/security/connectors/{connector_id}/test`

## Tools

- `security_connector_list`
- `security_connector_package_diagnostics`
- `security_connector_package_install`
- `security_connector_package_stage_upload`
- `security_connector_package_stage_validate`
- `security_connector_package_stage_install`
- `security_connector_package_stage_discard`
- `security_connector_package_enable`
- `security_connector_package_disable`
- `security_connector_package_rollback`
- `security_connector_package_uninstall`
- `security_connector_credentials_bind`
- `security_connector_credentials_list`
- `security_connector_sync`
- `security_connector_sync_runs`
- `security_connector_sync_cursors`
- `security_connector_sync_cursor_reset`
- `security_connector_sync_dead_letters`
- `security_connector_sync_schedule_upsert`
- `security_connector_sync_schedules`
- `security_connector_sync_schedule_run`
- `security_connector_sync_schedule_enable`
- `security_connector_sync_schedule_disable`
- `security_connector_sync_schedule_delete`
- `security_connector_sync_scheduler_tick`
- `security_evidence_graph_get`
- `security_evidence_graph_rebuild`
- `security_entity_resolution_candidates`
- `security_connector_get`
- `security_connector_test_connection`
- `security_connector_list_capabilities`
- `security_connector_preview`
- `security_connector_validate`

The first phase does not create real blocking, isolation, or remediation actions against vendor systems.
