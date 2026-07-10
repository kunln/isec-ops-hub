# Integration Runtime v2 Design

## 1. Purpose

Integration Runtime v2 defines the target design for moving iSecOps Hub from scattered connector implementations toward a platform Integration Package system.

Goals:

- Upgrade current distributed connector implementations into a platform-level Integration Package architecture.
- Add new vendor products and services with minimal or no Runtime changes.
- Keep the Runtime focused on capabilities, not specific vendors or products.
- Encapsulate vendor/product differences inside packages.
- Make every package emit a unified Evidence Event.
- Keep Security and Analysis consuming only Evidence, Alerts, and Analysis Cases; they must not directly handle vendor APIs.
- Avoid long-term storage of complete raw logs or full API responses.
- Keep credentials out of Security pages.
- Avoid automatic remediation at the current stage.

## 2. Relationship with Current Code

The current codebase already has useful v1 foundations:

- `flocks/security/connectors/tda.py` and `flocks/security/connectors/mingyu_apt.py` are v1 lightweight connectors.
- `evidence_ingestion.py` is the Evidence Event ingestion foundation.
- `connector_runs.py` is the run history foundation.
- `/api/security/connectors/tda/*` and `/api/security/connectors/mingyu-apt/*` remain compatibility APIs.
- The Device Integration / Security Boundary Refactor is a UI-layer boundary correction that moves integration setup out of Security pages.
- v2 is a gradual migration, not a one-time replacement of the current implementation.

Current connector APIs remain supported during migration.

v2 introduces package/runtime abstractions above or beside existing code.

Do not delete existing v1 connectors until v2 parity exists.

## 3. Core Concepts

### Integration Package

An Integration Package is an installable package for a vendor product or service. It contains the product-specific implementation and metadata required by the Runtime.

Typical package contents:

- `manifest.yaml`
- `capabilities.yaml`
- `auth.yaml` or another authentication spec
- `mappings/`
- `fixtures/`
- `README.md`
- Optional Python adapter for complex scenarios that cannot be expressed declaratively

### Integration Instance

An Integration Instance is a user-configured instance of a package, such as `TDA-测试环境`, `明御APT-某客户`, or `微步账号A`.

Integration Instance metadata is stored in the persistent storage layer. The store still persists only instance metadata and `credential_profile_id` references; it does not store credential values, run test connections, run sync, call connectors, make HTTP requests, or create security objects.

Suggested fields:

- `instance_id`
- `package_id`
- `vendor`
- `product`
- `display_name`
- `environment`
- `base_url`
- `credential_profile_id`
- `verify_ssl`
- `enabled`
- `health_status`
- `created_at`
- `updated_at`

### Credential Profile

A Credential Profile is the Integration Layer skeleton that stores credential metadata and future secret references for an Integration Instance. It stores `secret_ref` and `configured_fields` field names only; it does not store credential values, return secrets, provide test connection behavior, call connectors, make HTTP requests, run sync, or create Security objects.

Suggested fields:

- `credential_profile_id`
- `display_name`
- `profile_type`
- `package_id`
- `instance_id`
- `secret_ref`
- `required_fields`
- `configured_fields`
- `expires_at`
- `status`

Plaintext credentials must not be stored in Security pages, Analysis Cases, Facts, Integration Run `item_refs`, Credential Profile metadata, or API responses.

### Capability

A Capability is the external ability declared by an Integration Package. The Runtime schedules and executes capabilities, not vendor-specific actions.

Examples:

- `alert.search`
- `event.search`
- `asset.search`
- `vulnerability.search`
- `weak_password.search`
- `plaintext_password.search`
- `ioc.search`
- `threat_intel.lookup`
- `incident.search`
- `report.fetch_metadata`

Capability is the Runtime scheduling unit.

### Integration Run

An Integration Run is one execution record for a capability.

Suggested fields:

- `run_id`
- `instance_id`
- `package_id`
- `capability`
- `mode`
- `status`
- `started_at`
- `finished_at`
- `request_summary`
- `result_summary`
- `error_summary`
- `item_refs`
- `cursor_before`
- `cursor_after`

`ConnectorSyncRun` is the v1 name. The v2 target name is `IntegrationRun`; during migration, the system may keep compatibility aliases or map v1 records into v2 terminology.

### Evidence Event

An Evidence Event is the standard lightweight event emitted by Integration Runtime into the Evidence Pipeline.

Suggested fields:

- `source_type`
- `package_id`
- `instance_id`
- `vendor`
- `product`
- `capability`
- `external_event_id`
- `title`
- `description`
- `severity`
- `asset_refs`
- `ioc_refs`
- `occurred_at`
- `key_fields`
- `payload_hash`
- `external_refs`
- `limitations`

An Evidence Event is not a full raw log or full raw API response.

## 4. Runtime Architecture

```text
Integration Center
  -> Integration Registry
  -> Integration Runtime
  -> Auth Engine
  -> Request Engine
  -> Pagination Engine
  -> Mapping Engine
  -> Evidence Dispatcher
  -> Evidence Pipeline
  -> Security Operations
```

### Integration Registry

The Integration Registry handles package discovery, manifest loading, capability indexing, version compatibility, package status, and validation. It is also the future home of Capability Registry behavior, where declared capabilities are indexed and made available to the Runtime.

### Auth Engine

The Auth Engine handles API key authentication, bearer tokens, basic auth, HMAC, cookie/session flows, future OAuth2 support, secret redaction, and header injection.

### Request Engine

The Request Engine handles HTTP execution, timeout behavior, `verify_ssl`, future proxy support, error normalization, response shape summaries, and the rule that full raw responses are not persisted long term.

### Pagination Engine

The Pagination Engine handles page/limit, offset/limit, cursor, scroll, next token, maximum page limits, and stop conditions.

### Mapping Engine

The Mapping Engine converts vendor responses into Evidence Events. It handles safe `key_fields`, sensitive field filtering, severity normalization, asset and IOC extraction, `payload_hash`, and evidence limitations.

### Sync Engine

The Sync Engine handles manual sync, future scheduled sync, incremental cursors, deduplication, retry, future dead letter handling, and IntegrationRun creation.

### Evidence Dispatcher

The Evidence Dispatcher sends Evidence Events to `evidence_ingestion`, creates normalized Alerts/EvidenceItems, and may optionally create an Analysis Case and initial analysis. It must never auto-create an Incident unless an explicit human-driven path says so.

## 5. Package Manifest Design

The following TDA `manifest.yaml` is an example package manifest. It illustrates the package shape; it does not hard-code TDA behavior into the Runtime.

```yaml
id: asiainfo.tda
name: 信桅高级威胁监测系统 TDA
vendor: AsiaInfo
product: TDA
version: "1.0.0"
category: security_monitoring
description: Lightweight security event integration for TDA.
auth:
  type: hmac_sha256
  fields:
    - api_key
    - secret
connection:
  base_url_required: true
  verify_ssl_default: false
capabilities:
  - alert.search
  - event.search
  - asset.search
  - weak_password.search
  - plaintext_password.search
retention:
  raw_response: transient_only
  raw_log_storage: forbidden
security:
  sensitive_fields:
    - api_key
    - secret
    - sign
    - login_password
    - login_password_encrypted
```

## 6. Capability Design

Capabilities may be declarative. Complex scenarios may use a Python adapter. Declarative configuration is preferred, and adapters are the fallback for vendor-specific behavior that cannot be represented safely in YAML.

Example `capabilities.yaml`:

```yaml
capabilities:
  alert.search:
    method: POST
    path: /ngtda/diagnosis/alert_list
    pagination: page_limit
    default_params:
      order: event_time
      order_direction: desc
    time_range:
      type: time_limit
      begin_param: begin
      end_param: end
    response:
      items_path:
        - data.alarm_list
        - data.list
        - alarm_list
    mapping: mappings/alert.yaml
```

A capability must not execute remediation actions unless a future Response Layer explicitly approves that class of action with approval and audit boundaries.

## 7. Mapping Design

Mapping is responsible for:

- Field extraction
- Severity normalization
- Asset extraction
- IOC extraction
- Time parsing
- `external_event_id` generation
- Safe `key_fields`
- Sensitive field dropping
- `payload_hash`

Example mapping:

```yaml
title:
  first_of:
    - threat_desc
    - rule_name
    - "TDA alert"
severity:
  normalize:
    field: severity
    map:
      超危: critical
      高危: high
      中危: medium
      低危: low
asset_refs:
  first_of:
    - victim_addr
    - dst
    - asset_addr
ioc_refs:
  collect:
    - src
    - dst
    - attacker_addr
    - domain
    - url
key_fields:
  allowlist:
    - merge_key
    - event_time
    - threat_desc
    - rule_name
    - src
    - dst
  denylist:
    - http_req_body
    - http_resp_body
    - login_password
    - login_password_encrypted
```

Mapping outputs an Evidence Event. It must not output plaintext passwords and must not persist the full original vendor payload long term. Mapping failures should produce an IntegrationRun error or EvidenceGap; the Runtime must not silently drop critical errors.

## 8. Authentication Design

Supported authentication types:

- `none`
- `api_key_header`
- `bearer_token`
- `basic`
- `hmac_sha256`
- `cookie_session`
- `oauth2_future`

### api_key_header

`api_key_header` injects a secret reference into a configured header name, such as `X-API-Key`. The header value is read from the Credential Profile secret reference at execution time, redacted from diagnostics, and never persisted in run history.

### hmac_sha256

`hmac_sha256` supports:

- Sign input template
- Timestamp source
- Digest algorithm
- Base64 and URL-safe options
- Padding option
- Header injection
- The rule that the secret is never persisted in run history

Example TDA HMAC authentication spec, based on the current understanding of TDA documentation. The final live connector behavior should still be verified against real devices during integration testing:

```yaml
auth:
  type: hmac_sha256
  fields:
    api_key:
      source: secret_ref
      required: true
    secret:
      source: secret_ref
      required: true
  timestamp:
    name: auth_timestamp
    source: unix_seconds
  sign:
    input_template: "{auth_timestamp}{api_key}"
    digest: sha256
    output: base64_urlsafe
    header: sign
  headers:
    api_key: "{api_key}"
    auth_timestamp: "{auth_timestamp}"
    sign: "{sign}"
  run_history:
    persist_secret: false
```

## 9. Pagination and Time Window Design

Pagination types:

- `none`
- `page_limit`
- `offset_limit`
- `cursor`
- `next_token`
- `scroll_future`

Time window types:

- Absolute `begin`/`end`
- Relative lookback
- Vendor-specific `time_type`/`time_limit`
- Cursor-based incremental sync

Manual sync uses explicit `begin`/`end` or lookback parameters. Scheduled sync uses cursor/checkpoint state. A cursor is not raw data and may be saved as durable checkpoint metadata.

## 10. Error Handling and Diagnostics

Error classifications:

- `auth_failed`
- `permission_denied`
- `network_timeout`
- `tls_error`
- `rate_limited`
- `api_error`
- `response_shape_changed`
- `mapping_error`
- `sensitive_data_detected`
- `partial_success`

`error_summary` must be redacted. It may store status code, endpoint path, and top-level message/code. It must not store the full response body. Diagnostics may store a response shape summary. The Live Test Fix Pack should rely on these diagnostics rather than raw response persistence.

## 11. Run History and Observability

IntegrationRun should record:

- Status
- Duration
- Counts
- Skipped duplicates
- Created alerts
- Created analysis cases
- Error count
- Request summary
- Result summary
- Item refs

IntegrationRun must not record:

- Secret
- Token
- Raw event
- Full response
- Request body containing sensitive fields

Current `ConnectorSyncRun` records are the v1 run-history foundation. Future `IntegrationRun` records should either migrate from `ConnectorSyncRun` or expose compatibility aliases until the v2 data model reaches parity.

## 12. Security Boundaries

- No raw log lake.
- No long-term raw API response storage.
- No credentials in Security.
- No automatic remediation.
- No direct vendor API call from Analysis.
- No final verdict without Evidence/Fact.
- No silent sensitive-field persistence.

## 13. Migration Plan

### Phase 0 Current v1

TDA/Mingyu lightweight connectors, Evidence Ingestion, ConnectorSyncRun, and Security/Device boundary corrected.

### Phase 1 Design and Compatibility

Add docs, introduce Integration terminology, and keep v1 APIs.

### Phase 2 Package Registry Skeleton

The initial skeleton is implemented as a built-in Integration Package Registry with static TDA and Mingyu APT package metadata. It does not change v1 connector behavior.

Add package registry data model, manifest parser, and static built-in packages for TDA/Mingyu with no behavior change.

### Phase 3 Capability Runtime

Implement `run(instance, capability, params)`, wrap TDA/Mingyu through the Runtime, and keep old endpoints as compatibility wrappers.

The first Capability Runtime skeleton validates package/capability requests, builds sanitized dry-run execution plans, and rejects destructive capabilities. It does not perform real HTTP requests, credential access, evidence ingestion, or v1 connector calls.

### Phase 4 Mapping Engine

Move mapping to declarative/adapter package definitions and add fixture validation.

The first Mapping Engine skeleton maps vendor-like dictionaries or fixtures into lightweight Evidence Events using declarative rules. It filters sensitive fields, drops raw payloads, normalizes severity, extracts assets/IOCs, and produces payload_hash without creating Alerts or Analysis Cases.

### Phase 5 Sync Engine

Add Sync Profile, scheduled sync, cursor/checkpoint, retry, and dead letter handling.

### Phase 6 Rename UX

Rename user-facing concepts from Device Integration to Integration Center and from Connector Runs to Integration Runs. User-facing docs should prefer Integration terminology; code-level connector compatibility remains.

## 14. Non-Goals

This design PR does not include:

- Immediate `flocks` package rename.
- Immediate removal of existing connector APIs.
- Full SIEM/log lake.
- Real automatic remediation.
- Real credential vault implementation in this PR.
- Full marketplace implementation in this PR.
- Scheduler implementation in this PR.

## 15. PR Checklist for Future Integration Work

- [ ] Which capability does this integration implement?
- [ ] Does it use Integration Runtime instead of product-specific UI where possible?
- [ ] Are credentials stored only in Integration/credential layer?
- [ ] Are raw responses transient only?
- [ ] Are sensitive fields filtered?
- [ ] Are Evidence Events generated?
- [ ] Are IntegrationRuns recorded?
- [ ] Are mapping fixtures provided?
- [ ] Does Security only consume normalized evidence?
- [ ] Is no automatic remediation performed?
