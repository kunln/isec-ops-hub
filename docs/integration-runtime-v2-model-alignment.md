# Integration Runtime v2 Product-Sync Model Alignment

## 1. Background

iSecOps Hub currently has two related integration concepts that were introduced at different stages:

- The existing FLOCKS Device Integration flow handles product onboarding, connection configuration, connection testing, and tool invocation.
- Integration Runtime v2 introduces the standard data pipeline for sync planning, preview, confirmation-gated ingest, and run history.

Both concepts are necessary, but their relationship must be explicit. A user can already add a TDA product and verify its connection through Device Integration, while the later sync and ingest workflow depends on Runtime v2 objects such as an Integration Instance, Credential Profile reference, Sync Profile, and Integration Run. Without an alignment model, the same connected product could appear as two unrelated configurations, credentials could be duplicated, and product-specific code could bypass the Runtime boundary.

PR #55 aligned the frontend semantics: Sync on a product details page is the single-product view, while global Sync and Ingest is the cross-product configuration, preview, confirmation, and run-history view. The internal model now needs to support that unified experience.

This document defines the target relationship. It is an architecture and product-model decision for future bridge implementation; it does not replace existing Device Integration behavior or introduce runtime execution by itself.

## 2. User-Visible Model

Users should see one continuous workflow:

```text
Add product
  -> Test connection
  -> Configure sync
  -> Preview data
  -> Confirm ingest
  -> View run history
```

The user-facing concepts are:

- **Product access is the primary entry point.** Users begin by adding a security product and configuring its connection.
- **Sync and ingest are the data pipeline.** After a product is connected, users select what data to synchronize, preview normalized results, and explicitly confirm ingest.
- **Sync on a product details page is the single-product view.** It shows sync configuration, previews, confirmation actions, and runs scoped to that connected product.
- **Global Sync and Ingest is the global view.** It shows sync configuration, previews, confirmation actions, and run history across all connected products.

These views must present the same underlying product-sync relationship. They are different scopes over one workflow, not separate integration systems. Ordinary users should not need to understand or manually maintain Package, Instance, Credential Profile, Adapter, or other Runtime v2 technical objects.

## 3. Internal Object Model

The aligned internal model is:

```text
DeviceIntegration
  -> bridge mapping
  -> Integration Package + Integration Instance
       -> Credential Profile reference
       -> Sync Profile
            -> Integration Run
                 -> confirmed ingest -> Evidence / Alert
```

| Object | Responsibility | Relationship in the aligned model |
|---|---|---|
| `DeviceIntegration` | Product-access entry point; retains connection configuration, connection status, and tool capabilities. | The primary record from which an eligible connected product is bridged into Runtime v2. |
| Integration Package | Runtime v2 package definition containing product metadata, declared capabilities, authentication requirements, mappings, and optional adapter behavior. | Selected by the bridge from the connected product type; it is platform-managed rather than configured by an ordinary user. |
| Integration Instance | Runtime v2 runtime instance for one configured product environment. | Created or associated with one `DeviceIntegration`; it carries runtime metadata and references, not duplicated credential values. |
| Credential Profile | Credential reference and security boundary for runtime execution. | Initially points to the existing credential source; it must not copy or expose plaintext credentials. |
| Sync Profile | Synchronization configuration describing which data is synchronized from which connected product, with capability, parameters, cursor, and scheduling intent. | Belongs to the bridged Integration Instance and is managed through the product or global sync experience. |
| Integration Run | Auditable run record for plan, preview, confirmed ingest, and future scheduled sync stages. | Records bounded request, result, state, cursor, and item-reference summaries without long-term raw payload storage. |
| Evidence / Alert | Standardized Security objects created only after confirmation-gated ingest. | Downstream output of the Runtime and Evidence Pipeline; these objects are consumed by Security and Analysis rather than vendor responses being consumed directly. |

The relationship between `DeviceIntegration` and Integration Instance should be stable and idempotent: repeated bridge operations must associate the same connected product with the same runtime instance instead of creating duplicates. The bridge belongs to the Integration Layer and must not create Analysis Cases, Incidents, or response actions.

## 4. Recommended Architecture Route

Adopt the following route:

1. Keep `DeviceIntegration` as the primary product-access model and the source of the current connected-product experience.
2. Use Integration Runtime v2 as the downstream data synchronization and ingest pipeline.
3. Add an Integration Layer bridge that maps an eligible `DeviceIntegration` to its Integration Package and creates or associates an Integration Instance.
4. Let product-scoped and global sync views operate on the same bridged runtime objects while presenting task-oriented product language.
5. Pass only normalized Evidence Events into the Evidence Layer, and create Evidence / Alert records only through explicit confirmation-gated ingest.

This route preserves the five-layer architecture:

- The Integration Layer owns product connectivity, credentials, connection testing, synchronization, mapping, and Integration Runs.
- The Evidence Layer receives normalized evidence, provenance, hashes, bounded fields, and external references.
- The Analysis Layer consumes Evidence and Facts and never calls vendor APIs directly.
- The Operations Layer owns later human workflow, escalation, notification, and audit behavior.
- The future Response Layer remains approval-gated; no automatic remediation is introduced.

Do not adopt any of the following alternatives:

- Do not require ordinary users to create or maintain Runtime v2 technical objects manually.
- Do not replace the existing Device Integration product-onboarding flow with Runtime v2.
- Do not leave Device Integration and Runtime v2 as permanently separate systems with duplicate products, credentials, sync configuration, or run histories.

The bridge is an anti-corruption boundary between the existing product-access model and the Runtime v2 capability model. Vendor-specific mapping stays in an Integration Package or adapter; platform Runtime code should depend on packages and capabilities rather than product-specific branches.

## 5. Sync Semantics

In iSecOps Hub, **sync** means pulling or receiving security data from an already connected security product, then passing it through planning, preview, and explicit human confirmation before ingesting it as platform-standard objects.

The manual flow is:

```text
Connected product
  -> Sync Profile
  -> Plan
  -> Preview normalized data
  -> Human confirms ingest
  -> Evidence Pipeline
  -> Evidence / Alert
```

Sync is not:

- A connection test.
- A tool invocation.
- A device-health or connection-status refresh.
- Direct or automatic ingest without preview and human confirmation.

A plan or preview can create an Integration Run for auditability, but neither stage creates Evidence, Alert, Analysis Case, or Incident records. Confirm Ingest is a distinct, explicit action. Future scheduled synchronization may automate data retrieval and preparation, but it must not remove the confirmation gate unless a separately reviewed architecture decision changes that policy.

## 6. Credential Boundary

### Short term

- `DeviceIntegration` continues to hold the existing connection configuration under its current security controls.
- Runtime v2 references credentials through Credential Profile metadata or a secret reference; it does not duplicate credential values.
- The bridge must not read and persist, copy, serialize, log, or return plaintext tokens, API keys, secrets, or passwords.
- Runtime metadata, Integration Runs, preview data, and Security objects must contain no plaintext credentials.

### Long term

- Credentials should progressively move into a unified Credential Profile Store with an appropriate secret manager behind it.
- Both `DeviceIntegration` and Runtime v2 should reference the same credential profile rather than own separate credential values.
- Credential resolution remains an Integration Layer responsibility and must never move into Security or Analysis pages, APIs, or objects.

Credential migration must be staged and backward-compatible. Creating the bridge does not authorize a bulk credential migration or a change to the existing product-onboarding flow.

## 7. Phase-One Bridge Scope

A later implementation PR should provide a bridge skeleton with the following bounded scope:

- Identify `DeviceIntegration` products that have a supported Integration Package mapping and are eligible for bridging.
- Create or associate a Runtime v2 Integration Instance idempotently.
- Create or associate a Credential Profile reference without copying plaintext credential material.
- Support creating a Sync Profile for the connected product.
- Support at least the `alert.search` capability.
- Expose enough safe linkage metadata for the single-product and global sync views to resolve the same runtime objects.
- Add tests for mapping, idempotency, credential redaction, unsupported products, and layer boundaries.

The first bridge skeleton must not:

- Automatically ingest previewed data.
- Automatically create an Analysis Case or Incident.
- Perform automatic remediation or any destructive response action.
- Turn bridge creation itself into a vendor API call or a sync execution.

The skeleton should establish object identity and safe references first. Real connector-backed execution, scheduling, and broader capability support should remain separate, reviewable steps.

### Bridge Skeleton Implementation Notes

The first Device Integration bridge implementation is intentionally limited to
safe Runtime v2 reference creation:

- It reads a credential-free identity projection of a `DeviceIntegration`; the
  device credential/configuration fields are not selected, resolved, masked,
  copied, logged, or returned by the bridge.
- It maps supported TDA Device Integration identifiers to the existing
  `asiainfo.tda` Integration Package and exposes the initial
  `alert.search` capability association.
- The plan endpoint is always a dry run and does not modify Device Integration,
  Integration Instance, Credential Profile, Sync Profile, or Integration Run
  storage.
- Confirmed bridge creation writes an idempotent Integration Instance and a
  Credential Profile whose `secret_ref` points back to the existing Device
  Integration credential source. It does not migrate plaintext credentials.
- The bridge does not call a vendor API, connector, Adapter Registry, or
  Evidence Dispatcher. It performs no sync, preview, confirm ingest, Evidence
  or Alert creation, Analysis Case or Incident creation, notification, or
  remediation.
- No raw payload or full API response is retained, and bridge actions are not
  recorded as Integration Runs in this skeleton.
- Sync Profile creation from a connected product is implemented by the bounded
  metadata-only flow described below.

### Sync Profile from Connected Product Notes

- This flow creates Runtime v2 Sync Profile metadata only and requires an
  existing Device Integration bridge.
- It does not auto-bridge a product, execute synchronization, preview data,
  confirm ingest, call a vendor API, resolve an Adapter, or dispatch evidence.
- Manual mode is the default and only enabled mode in this phase. A schedule
  request is not started or persisted as an active schedule; scheduled
  execution remains a later step.
- Sync Profile identity is idempotent for the source Device Integration,
  bridged Runtime v2 Integration Instance, and capability.
- Params and generated metadata are validated against plaintext credential and
  authorization material. The Sync Profile references the bridged Instance and
  never reads or copies Device Integration fields or Credential Profile
  secrets.
- Plan is read-only. Confirmed creation does not create an Integration Run,
  Evidence, Alert, Analysis Case, Incident, Notification, or remediation.
- Preview and explicit Confirm Ingest remain later, separate Runtime actions.

## 8. Prohibited Design and Behavior

- The Analysis Layer must not call vendor APIs directly; it consumes Evidence and Facts with source references.
- Runtime v2 must not retain full raw payloads, raw logs, or complete API responses long term. Raw vendor data may exist transiently for mapping and hashing, then must be discarded.
- Confirm Ingest must require explicit human confirmation.
- The bridge must not copy or persist plaintext credentials.
- Ordinary frontend users must not be required to understand Package, Instance, Credential Profile, Adapter, or other Runtime implementation objects.
- Missing evidence must not be treated as proof that no abnormal activity exists. Negative Observations must state query scope, time range, data source, and limitations.
- AI conclusions must cite Evidence, Facts, Evidence Gaps, and source references as applicable.
- The current stage must not block, isolate, delete, disable accounts, modify firewall/WAF/EDR/IAM policies, or perform any other automatic response action.

## 9. Recommended Follow-Up PR Order

A. **Model alignment document** — establish the product model, object relationships, layer ownership, safety boundaries, and terminology.

B. **DeviceIntegration to Runtime v2 Instance Bridge Skeleton** — add idempotent package/instance mapping and reference-only credential linkage without sync execution.

C. **Create Sync Profile from Connected Product** — let the product-scoped and global views configure the same runtime sync metadata, beginning with `alert.search`.

D. **Scheduled Sync Skeleton v2** — add bounded scheduling and run-state behavior without automatic ingest, Incident creation, or remediation.

E. **Provider upstream backport** — backport the completed, tested provider-side changes after the local model and bridge boundaries are stable.

Each implementation PR should state its Architecture Layer Impact, Raw Data / Credential Safety, and Tests. Cross-layer coupling, automatic ingest, credential duplication, and long-term raw payload storage are out of scope for this sequence.
