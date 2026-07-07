# Security Evidence Ingestion Architecture

## Principle: no long-term raw log storage

iSecOps Hub is not a SIEM, raw log platform, or log lake. Security Product API and MCP connector responses are treated as temporary inputs for immediate parsing, normalization, and evidence extraction only.

## What the platform stores long term

The Security Extension keeps investigation-ready records rather than complete raw telemetry:

- Alert summaries
- Analysis Case records
- Facts in the embedded Fact Ledger
- Evidence Items
- Evidence Gaps
- `notification_records`
- `confirmation_records`
- Incident records
- Report / Brief output

## What the platform does not store long term

The platform must not persist heavy raw event material such as:

- Full raw logs
- Large batches of raw API responses
- Full request body / response body text
- Full packet captures or process-tree snapshots
- Complete SIEM / EDR / NDR / WAF event streams

## How to retrieve original evidence

When analysts need to revisit the source system, iSecOps Hub should keep lightweight references that point back to the authoritative product, log platform, or MCP backend:

- `source_ref`
- `external_event_id`
- `external_url`
- `query_hint`
- `time_range_start` / `time_range_end`
- `connector_id`

These fields are sufficient to re-query original evidence without turning iSecOps Hub into a raw event store.

## Connector ingestion flow

```text
Security Product API / MCP
→ temporary raw response parsing
→ Evidence Summary / Evidence Reference fields
→ Alert
→ Analysis Case
→ Fact Ledger
→ Notification / Confirmation / Incident / Brief
```

Connector implementations may compute `payload_hash` values for consistency checks and de-duplication, and may store bounded `key_fields` for analyst context. `key_fields` must remain a compact subset and must not contain complete raw payloads.
