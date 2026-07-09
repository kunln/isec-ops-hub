# iSecOps Hub Architecture Principles v1

## 1. Product and Core Boundary

- Product name: iSecOps Hub.
- Repository name: isec-ops-hub.
- Current internal Python package: flocks.
- FLOCKS is an internal technical foundation during migration, not the user-facing product identity.
- Do not rename the flocks Python package in normal feature PRs.
- User-facing UI, docs, menus, browser titles, and product copy should prefer iSecOps Hub.
- Future migration may introduce an isecops CLI/package alias, but it must be staged and backward-compatible.

## 2. Platform Positioning

iSecOps Hub is not a generic FLOCKS-style agent playground.

iSecOps Hub is an AI-native security operations product built on:

- Integration Runtime
- Evidence Pipeline
- Analysis Case / Fact Ledger
- Security Operations Workflow
- Future Response / Remediation Approval layer

FLOCKS provides reusable infrastructure:

- server
- auth
- storage
- tools
- workflows
- provider access
- commercial admin
- MCP / plugin capabilities

But iSecOps Hub product features must follow security-domain architecture boundaries.

## 3. Five-Layer Architecture

Every feature, API, data model, UI page, and automation path must be placed in the five-layer architecture before implementation.

### Layer 1: Integration Layer

Responsibilities:

- vendor/product integration
- API connectivity
- credential handling
- connection testing
- sync execution
- pagination/retry/rate-limit
- vendor response parsing
- lightweight normalization into Evidence Event
- Integration Runs

Must not:

- decide final incident truth
- generate final security verdicts
- own Analysis Case lifecycle
- store long-term raw logs
- expose credentials in Security pages

Terminology:

- Connector should be gradually replaced by Integration Package.
- Connector Runtime should be gradually replaced by Integration Runtime.
- Connector Runs should be gradually replaced by Integration Runs.
- Existing connector code may remain for compatibility.

### Layer 2: Evidence Layer

Responsibilities:

- Evidence Item
- Evidence Gap
- Fact Ledger
- source references
- payload hash
- provenance
- external event pointer
- negative observation
- evidence strength / coverage

Must not:

- connect to devices
- store API keys
- make final business notification decisions
- perform remediation

### Layer 3: Analysis Layer

Responsibilities:

- Analysis Case
- hypotheses
- verdict
- severity
- notification decision
- incident decision
- confidence
- reasoning summary
- initial analysis
- AI-assisted analysis

Must not:

- invent conclusions without evidence/facts
- store raw logs
- directly call vendor device APIs for credentials
- perform remediation

### Layer 4: Operations Layer

Responsibilities:

- case workflow
- assignment
- manual confirmation
- notification records
- incident escalation
- report generation
- audit trail
- SLA / queue future design

Must not:

- configure device credentials
- directly mutate security devices
- bypass Evidence / Fact Ledger

### Layer 5: Response Layer

Future layer.

Responsibilities:

- playbook
- approval
- remediation proposal
- human approval
- execution audit
- rollback

Current rule:

- iSecOps Hub current stage must not perform automatic remediation.
- No automatic blocking, isolation, account disabling, policy changes, deletion, or destructive response.
- Only design interfaces and audit boundaries for future response.

## 4. Information Architecture

### Integration Center / Device Integration

Current UI name may still be Device Integration, but target concept is Integration Center.

Responsible for:

- vendor/category based navigation
- integration packages
- integration instances
- credential profiles
- test connection
- sync now
- sync profiles
- integration runs / connector runs
- integration health

### Security Operations

Responsible for:

- dashboard
- assets
- alerts
- evidence
- analysis cases
- incidents
- notifications
- reports

Security Operations must not show:

- api_key
- secret
- token
- password
- base_url credential form for a specific product

If no integration is configured:

- Security may show empty state
- Security may guide user to Integration Center / Device Integration
- Security must not recreate the credential form locally

### AI Center

Future / existing AI settings may include:

- providers
- models
- prompts
- knowledge
- tools
- workflows

AI Center must not bypass evidence requirements.

### System / Commercial Admin

Responsible for:

- users
- roles
- license
- branding
- feature gates
- outbound policy
- audit logs

Community Edition connectivity:

- commercial outbound policy should only apply when licensed connectivity feature is enabled.
- community/unlicensed mode should not block normal development/provider/security connector/device tests.

## 5. Integration Runtime v2 Direction

Future target:

Integration Package should contain:

- manifest.yaml
- capabilities.yaml
- authentication spec
- mapping implementation or mapping rules
- fixtures
- README

Integration Runtime should provide:

- package loading
- capability registry
- authentication engine
- request execution
- retry
- timeout
- rate limit
- pagination
- response extraction
- mapping dispatch
- evidence event dispatch
- run history

Capabilities examples:

- alert.search
- event.search
- asset.search
- vulnerability.search
- weak_password.search
- ioc.search
- incident.search
- threat_intel.lookup

Vendor/product code should implement capabilities, not own the platform lifecycle.

For detailed runtime design, see docs/integration-runtime-v2.md.

## 6. Data Retention and Raw Log Boundary

- iSecOps Hub is not SIEM.
- iSecOps Hub is not a full log lake.
- Do not persist full raw logs or full raw API responses long term.
- Persist only:
  - normalized Alert
  - Evidence Item
  - Evidence Gap
  - Fact
  - Analysis Case
  - Incident
  - external references
  - payload_hash
  - bounded key_fields
  - Integration Run summaries
- Raw vendor response may be used temporarily in memory for mapping and hashing, then discarded.
- All customer-facing briefs, reports, and exports must pass through safe export/redaction utilities before including metadata, key_fields, raw_data, normalized_data, or evidence-derived details.
- Sensitive fields must be excluded:
  - api_key
  - secret
  - token
  - sign
  - password
  - login_password
  - login_password_encrypted
  - http_req_body
  - http_resp_body
  - full_content
  - packet
  - pcap payload

## 7. AI Safety and Evidence Discipline

- AI cannot confirm an incident without cited facts/evidence.
- Fact Ledger discipline requires analysis conclusions to distinguish supported facts, unsupported facts, cited evidence, uncited evidence, and open evidence gaps.
- AI-generated facts must be distinguished from human/system/vendor facts.
- False positive must cite contradiction/negative observations.
- Missing evidence is an Evidence Gap, not proof of absence.
- High-risk conclusions require human review.
- Current stage no automatic remediation.

## 8. PR Placement Rules

Every PR must answer:

- Which layer does this change belong to?
- Does it introduce cross-layer coupling?
- Does it put credentials into Security?
- Does it make Analysis call vendor APIs directly?
- Does it store raw logs?
- Does it create final verdicts without facts?
- Does it perform automatic remediation?
- Does it preserve existing flocks package compatibility?

If violated, PR should be rejected or redesigned.

## 9. Migration Rules

- Do not rename flocks package in normal PR.
- Do not break existing /api/security paths.
- Do not remove existing connector APIs abruptly.
- New user-facing copy should prefer iSecOps Hub.
- Connector terminology can remain in code for compatibility, but docs should introduce Integration terminology.
- Migration from Device Integration to Integration Center should be staged.
- Migration from Connector Runs to Integration Runs should be staged.

## 10. Short Decision Table

| Question | Correct Layer | Wrong Placement |
|---|---|---|
| Store TDA api_key | Integration | Security |
| Show Analysis Case verdict | Analysis/Security | Integration |
| Run TDA alert sync | Integration | Analysis |
| Display latest sync status | Integration, summarized in Security | Credential form in Security |
| Create Incident report | Operations | Integration |
| Auto block IP | Response future only | Current stage automatic action |
| Store full WAF request body | Nowhere long-term | Evidence raw storage |
