# AI Development Workflow

## Purpose

This workflow defines how users, GPT, and Codex Cloud collaborate on iSecOps Hub / FLOCKS Security Extension development. It keeps product direction, architecture review, implementation, and merge authority separated.

## Roles

### User

The user is responsible for direction and authority:

- Confirm product direction and priorities.
- Define responsibility boundaries and risk tolerance.
- Confirm whether a PR should be merged.
- Decide when business or security trade-offs are acceptable.
- Ensure current-stage scope remains focused on AI security incident confirmation and notification rather than automatic remediation.

### GPT

GPT is responsible for product and architecture thinking:

- Clarify requirements and identify ambiguity.
- Translate user goals into concrete task descriptions.
- Design workflows, domain models, and architecture boundaries.
- Review whether proposed changes fit the existing FLOCKS Security Extension.
- Review PRs from a business and architecture perspective.
- Ensure AI analysis requirements cite Facts, Evidence Gaps, and source references.
- Prevent scope creep into automatic blocking, isolation, account disabling, deletion, or policy changes during the current stage.

### Codex Cloud

Codex Cloud is responsible for implementation work in PRs:

- Implement requested changes on a branch.
- Update documentation and tests required by the task.
- Run appropriate checks and report results.
- Respond to GPT or user review comments.
- Keep changes inside the requested scope and avoid unrelated rewrites.

Codex Cloud must not directly change `main`. All work should be performed through pull requests.

## Pull Request Rule

All tasks should go through a PR. A PR should include:

- Clear summary of changes.
- Tests or checks performed.
- Known limitations or follow-up items.
- Explicit mention when no runtime behavior changed.

The user remains responsible for merge confirmation.

## Task Quality Requirements

Every task should include the following:

1. Background: why the change is needed.
2. Goal: what outcome is expected.
3. Boundary: what must not be changed.
4. Acceptance criteria: how the change will be judged.

For security-domain tasks, boundaries should explicitly state whether the task may touch business code, tests, frontend, configuration, connector behavior, or only documentation.

## Current-stage Security Boundary

The current stage does not implement automatic remediation. Tasks must not introduce real actions such as:

- Automatic blocking or banning.
- Host isolation.
- Account disabling.
- User deletion.
- Firewall, WAF, EDR, IAM, or routing policy changes.
- Any destructive or irreversible operational action.

Future remediation work may be designed as Remediation Action, Approval, and Audit concepts, but it should not become the mainline current-stage behavior.

## Architecture Guardrails

Development should preserve the existing architecture:

- Product name: iSecOps Hub.
- Repository name: `isec-ops-hub`.
- Internal platform name: FLOCKS.
- Python package name: `flocks`.
- Security APIs remain under `/api/security`.
- Permissions remain `security.ops.read` and `security.ops.write`.
- New security capabilities should prefer `flocks/security`, `flocks/server/routes/security.py`, `flocks/tool/security/security_ops.py`, `flocks/security/evidence_graph.py`, `flocks/security/connectors`, `webui/src/pages/Security/index.tsx`, and `webui/src/api/security.ts` before adding new structures.
- Analysis Case remains between Alert and Incident.
- Fact Ledger remains embedded in Analysis Case for the first stage.
