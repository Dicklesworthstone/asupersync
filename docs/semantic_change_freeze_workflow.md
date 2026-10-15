# Semantic Change Freeze and Exception Workflow

Status: Active
Program: `asupersync-3cddg` (SEM-00)
Primary Bead: `asupersync-3cddg.1.2`
Normative Source: [`docs/semantic_harmonization_charter.md`](semantic_harmonization_charter.md)
Decision Thread: `coord-2026-03-02`

## 1. Purpose

This document operationalizes the charter freeze policy so semantic changes are
controlled, auditable, and deterministic while SEM phases are in flight.

The workflow is intentionally strict: semantic-affecting changes are frozen by
default and only proceed through the documented exception path.

## 2. Scope of the Freeze

### 2.1 Frozen change classes

The following are frozen outside approved SEM work items:

- Runtime semantic behavior changes that alter transition meaning, ordering,
  cancellation semantics, or obligation lifecycle interpretation.
- Contract/projection changes that would drift rule interpretation across
  runtime/docs/Lean/TLA.
- Ambiguity-resolving changes made without explicit rule ID references and
  supporting evidence.

### 2.2 Allowed without exception

The following are allowed when they do not change semantic meaning:

- Non-semantic refactors and editorial clarity updates.
- Tooling/formatting changes with no rule-level effect.
- Verification-only additions that preserve existing contract meaning.

When uncertain, treat the change as semantic and follow exception intake.

## 3. Exception Eligibility

Exceptions are for production-risk mitigation only.

A request qualifies only if all are true:

1. Deferring the change materially increases production or correctness risk.
2. No lower-risk operational mitigation exists.
3. The request includes explicit rollback or forward-fix strategy.
4. The requester commits to post-hoc ADR and traceability updates.

Non-qualifying requests should be deferred into the SEM dependency graph.

## 4. Approval Authority and SLA

Authority model aligns to charter governance rules:

- Runtime semantic authority: runtime-core maintainers (`SEM-GOV-001`).
- Formal projection authority: Lean/TLA owners (`SEM-GOV-002`).
- Tie-break: canonical contract text prevails until amended (`SEM-GOV-003`).

SLA targets:

- Critical conflict: triage within 24h, decision within 48h (`SEM-SLA-001`).
- High severity ambiguity: triage within 72h, decision within 5d (`SEM-SLA-002`).
- Medium discrepancy: triage within 7d, decision by next phase gate (`SEM-SLA-003`).
- Decision publication before dependent work continues (`SEM-SLA-004`).

## 5. Mandatory Exception Record

Every approved exception must include:

- Impacted rule IDs (`SEM-*`).
- Problem statement and risk classification (critical/high/medium).
- Alternatives considered and rejection rationale.
- Explicit rollback or forward-fix plan.
- Named owner and expiry/revisit timestamp.
- Bead IDs, thread IDs, and reproducible evidence pointers.
- Deterministic verification references from SEM verification fabric
  (`SEM-12`), including runner artifact locations and gate-result IDs.

## 6. Workflow

1. Intake
- Open/update bead with candidate change and impacted rule IDs.
- Post request in coordination thread with `ack_required=true`.

2. Triage
- Classify severity and confirm whether freeze applies.
- If no semantic impact, document rationale and proceed normally.

3. Decision
- Collect runtime + formal authority sign-off as required.
- Record decision and rationale in-thread and in bead notes.

4. Execution
- Implement minimal approved change surface.
- Preserve deterministic validation and evidence logging requirements.

5. Publication
- Publish decision outcome and evidence links before dependent beads proceed.
- Update relevant docs/beads with final rule references.

6. Closure
- Confirm rollback/forward-fix obligations are resolved.
- Mark exception closed or convert to tracked follow-up work.

## 7. Communication and Evidence Protocol

- All freeze/exception requests must use a thread tied to the active SEM
  coordination channel or the owning bead thread.
- `ack_required=true` is mandatory for requests needing active contributor
  alignment.
- Evidence pointers must be reproducible commands/artifacts, not narrative-only
  statements.
- Exception approvals must include deterministic verification artifacts (for
  example, SEM-12 runner summaries, gate IDs, and trace/log pointers) before
  dependent semantic work resumes.
- Active participant acknowledgement should be captured via Agent Mail acks and
  linked message IDs.

## 8. Operator Checklist

Before approving any semantic exception, verify:

- The request references concrete rule IDs.
- Severity/SLA classification is explicit.
- Owner and expiry are assigned.
- Rollback/forward-fix plan is concrete.
- Dependent beads and gating impact are listed.
- Deterministic evidence plan exists.

## 9. Mapping to SEM-01.2 Acceptance Criteria

- Published governance artifact: this document.
- Ownership + scope boundaries: Sections 2, 4, and 6.
- Escalation/exception process with SLA and records: Sections 3 through 6.
- Communication evidence and contributor alignment expectations: Section 7.
