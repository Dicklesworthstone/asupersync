# Semantic Harmonization Charter and Invariant Baseline

Status: Active
Program: `asupersync-3cddg` (SEM-00)
Tasks: `asupersync-3cddg.1.1`, `asupersync-3cddg.1.3`, `asupersync-3cddg.1.4`
Scope Owner: Runtime Core maintainers + active SEM contributors
Published: 2026-03-02 UTC
Decision Record Thread: `coord-2026-03-02`

## 1. Purpose

This charter defines the governance boundary and non-negotiable semantic
baseline for the Semantic Harmonization Program. It is the operational source
used to align runtime behavior, documentation, Lean artifacts, and TLA checks
without moving targets during execution.

## 2. Program Scope

In scope:
- Canonical semantics definitions and rule IDs for runtime-critical behavior.
- Cross-artifact alignment work (runtime/docs/Lean/TLA) against one contract.
- Evidence-driven verification and anti-drift gates.

Out of scope:
- Feature-surface expansion unrelated to semantic harmonization.
- Backward-compatibility shims for superseded semantics.
- Ad hoc semantic edits that bypass SEM governance.

## 3. Goals and Non-Goals

Goals:
- `SEM-GOAL-001`: one canonical semantic contract with stable rule IDs.
- `SEM-GOAL-002`: deterministic, replayable evidence for semantic claims.
- `SEM-GOAL-003`: explicit ownership and escalation for unresolved ambiguity.
- `SEM-GOAL-004`: machine-checkable anti-drift gates in CI.

Non-goals:
- `SEM-NONGOAL-001`: optimize for historical API compatibility.
- `SEM-NONGOAL-002`: accept implicit behavior without contract text + evidence.
- `SEM-NONGOAL-003`: defer ambiguity resolution to undocumented tribal memory.

## 4. Non-Negotiable Invariant Baseline

These invariants are normative and must be referenced by downstream SEM work.

- `SEM-INV-001 Structured Ownership`:
  every task/fiber/actor is owned by exactly one region.
- `SEM-INV-002 Region Close Implies Quiescence`:
  region close completes only when no live children remain and all finalizers
  have finished.
- `SEM-INV-003 Cancellation Protocol`:
  cancellation is request -> drain -> finalize; each phase must be idempotent.
- `SEM-INV-004 Loser Drain`:
  race/join-style combinators must cancel and fully drain non-winning branches.
- `SEM-INV-005 No Obligation Leak`:
  permits/acks/leases are never silently dropped; each obligation is committed
  or aborted.
- `SEM-INV-006 No Ambient Authority`:
  effects are capability-scoped through `Cx`; no implicit authority flow.
- `SEM-INV-007 Deterministic Replayability`:
  equivalent seeded executions must produce replayable, explainable outcomes in
  lab/runtime verification paths.

## 5. Core Semantic Definitions

- `SEM-DEF-001 Determinism`:
  for a fixed contract version, seed, and ordered external stimuli, the runtime
  produces equivalent transition outcomes and diagnostics under replay.
- `SEM-DEF-002 Structured Concurrency Ownership`:
  no orphan tasks; ownership edges are explicit and auditable through regions.
- `SEM-DEF-003 Cancellation Correctness`:
  cancel requests cannot cause silent data loss; losers and in-flight cleanup
  are drained within bounded policy.
- `SEM-DEF-004 Obligation Lifecycle`:
  obligation state transitions are explicit (`reserve -> commit|abort`) and
  externally testable.

## 6. Governance and Decision Rights

- `SEM-GOV-001` Runtime semantics authority:
  runtime-core maintainers arbitrate code-level semantic interpretation.
- `SEM-GOV-002` Formal projection authority:
  Lean/TLA owners approve projection fidelity against canonical rule IDs.
- `SEM-GOV-003` Tie-break rule:
  if runtime/docs/formal artifacts diverge, canonical contract rule text wins
  until explicitly amended via the exception workflow below.
- `SEM-DBRD-001` Decision board composition:
  every blocking semantic decision must include at least one runtime-core
  maintainer and one verification/formal owner in the approval set.
- `SEM-DBRD-002` Quorum and closure:
  board decisions need two explicit approvals with no unresolved objection from
  any declared owner role before dependent beads may proceed.
- `SEM-DBRD-003` Recusal and conflict handling:
  reviewers with direct implementation ownership on disputed behavior must
  declare role context in-thread; unresolved conflict escalates per Section 8.
- `SEM-DBRD-004` Decision record minimum:
  decision records must capture rule IDs, chosen option, rejected alternatives,
  approvers, timestamp, and required follow-up beads.

## 7. Change Freeze and Exception Workflow

- `SEM-FRZ-001` Freeze:
  semantic-affecting edits outside the SEM dependency graph are frozen while
  SEM-01 through SEM-04 are in flight.
- `SEM-EXC-001` Emergency exception:
  allowed only for production-critical risk mitigation.
- `SEM-EXC-002` Required records for any exception:
  - impacted rule IDs
  - rationale + alternatives considered
  - rollback or forward-fix plan
  - owner and expiry
  - linked bead/thread evidence

## 8. Escalation and SLA

- `SEM-ESC-001` Severity classes:
  - `C0` critical correctness/safety risk (invariant violation risk live).
  - `C1` high-impact ambiguity blocking multiple SEM dependents.
  - `C2` medium discrepancy with bounded local blast radius.
- `SEM-SLA-001` Critical semantic conflict (`C0`):
  triage within 24 hours, decision within 48 hours.
- `SEM-SLA-002` High severity ambiguity (`C1`):
  triage within 72 hours, decision within 5 days.
- `SEM-SLA-003` Medium severity discrepancy (`C2`):
  triage within 7 days, decision window bounded by next SEM phase gate.
- `SEM-SLA-004` SLA clock start:
  starts at first explicit thread report that includes impacted rule IDs and
  blocking scope.
- `SEM-SLA-005` Breach handling:
  SLA breach requires explicit escalation post tagging board owners and opening
  a follow-up bead for root-cause and prevention actions.
- `SEM-SLA-006` Decision publication:
  outcomes must be recorded in thread + bead history before dependent tasks
  continue.

## 9. Evidence and Communication Requirements

- `SEM-EVD-001` Every semantic claim must include reproducible evidence pointers
  (tests, reports, traces, or formal checks).
- `SEM-EVD-002` Every resolved conflict must reference rule IDs + decision
  records.
- `SEM-COMM-001` Active contributors aligned thread:
  `coord-2026-03-02` and bead thread `asupersync-3cddg.1.1`.
- `SEM-COMM-002` Current active participant set (2026-03-02 refresh):
  `PurpleGorge`, `PearlCastle`, `SunnyStone`, `VioletHarbor`, `FrostyFox`,
  `BrightReef`.
- `SEM-COMM-003` Alignment evidence log:
  - `msg:3205` (`coord-2026-03-02`) kickoff to active contributors with
    acknowledgement required.
  - `msg:3206` and `msg:3209` contributor status confirmations from
    `SunnyStone` and `PearlCastle`.
  - `ack:3206` and `ack:3209` recorded by `PurpleGorge`, followed by explicit
    scope/no-overlap replies `msg:3214` and `msg:3215`.
  - `msg:3213` (`asupersync-3cddg.1.1`) start notice with claimed bead and
    reserved file surface.
- `SEM-COMM-004` Governance policy broadcast (`asupersync-3cddg.1.4`):
  - `msg:3233` (`br-asupersync-3cddg.1.4`) sent to active SEM contributors with
    `ack_required=true`, referencing charter + freeze workflow as normative.
- `SEM-COMM-005` Follow-up acknowledgement evidence:
  - `msg:3219` confirms post-`1.1` handoff and reservation release for
    downstream governance work.
  - `msg:3239` explicitly acknowledges the `1.4` governance-policy broadcast
    with no blocker concerns.
  - `msg:3226` + `msg:3234` capture freeze-workflow review acknowledgement and
    acceptance for active SEM execution.
  - `msg:3227` records explicit non-overlap confirmation between `1.2` and
    `1.3`/`1.4` governance workstreams.

## 10. Downstream Dependency Contract

Downstream SEM tasks must:
- reference relevant `SEM-INV-*` and `SEM-DEF-*` IDs in outputs;
- reference governance/board/escalation rules (`SEM-GOV-*`, `SEM-DBRD-*`,
  `SEM-ESC-*`, `SEM-SLA-*`) when decisions or conflicts are involved;
- declare any proposed semantic delta against this charter;
- include deterministic verification evidence before closure.

If a downstream task requires changing this charter, it must first land an
exception record under Section 7 and receive explicit governance approval.
