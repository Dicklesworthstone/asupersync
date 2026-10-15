# Global Optimal Semantic Profile Selection

Status: Active
Program: `asupersync-3cddg` (SEM-03.8)
Parent: SEM-03 Decision Framework and ADR Resolution
Author: SapphireHill
Published: 2026-03-02 UTC
Portfolio Reference: `docs/semantic_pareto_portfolio.md`

## 1. Selected Profile: P1 (Targeted Formal + Pragmatic)

**Composite score**: 0.83 (highest among all candidates)
**Pareto status**: Optimal — dominates P4, charter-compliant unlike P3

## 2. Profile Summary

### What We Prove (Formal)

| Artifact | What | ADR |
|----------|------|-----|
| LEAN combinator defs | Race, Join, Timeout as derived Step sequences | ADR-001, ADR-005 |
| LEAN LoserDrained | race_ensures_loser_drained theorem | ADR-001 |
| LEAN 3 laws | LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN | ADR-005 |

### What We Accept (Documented Abstractions)

| Artifact | What | ADR |
|----------|------|-----|
| TLA+ cancel propagation | No CancelPropagate/CancelChild actions | ADR-003 |
| TLA+ finalizers | No CloseRunFinalizer action | ADR-004 |
| TLA+ severity | Single "Completed" (no 4-valued outcome) | ADR-008 |
| LEAN/TLA+ capability | Not modeled (Rust type-system property) | ADR-006 |
| LEAN/TLA+ determinism | Not modeled (LabRuntime implementation property) | ADR-007 |

### What We Extend (Contract Policies)

| Area | Policy | ADR |
|------|--------|-----|
| CancelKind | 5 canonical + RT extension mapping | ADR-002 |

## 3. Rationale Bundle

### Why P1 Over P2 (Full Formal)

P2 requires proving capability and determinism in the formal model, which
is either impossible (capability requires dependent types) or impractical
(determinism requires scheduler refinement proof ~months). The marginal
safety gain (+0.08) does not justify the proof cost (+0.45 effort) and
maintenance overhead (+0.30).

### Why P1 Over P3 (Accept All)

P3 would leave SEM-INV-004 (loser drain) with no formal assurance. This
is a charter non-negotiable. The proof cost for the combinator layer
(~weeks) is justified by closing the single highest-impact gap (I4/C0).

### Why P1 Over P4 (TLA+ Focus)

P4 extends TLA+ for combinators and severity but does not add Lean proofs.
TLC model checking is bounded and cannot replace inductive proofs for
properties that must hold for arbitrary task counts. P1 dominates P4 on
all objectives.

## 4. Verification Evidence Summary

| Charter Invariant | Verification Layer | Evidence Level |
|-------------------|-------------------|----------------|
| SEM-INV-001 Ownership | LEAN: step_preserves_wellformed | Machine-checked proof |
| SEM-INV-002 Quiescence | LEAN: close_implies_quiescent | Machine-checked proof |
| SEM-INV-003 Cancel Protocol | LEAN: cancel_protocol_terminates | Machine-checked proof |
| SEM-INV-004 Loser Drain | LEAN: (planned) + RT oracle | Proof pending + runtime oracle |
| SEM-INV-005 No Obligation Leak | LEAN: commit_resolves + TLC | Machine-checked proof + model-checked |
| SEM-INV-006 No Ambient Authority | RT: Rust type system (CapSet) | Compile-time enforcement |
| SEM-INV-007 Determinism | RT: LabRuntime (seed-based) | Implementation + testing |

## 5. Publication

This profile selection is published for consumption by:
- SEM-03.9 (stress testing against adversarial scenarios)
- SEM-03.10 (adversarial scenario set construction)
- SEM-03.5 (final ratification)
- SEM-04 (canonical contract authoring)
