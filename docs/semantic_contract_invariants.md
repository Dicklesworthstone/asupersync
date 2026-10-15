# Invariants and Laws with Checkable Clauses (SEM-04.4)

**Bead**: `asupersync-3cddg.4.4`
**Parent**: SEM-04 Canonical Semantic Contract (Normative Source)
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_contract_transitions.md` (SEM-04.3, transition rules)
- `docs/semantic_contract_glossary.md` (SEM-04.2, canonical terms)
- `docs/semantic_contract_schema.md` (SEM-04.1, rule-ID namespace)

---

## 1. Purpose

This document specifies every invariant, progress property, and algebraic law
in the semantic contract as a formal checkable clause. Each clause is verifiable
by at least one enforcement layer (LEAN proof, TLA+ model check, RT test, or
Rust type system).

---

## 2. Notation

```
INV <rule-id>: <name>
  CLAUSE:     <formal property in predicate form>
  SCOPE:      <which states/transitions the property constrains>
  CHECK:      <how to verify — proof/model-check/test/type-system>
  VIOLATIONS: <what happens if this is violated>
  ADR:        <applicable ADR reference, if any>
```

---

## 3. Structural Invariants

### INV #33: `inv.ownership.single_owner`

```
INV inv.ownership.single_owner
  CLAUSE:  ∀ task T: |{R : R.tasks ∋ T}| = 1
           (Every task belongs to exactly one region)
  SCOPE:   All reachable states
  CHECK:   LEAN (proved), TLA (modeled: TypeInvariant), RT (enforced by TaskEntry.region_id)
  VIOLATIONS: Double-ownership → double-cancel, double-free, use-after-complete
```

### INV #34: `inv.ownership.task_owned`

```
INV inv.ownership.task_owned
  CLAUSE:  ∀ task T: ∃ region R: T ∈ R.tasks
           (No orphaned tasks)
  SCOPE:   All reachable states from Spawned through Completed
  CHECK:   LEAN (proved), TLA (modeled), RT (enforced by spawn requiring RegionHandle)
  VIOLATIONS: Orphaned task → leaked resources, no cancel propagation
```

### INV #27: `inv.region.quiescence`

```
INV inv.region.quiescence
  CLAUSE:  region.state = Closed →
             (∀ T ∈ region.tasks: T.state = Completed) ∧
             (∀ O ∈ region.obligations: O.state ∈ {Committed, Aborted})
  SCOPE:   Region terminal state
  CHECK:   LEAN (proved), TLA (checked: SafetyInvariant), RT (is_quiescent() check)
  VIOLATIONS: Closing with active tasks → deadlock. Closing with pending obligations → leak.
```

### INV #5: `inv.cancel.idempotence`

```
INV inv.cancel.idempotence
  CLAUSE:  cancel(T, k1); cancel(T, k2) ≡ cancel(T, strengthen(k1, k2))
           strengthen(a, b) = max_severity(a, b)
  SCOPE:   Duplicate cancel signals on same task
  CHECK:   LEAN (proved), TLA (modeled)
  VIOLATIONS: Non-idempotent cancel → severity downgrade, inconsistent outcome
  NOTE:    On equal severity, first-received kind wins (left-bias). This is
           deterministic for a given schedule.
```

### INV #6: `inv.cancel.propagates_down`

```
INV inv.cancel.propagates_down
  CLAUSE:  cancel(region R) → ∀ child T ∈ R.tasks:
             T.state ≠ Completed → cancel(T, ParentCancelled)
  SCOPE:   Region close triggers child cancellation
  CHECK:   LEAN (proved: cancelPropagate L499-511, cancelChild L513-528)
           TLA absent (ADR-003: accepted abstraction)
  ADR:     ADR-003
  VIOLATIONS: Uncancelled children → region close blocks forever
```

### INV #11: `inv.cancel.mask_bounded`

```
INV inv.cancel.mask_bounded
  CLAUSE:  ∀ task T: T.mask_depth ∈ ℕ ∧ T.mask_depth ≤ MAX_MASK
  SCOPE:   All states where mask_depth > 0
  CHECK:   LEAN (proved), TLA (modeled)
  VIOLATIONS: Unbounded mask → cancel never acknowledged → deadlock
  NOTE:    RT uses u32 for mask_depth. MAX_MASK = 2^32 - 1.
```

### INV #12: `inv.cancel.mask_monotone`

```
INV inv.cancel.mask_monotone
  CLAUSE:  During cancel processing: mask_depth(t+1) ≤ mask_depth(t)
           (mask_depth never increases once cancel is requested)
  SCOPE:   States CancelRequested and CancelMasked
  CHECK:   LEAN (proved)
  VIOLATIONS: Non-monotone mask → cancel processing may not terminate
```

---

## 4. Safety Invariants

### INV #40: `inv.combinator.loser_drained`

```
INV inv.combinator.loser_drained
  CLAUSE:  ∀ race R: R.state = Completed →
             ∀ loser L ∈ R.losers: L.state = Completed
  SCOPE:   Race completion
  CHECK:   LEAN (proof pending, ADR-001). RT (oracle: loser_drain.rs:155-199)
  ADR:     ADR-001 (Lean proof required)
  VIOLATIONS: Undrained loser → region quiescence blocked → cascading deadlock
  WITNESS: W1.1 (normal drain), W1.2 (masked drain), W1.3 (deadlock without)
```

### INV #17: `inv.obligation.no_leak`

```
INV inv.obligation.no_leak
  CLAUSE:  ∀ region R: R.state = Closed →
             ∀ O ∈ R.obligations: O.state ∈ {Committed, Aborted}
           (No leaked obligations at region close)
  SCOPE:   Region terminal state
  CHECK:   LEAN (proved), TLA (checked: SafetyInvariant)
  VIOLATIONS: Leaked obligation → resource leak, phantom work, audit failure
```

### INV #18: `inv.obligation.linear`

```
INV inv.obligation.linear
  CLAUSE:  ∀ obligation O: O transitions from Reserved to exactly one of
           {Committed, Aborted, Leaked}. No re-reservation, no double-commit.
  SCOPE:   Obligation lifecycle
  CHECK:   LEAN (proved)
  VIOLATIONS: Double-commit → phantom work. Re-reserve → ledger inconsistency.
```

### INV #19: `inv.obligation.bounded`

```
INV inv.obligation.bounded
  CLAUSE:  ∀ region R: |{O ∈ R.obligations : O.state = Reserved}| ≤ BOUND
  SCOPE:   Active obligation count per region
  CHECK:   LEAN (proved), TLA (modeled)
  VIOLATIONS: Unbounded obligations → memory exhaustion
```

### INV #20: `inv.obligation.ledger_empty_on_close`

```
INV inv.obligation.ledger_empty_on_close
  CLAUSE:  region.state = Closed → |{O : O.state = Reserved}| = 0
  SCOPE:   Region terminal state (equivalent to no_leak + linear)
  CHECK:   LEAN (proved), TLA (checked)
```

### INV #44: `inv.capability.no_ambient`

```
INV inv.capability.no_ambient
  CLAUSE:  ∀ effect E: E requires Cx<C> where C ⊇ required_caps(E)
           (No runtime effect without capability token)
  SCOPE:   All task execution
  CHECK:   Rust type system — #![deny(unsafe_code)] (ADR-006)
  ADR:     ADR-006
  VIOLATIONS: Ambient authority → uncontrolled effects, determinism leak
  AUDIT:   grep '#[allow(unsafe_code)]' src/cx/ must return empty
```

### INV #46: `inv.determinism.replayable`

```
INV inv.determinism.replayable
  CLAUSE:  ∀ seed S, stimuli X:
             run(S, X) = run(S, X)
           (Same seed + same stimuli → identical outcomes + trace)
  SCOPE:   LabRuntime deterministic execution mode
  CHECK:   RT replay test suite (ADR-007). Seed-based execution + certificate hash.
  ADR:     ADR-007
  VIOLATIONS: Nondeterminism leak → replay divergence, test flakiness
  BOUNDARY: Seed selection is OUTSIDE the determinism boundary (OBS-1).
```

---

## 5. Progress Properties

### PROG #9: `prog.cancel.drains`

```
PROG prog.cancel.drains
  CLAUSE:  ∀ task T: T.state = CancelRequested →
             ◇ (T.state = Completed)
           (Every cancelled task eventually completes)
  SCOPE:   Liveness under fair scheduling
  CHECK:   LEAN (proved: cancel_protocol_terminates, bounded by mask_depth + 3)
  BOUND:   T reaches Completed within mask_depth + 3 steps
```

### PROG #21: `prog.obligation.resolves`

```
PROG prog.obligation.resolves
  CLAUSE:  ∀ obligation O: O.state = Reserved →
             ◇ (O.state ∈ {Committed, Aborted, Leaked})
  SCOPE:   Liveness — obligation must resolve
  CHECK:   LEAN (proved)
  NOTE:    Leaked is a resolution (albeit a bad one). The invariant
           `no_leak` separately constrains that Leaked should not occur.
```

### PROG #28: `prog.region.close_terminates`

```
PROG prog.region.close_terminates
  CLAUSE:  ∀ region R: R.state = Closing →
             ◇ (R.state = Closed)
  SCOPE:   Liveness under fair scheduling + cancel drain termination
  CHECK:   LEAN (proved: depends on cancel_protocol_terminates + obligation_resolves)
  BOUND:   Bounded by max(child drain times) + finalizer time
```

---

## 6. Algebraic Laws

### LAW #42: `law.join.assoc`

```
LAW law.join.assoc
  CLAUSE:  severity(join(join(a, b), c)) = severity(join(a, join(b, c)))
           (Join is associative on outcome severity)
  SCOPE:   Combinator rewrite rules
  CHECK:   LEAN (proof pending, ADR-005)
  NOTE:    Associativity holds on severity. Value-level left-bias is documented:
           join(P(X), P(Y)) = P(X) ≠ P(Y) = join(P(Y), P(X)) when X ≠ Y.
           This is intentional — join is NOT value-commutative.
```

### LAW #43: `law.race.comm`

```
LAW law.race.comm
  CLAUSE:  ∀ schedules S: winner(race(a, b), S) = winner(race(b, a), S)
           (Race winner is determined by completion time, not argument order)
  SCOPE:   Combinator rewrite rules
  CHECK:   LEAN (proof pending, ADR-005)
  NOTE:    Commutativity holds per-schedule. Different schedules may yield
           different winners (this is expected — schedule is an input).
```

### LAW (unnumbered): `law.timeout.min`

```
LAW law.timeout.min
  CLAUSE:  timeout(d1, timeout(d2, f)) ≡ timeout(min(d1, d2), f)
           (Nested timeouts collapse to the minimum deadline)
  SCOPE:   Combinator rewrite rules
  CHECK:   LEAN (proof pending, ADR-005)
  WITNESS: W5.3 (timeout collapse demonstration)
```

### LAW #41: `law.race.never_abandon` (deferred)

```
LAW law.race.never_abandon
  CLAUSE:  ∀ race R: R.state = Completed →
             ¬∃ loser L: L.state ∉ {Completed, CancelRequested, Finalizing}
           (Race never leaves a loser in Running state)
  SCOPE:   Race completion
  CHECK:   Property tests only (ADR-005: deferred from Lean formalization)
  NOTE:    This is a weaker form of inv.combinator.loser_drained (#40).
           The invariant (#40) guarantees Completed; this law guarantees
           at least CancelRequested.
```

---

## 7. Monotonicity and Tie-Breaking Rules

### 7.1 Cancel Severity Monotonicity

```
PROPERTY: cancel_severity_monotone
  CLAUSE:  strengthen(k1, k2).severity = max(k1.severity, k2.severity)
  CONSEQUENCE: Cancel severity never decreases during propagation
```

### 7.2 Outcome Join Tie-Breaking

```
PROPERTY: outcome_join_left_bias
  CLAUSE:  join(a, b) where severity(a) = severity(b):
           result = a (left argument wins)
  CONSEQUENCE: Deterministic tie-breaking for equal-severity outcomes
  NOTE: This is NOT commutativity violation — it's documented left-bias.
```

### 7.3 Absorbing States

```
PROPERTY: completed_is_absorbing
  CLAUSE:  task.state = Completed → ∀ transitions T: T(task).state = Completed
  CONSEQUENCE: Completed tasks cannot be reactivated

PROPERTY: closed_is_absorbing
  CLAUSE:  region.state = Closed → ∀ transitions T: T(region).state = Closed
  CONSEQUENCE: Closed regions cannot be reopened
```

---

## 8. Invariant Coverage Matrix

| Rule ID | Type | Charter | LEAN | TLA | RT | Type-Sys |
|---------|------|---------|:----:|:---:|:--:|:--------:|
| #5 | inv | SEM-INV-003 | proved | modeled | — | — |
| #6 | inv | SEM-INV-003 | proved | absent* | — | — |
| #11 | inv | — | proved | modeled | — | — |
| #12 | inv | — | proved | — | — | — |
| #17 | inv | SEM-INV-005 | proved | checked | — | — |
| #18 | inv | — | proved | — | — | — |
| #19 | inv | — | proved | modeled | — | — |
| #20 | inv | — | proved | checked | — | — |
| #27 | inv | SEM-INV-002 | proved | checked | test | — |
| #33 | inv | SEM-INV-001 | proved | modeled | test | — |
| #34 | inv | SEM-INV-001 | proved | modeled | test | — |
| #40 | inv | SEM-INV-004 | pending | — | oracle | — |
| #44 | inv | SEM-INV-006 | — | — | — | enforced |
| #46 | inv | SEM-INV-007 | — | — | test | — |

*ADR-003: TLA+ abstraction accepted for #6.

---

## 9. Downstream Usage

1. **SEM-04.5**: Versioning policy for invariant modifications.
2. **SEM-08**: Conformance harness maps each invariant to test cases.
3. **SEM-10**: CI checker validates LEAN/TLA citations are current.
4. **SEM-12**: Verification fabric uses coverage matrix to gate releases.
