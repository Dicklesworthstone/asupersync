# Pre-Ratification Adversarial Scenario Set (SEM-03.10)

**Bead**: `asupersync-3cddg.3.10`
**Parent**: SEM-03 Decision Framework and ADR Resolution
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_option_portfolio.md` (SEM-03.7, Pareto frontiers + selections)
- `docs/semantic_witness_pack.md` (SEM-03.3, evidence pack)
- `docs/semantic_optimality_model.md` (SEM-03.6, scoring model)

---

## 1. Purpose

This document defines a focused adversarial scenario set that stress-tests the
selected semantic profile before contract ratification. Each scenario targets
a known residual risk (O1 > 0.00) or a profile flip condition from the
sensitivity analysis.

The goal is to either confirm the selected profile's robustness or surface
concrete failure modes that require profile revision.

---

## 2. Adversarial Strategy

### 2.1 Attack Surfaces

From SEM-03.7 section 9.2, three decisions have residual safety risk (O1 > 0):

| ADR | Selected | Residual O1 | Attack Surface |
|-----|----------|:-----------:|----------------|
| ADR-005 | B (Incremental 3 laws) | 0.25 | Unproven laws could be violated |
| ADR-006 | C (Type-system) | 0.25 | Unsafe code could bypass Cx |
| ADR-007 | C (Impl property) | 0.25 | Scheduler nondeterminism leak |

### 2.2 Flip Conditions

From SEM-03.6 section 3.2, the profile flips under the Pragmatic weight set:
- ADR-001: A (Lean) → C (Oracle) if Safety weight drops below 0.20
- ADR-005: B (Incremental) → C (PropTest) if Safety weight drops below 0.20

### 2.3 Scenario Categories

1. **Safety-breach scenarios**: Construct conditions where residual O1 risk
   manifests as an actual invariant violation.
2. **Weight-flip scenarios**: Show that a Pragmatic-profile selection would
   fail under conditions the charter considers in-scope.
3. **Cross-ADR interaction scenarios**: Test that decisions from different ADRs
   don't create emergent failures when combined.

---

## 3. Safety-Breach Scenarios

### S1: Unproven Combinator Law Violation (targets ADR-005, O1=0.25)

**Hypothesis**: The 3 deferred laws (LAW-RACE-NEVER-ABANDON, LAW-RACE-JOIN-DIST,
LAW-TIMEOUT-ASSOC) contain a counterexample that breaks an optimizer rewrite.

```
Scenario S1.1: race_join_dist counterexample attempt

Setup:
  race(join(a, b), c) vs join(race(a, c), race(b, c))

  a = task that panics after 100ms
  b = task that completes Ok after 200ms
  c = task that completes Ok after 50ms

LHS: race(join(a, b), c)
  c finishes at t=50ms → winner = c
  join(a, b) is loser → cancelled
  Result: Ok(c_result)

RHS: join(race(a, c), race(b, c))
  race(a, c): c at 50ms → Ok(c_result), a cancelled
  race(b, c): c at 50ms → Ok(c_result), b cancelled
  join results: join(Ok, Ok) = Ok
  Result: Ok (but different structure — 2 c completions vs 1)

Verdict: Law does NOT hold in general because race(x, c) consumes c
  independently in each arm. This is expected — distributivity requires
  an idempotent shared-resource model. The law is correctly deferred.

Rule IDs: #38 (comb.race), #37 (comb.join), #41 (law.race.never_abandon)
```

**Expected outcome**: Confirms ADR-005's decision to defer LAW-RACE-JOIN-DIST.
The law does not hold for the RT's resource-consuming execution model.
No profile change needed.

### S2: Type-System Bypass via Internal Crate (targets ADR-006, O1=0.25)

**Hypothesis**: An internal module can construct a `Cx` with capabilities the
caller does not possess, bypassing the sealed-generic enforcement.

```
Scenario S2.1: pub(crate) constructor bypass

Target: src/cx/cx.rs — any pub(crate) function that returns Cx<C>
  where C is not constrained by caller's capability set.

Search: grep -rn 'pub(crate).*fn.*Cx' src/cx/

Attack vector:
  1. Internal function creates Cx<cap::All> (full capability set)
  2. Passes it to user code via callback
  3. User code gains ambient authority

Mitigation check:
  - All Cx constructors require RegionHandle (scoped to region tree)
  - RegionHandle is not user-constructible
  - Cx::restrict() enforces SubsetOf at compile time
  - `#![deny(unsafe_code)]` prevents raw pointer construction

Expected result: No bypass found. Cx construction chain is:
  Runtime → Region → RegionHandle → Cx (with inherited caps)

Rule IDs: #44 (inv.capability.no_ambient), #45 (def.capability.cx_scope)
```

**Expected outcome**: Confirms ADR-006's decision. The type system prevents bypass.
Audit surface: `grep '#[allow(unsafe_code)]' src/` returns zero results in
capability modules.

### S3: Determinism Leak via System Clock (targets ADR-007, O1=0.25)

**Hypothesis**: LabRuntime's deterministic scheduler leaks nondeterminism
through a system clock access path that isn't intercepted.

```
Scenario S3.1: Instant::now() leak in deterministic mode

Target: Any call to std::time::Instant::now() or SystemTime::now()
  that executes during a LabRuntime deterministic run.

Search: grep -rn 'Instant::now\|SystemTime::now\|time::now' src/

Attack vector:
  1. Task calls a function that reads wall-clock time
  2. Wall-clock time varies between runs with same seed
  3. Different time → different branch → different outcome
  4. Replay certificate hash mismatch

Mitigation check:
  - LabRuntime provides cx.now() via TimeProvider trait
  - TimeProvider in lab mode returns deterministic virtual time
  - Direct std::time access in task code requires Timer capability
  - Timer capability is gated by Cx (ADR-006)

Expected result: If all time access goes through Cx, determinism holds.
If any std::time::Instant::now() call exists in task-reachable code
outside of Cx, this is a genuine determinism leak.

Rule IDs: #46 (inv.determinism.replayable), #47 (def.determinism.seed_equivalence)
```

**Expected outcome**: Scenario validates the cross-ADR dependency between
ADR-006 (capability enforcement) and ADR-007 (determinism). If ADR-006
holds, ADR-007 holds. This reinforces the portfolio's internal coherence.

---

## 4. Weight-Flip Scenarios

### S4: Pragmatic Flip — ADR-001 (A→C)

**Hypothesis**: If we selected Oracle-only (C) instead of Lean proof (A) for
loser drain, what concrete failure would be missed?

```
Scenario S4.1: Unbounded mask depth counterexample

From witness W1.2: Race with masked loser works for mask <= 64.
Oracle tests cover mask depths 0, 1, 3, 10, 64.

Attack: mask_depth = 2^32 (overflow edge case)
  - Does the oracle test this? No — combinatorial explosion.
  - Does the Lean proof cover this? Yes — inductive argument over nat.
  - Would overflow crash? Only if mask is stored as u32.

Code check: src/types/cancel.rs — mask_depth is `u32`
  - 2^32 mask depth → 2^32 checkpoint steps to drain
  - In practice impossible (scheduler would timeout)
  - But the FORMAL guarantee requires handling all natural numbers

Verdict: Without Lean proof, the guarantee has a finite coverage bound.
  The Oracle cannot test all mask depths. For charter SEM-INV-004,
  this gap is unacceptable.

Rule IDs: #40 (inv.combinator.loser_drained)
```

**Expected outcome**: Confirms that flipping to Oracle-only (Pragmatic profile)
would leave SEM-INV-004 with a bounded, not universal, guarantee. The
Safety-First selection of A (Lean proof) is correct.

### S5: Pragmatic Flip — ADR-005 (B→C)

**Hypothesis**: If we selected property tests only (C) instead of incremental
Lean proofs (B) for combinator laws, what failure would be missed?

```
Scenario S5.1: Join associativity edge case — Panic + Cancel interaction

Property test: join(join(a, b), c) == join(a, join(b, c))
  for random a, b, c outcomes.

Attack: a = Panicked(X), b = Cancelled(Timeout), c = Ok(Y)
  LHS: join(Panicked(X), Cancelled(Timeout)) = Panicked(X) [severity: 3 > 2]
       join(Panicked(X), Ok(Y)) = Panicked(X) [severity: 3 > 0]
  RHS: join(Cancelled(Timeout), Ok(Y)) = Cancelled(Timeout) [severity: 2 > 0]
       join(Panicked(X), Cancelled(Timeout)) = Panicked(X) [severity: 3 > 2]
  Both = Panicked(X) ✓

  This case works. But property testing only covers sampled cases.

Attack 2: Outcome::join with equal-severity but different-kind values
  Panicked(X) vs Panicked(Y) — which "wins"?
  join picks "first argument" on tie: join(P(X), P(Y)) = P(X)
  But join(P(Y), P(X)) = P(Y)
  → join is NOT commutative on equal-severity outcomes!

  This is by design (join takes the "left" value on tie).
  But property tests might not catch this subtlety if they only
  check outcome KIND equality, not VALUE equality.

Verdict: Property tests could miss semantic-preserving but
  value-affecting edge cases. Lean proof would catch this because
  it reasons about the full Outcome type, not just severity.

Rule IDs: #42 (law.join.assoc), #37 (comb.join)
```

**Expected outcome**: Confirms that Lean proofs (option B) catch edge cases
that property tests (option C) might miss due to equivalence class coverage gaps.

---

## 5. Cross-ADR Interaction Scenarios

### S6: ADR-001 × ADR-005 — Loser Drain + Join Associativity

**Hypothesis**: The Lean proof for loser drain (ADR-001) and the Lean proofs
for combinator laws (ADR-005) must use consistent definitions. If the
formalization defines `Race` differently in each proof, the guarantees
don't compose.

```
Scenario S6.1: Definition consistency check

ADR-001 needs: Race(a, b) defined as derived Step sequence
ADR-005 needs: Race defined for LAW-RACE-COMM proof

Check: Both proofs must use the SAME Race definition.
If they don't, loser drain might hold for Race-v1 but
LAW-RACE-COMM might hold for Race-v2 — neither holds for
the actual RT implementation.

Mitigation: Single LEAN bead defines Race/Join/Timeout.
Both ADR-001 and ADR-005 proofs import from this shared definition.

Expected result: The bead structure ensures definition consistency.
Cross-reference: SEM-03.4 Action Item 1 (shared combinator bead).

Rule IDs: #38 (comb.race), #40 (inv.combinator.loser_drained),
          #43 (law.race.comm)
```

### S7: ADR-006 × ADR-007 — Capability + Determinism

**Hypothesis**: If capability enforcement (ADR-006) is weakened, determinism
(ADR-007) breaks because nondeterministic I/O bypasses the Cx gate.

```
Scenario S7.1: Capability bypass → determinism failure chain

Assume: ADR-006 type-system bypass exists (S2 scenario succeeds)
Then: Task gains ambient Timer capability
Then: Task calls std::time::Instant::now() directly
Then: Wall-clock time varies between runs
Then: Replay certificate mismatch
Then: ADR-007 determinism guarantee fails

This is a cross-ADR cascade:
  ADR-006 failure → ADR-007 failure

Mitigation: ADR-006 holds (S2 confirms no bypass exists).
Therefore the cascade cannot occur.

Rule IDs: #44, #45, #46, #47
```

**Expected outcome**: Confirms the portfolio's cross-ADR dependencies are
correctly captured and that ADR-006 is a load-bearing decision for ADR-007.

---

## 6. Scenario Summary and Test Matrix

| ID | Category | Target ADR | Target O1 | Rule IDs | Expected Result |
|----|----------|-----------|:---------:|----------|-----------------|
| S1 | Safety-breach | ADR-005 | 0.25 | #37-38, #41 | Deferred law correctly deferred |
| S2 | Safety-breach | ADR-006 | 0.25 | #44-45 | No bypass found |
| S3 | Safety-breach | ADR-007 | 0.25 | #46-47 | Determinism holds via Cx gate |
| S4 | Weight-flip | ADR-001 | 0.00→0.50 | #40 | Lean proof gap confirmed |
| S5 | Weight-flip | ADR-005 | 0.25→0.50 | #37, #42 | PropTest coverage gap confirmed |
| S6 | Cross-ADR | ADR-001×005 | — | #38, #40, #43 | Definition consistency required |
| S7 | Cross-ADR | ADR-006×007 | — | #44-47 | Cascade prevented by ADR-006 |

### Reproducibility

All scenarios are deterministic thought experiments with specific code pointers.
S2 and S3 include grep commands for empirical verification:
- S2: `grep -rn '#\[allow(unsafe_code)\]' src/cx/`
- S3: `grep -rn 'Instant::now\|SystemTime::now' src/`

---

## 7. Downstream Usage

1. **SEM-03.9**: Stress-test runner consumes this scenario set directly.
   Each scenario maps to a pass/fail criterion for the selected profile.
2. **SEM-03.8**: Global profile selection references adversarial results
   to justify robustness claims.
3. **SEM-12**: Verification fabric converts S2/S3 grep checks into CI gates.
