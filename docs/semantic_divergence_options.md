# Candidate Options for Divergent Semantic Rows

Status: Active
Program: `asupersync-3cddg` (SEM-03.2)
Parent: SEM-03 Decision Framework and ADR Resolution
Author: SapphireHill
Published: 2026-03-02 UTC
Rubric Reference: `docs/semantic_divergence_rubric.md`
Drift Matrix Reference: `docs/semantic_drift_matrix.md`

## 1. Purpose

For every non-aligned row in the drift matrix, this document enumerates
candidate semantic options with explicit assumptions and effects. Each
divergence has at least one conservative option and one
performance/complexity alternative.

## 2. Non-Aligned Concepts Requiring Decision

From the drift matrix, 23 concepts are not fully aligned across all 4 layers.
Grouped by resolution pathway from the rubric:

### Priority (composite score >= 3.0)

| Hotspot | Concepts | Score |
|---------|----------|-------|
| HOTSPOT-1 | #40 inv.combinator.loser_drained | 3.55 |
| HOTSPOT-5 | #37-39, #41-43 (6 combinator concepts) | 3.15 |

### Standard (2.0 <= score < 3.0)

| Hotspot | Concepts | Score |
|---------|----------|-------|
| HOTSPOT-7 | #46-47 (determinism) | 2.90 |
| HOTSPOT-6 | #44-45 (capability) | 2.80 |

### Accept (score < 2.0)

| Hotspot | Concepts | Score |
|---------|----------|-------|
| HOTSPOT-3 | #6 (cancel propagation) | 1.95 |
| HOTSPOT-2 | #7-8 (cancel reason granularity) | 1.90 |
| HOTSPOT-4 | #25 (finalizers) | 1.60 |
| HOTSPOT-8 | #29-32 (severity in TLA+) | 1.60 |

Additionally, the following concepts have layer gaps but are addressed by
the hotspot decisions above:
- #9 prog.cancel.drains (TLA missing, addressed by HOTSPOT-3 accept)
- #21 prog.obligation.resolves (TLA partial, addressed by HOTSPOT-8 accept)
- #27 inv.region.quiescence (TLA partial, addressed by HOTSPOT-4 accept)
- #28 prog.region.close_terminates (TLA missing, addressed by HOTSPOT-4 accept)

## 3. Priority Divergences — Full Option Analysis

### 3.1 HOTSPOT-1: Loser Drain Formal Proof

**Divergence**: RT has oracle enforcement. DOC specifies INV-LOSER-DRAINED.
LEAN defines `LoserDrained` predicate but has no proof. TLA absent.

#### Option A: Full Lean Combinator Theory

- **Description**: Define `join`, `race`, `timeout` as derived step sequences
  in Lean. Prove `LoserDrained` as a theorem about `race`.
- **Assumptions**: Combinators can be expressed as finite step sequences
  (spawn N tasks, poll, cancel losers, drain).
- **Effects**: Machine-checked guarantee. Enables proving algebraic laws.
- **Pros**: Strongest possible assurance; charter-compliant
- **Cons**: Weeks of Lean development; ongoing maintenance as RT evolves
- **Witness**: LEAN predicate at L274 shows the goal statement is already defined

#### Option B: TLA+ Combinator Model Checking

- **Description**: Add Race/Join/Timeout TLA+ actions. Add LoserDrained
  as TLC invariant.
- **Assumptions**: Bounded model (2-3 tasks per race) suffices.
- **Effects**: Exhaustive verification for bounded case.
- **Pros**: Faster than Lean; catches bugs in bounded space
- **Cons**: Not a proof; cannot guarantee for unbounded task count
- **Witness**: TLA+ already has task/region primitives to compose

#### Option C: Runtime Oracle Strengthening Only

- **Description**: Add property-based tests and adversarial scheduling
  scenarios to the loser drain oracle.
- **Assumptions**: Testing catches bugs in practice.
- **Effects**: Higher empirical confidence, no formal guarantee.
- **Pros**: Immediate; no formal model changes
- **Cons**: Does not satisfy SEM-GOAL-002 (deterministic evidence)
- **Witness**: Oracle at `src/lab/oracle/loser_drain.rs:90-99`

#### Option D: Status Quo (Document Limitation)

- **Description**: Record the gap as accepted limitation in the contract.
- **Effects**: No change.
- **Cons**: Violates charter SEM-INV-004 (non-negotiable)

**Recommendation**: A + C (Lean proof is the target; oracle provides coverage
during proof development).

---

### 3.2 HOTSPOT-5: Combinator Formalization

**Divergence**: No formal model for join/race/timeout. No algebraic law proofs.

#### Option A: Full Lean Formalization (All 6 Concepts)

- **Description**: Define all 3 combinators + prove all 6 algebraic laws
  (JOIN-ASSOC, JOIN-COMM, RACE-COMM, TIMEOUT-MIN, RACE-NEVER, RACE-JOIN-DIST).
- **Assumptions**: Laws hold for the small-step model.
- **Effects**: Complete formal coverage of combinator layer.
- **Pros**: Closes all 6 gaps simultaneously
- **Cons**: Very high effort; some laws may require non-trivial theory

#### Option B: Incremental — 3 Core Combinators + 3 Laws

- **Description**: Define join/race/timeout in Lean. Prove the 3 most
  impactful laws: JOIN-ASSOC, RACE-COMM, TIMEOUT-MIN.
- **Assumptions**: These 3 are sufficient for optimizer correctness.
- **Effects**: Partial but high-value coverage.
- **Pros**: Manageable scope; covers critical rewrite rules
- **Cons**: 3 laws left unproved (JOIN-COMM, RACE-NEVER, RACE-JOIN-DIST)

#### Option C: TLA+ Only (No Lean)

- **Description**: Add combinator actions to TLA+. Check laws as TLC
  properties for bounded cases.
- **Pros**: Faster than Lean; catches finite counterexamples
- **Cons**: Not proofs; limited by bounds

#### Option D: Contract + Test Oracle Only

- **Description**: State laws in the contract. Enforce via property tests
  in the lab runtime.
- **Pros**: Immediate; practical
- **Cons**: No formal verification

**Recommendation**: B (incremental Lean: define combinators, prove 3 core laws).

## 4. Standard Divergences — Option Analysis

### 4.1 HOTSPOT-6: Capability Security

**Divergence**: Capability enforcement is Rust type-system only. No formal
model in LEAN or TLA+.

#### Option A: Lean Capability Type Parameter

- **Description**: Add a `Cap` type parameter to the Step relation.
  Operations require matching capabilities.
- **Effects**: Formal capability checking in the model.
- **Cons**: Major model refactor; dependent types needed

#### Option B: Document as Rust Type-System Property

- **Description**: The contract states SEM-INV-006 and declares the Rust
  type system (CapSet + sealed generics) as the enforcement mechanism.
  The small-step model is explicitly out of scope for capability checking.
- **Effects**: Clean scope boundary; no model changes.
- **Pros**: Honest about what the model covers

#### Option C: Static Analysis Audit

- **Description**: Run periodic `unsafe` audits and `Cx`-bypass grep checks.
- **Effects**: Operational assurance without model changes.

**Recommendation**: B + C (document + periodic audit).

### 4.2 HOTSPOT-7: Determinism

**Divergence**: Formal models are intentionally nondeterministic. Determinism
is a LabRuntime implementation property.

#### Option A: Lean Scheduler Refinement Proof

- **Description**: Define a deterministic scheduler in Lean. Prove it
  refines the nondeterministic Step relation (simulation relation).
- **Effects**: Machine-checked determinism guarantee.
- **Cons**: Very high effort; scheduler implementation is complex

#### Option B: Document as Implementation Property

- **Description**: The contract states SEM-INV-007 and declares LabRuntime
  as the enforcement mechanism. The nondeterministic formal model enables
  DPOR exploration; determinism is achieved by fixing the schedule.
- **Effects**: Honest scope boundary.

#### Option C: Bisimulation Test Oracle

- **Description**: Run N schedules with same seed, verify identical outcomes.
- **Effects**: Empirical determinism evidence per seed.

**Recommendation**: B + C (document + bisimulation testing).

## 5. Accepted Divergences — Resolution Statements

### 5.1 HOTSPOT-2: CancelReason Granularity

**Resolution**: The canonical contract defines 5 CancelKind variants
matching DOC/LEAN (User, Timeout, FailFast, ParentCancelled, Shutdown).
RT's additional 6 kinds (Deadline, PollQuota, CostBudget, RaceLost,
ResourceUnavailable, LinkedExit) are documented as implementation-specific
extensions with mandatory severity mapping to the canonical 5.

**Contract clause**: "Implementations MAY define additional CancelKind
variants provided they map to one of the 5 canonical kinds via the severity
function and satisfy the strengthen monotonicity invariant."

### 5.2 HOTSPOT-3: Cancel Propagation TLA+ Absence

**Resolution**: Accept TLA+ abstraction. LEAN proofs for cancelPropagate
and cancelChild are the primary formal assurance. TLA+ relies on implicit
regionCancel flag which is correct for the bounded model.

### 5.3 HOTSPOT-4: Finalizer TLA+ Absence

**Resolution**: Accept TLA+ abstraction. LEAN closeRunFinalizer proof
covers the gap. TLA+ 3-part quiescence is documented as a deliberate
simplification for tractable model checking.

### 5.4 HOTSPOT-8: Severity TLA+ Absence

**Resolution**: Accept TLA+ abstraction. LEAN severity lattice proofs
(total order, transitivity) are the primary assurance. TLA+ collapses
outcomes to "Completed" for tractable state space.

## 6. Summary Table

| Hotspot | Recommended Option | Formal Work | RT Work | Doc Work |
|---------|-------------------|-------------|---------|----------|
| HOTSPOT-1 | A+C (Lean proof + oracle) | Lean combinator defs + LoserDrained thm | Oracle hardening | Contract references proof |
| HOTSPOT-5 | B (Incremental Lean) | 3 combinator defs + 3 law proofs | None | Contract states laws |
| HOTSPOT-6 | B+C (Document + audit) | None | Audit script | Scope boundary clause |
| HOTSPOT-7 | B+C (Document + testing) | None | Bisimulation tests | Scope boundary clause |
| HOTSPOT-2 | Accept + extension policy | None | None | Extension clause |
| HOTSPOT-3 | Accept (LEAN primary) | None | None | Abstraction note |
| HOTSPOT-4 | Accept (LEAN primary) | None | None | Abstraction note |
| HOTSPOT-8 | Accept (LEAN primary) | None | None | Abstraction note |
