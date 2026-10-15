# Candidate Options for Divergent/Ambiguous Semantic Rows (SEM-03.2)

**Bead**: `asupersync-3cddg.3.2`
**Parent**: SEM-03 Decision Framework and ADR Resolution
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_drift_matrix.md` (SEM-02.6)
- `docs/semantic_divergence_rubric.md` (SEM-03.1)

---

## 1. Scope

The drift matrix identifies 23 non-aligned concepts (47 total minus 24 fully
aligned). This document enumerates candidate resolution options for each,
grouped by divergence category per the rubric's resolution pathways.

Each entry provides:
- Conservative option (minimize change, accept limitation)
- Alignment option (close the gap)
- Hybrid option (partial alignment with documented boundary)

---

## 2. Priority Divergences (Composite Score >= 3.0)

### 2.1 HOTSPOT-1: `inv.combinator.loser_drained` (#40)

**Current state**: RT oracle-verified. LEAN definition only. TLA absent.
**ADR resolution**: Priority (composite 3.55).

| Option | Description | Assumptions | Effects |
|--------|-------------|-------------|---------|
| **A: Full Lean proof** | Define `Race`, `Join`, `Timeout` as derived Step sequences in Lean. Prove `race_ensures_loser_drained`. | Combinators can be decomposed into existing Step constructors (spawn + cancel + join). | Closes gap fully. Proof tracks any combinator refactoring. ~2-4 weeks effort. |
| **B: TLA+ combinator encoding** | Add `RaceStart`, `RaceWinnerDone`, `RaceLoserCancel`, `RaceLoserDrained` actions to TLA+. Add `LoserDrainedInvariant`. | State-space remains tractable with 2 tasks per race. | TLC exhaustively checks for small bounds. Not a proof. Catches bugs Lean might miss via different abstraction. ~3-5 days. |
| **C: Oracle + metamorphic tests** | Add adversarial scheduling metamorphic tests to RT oracle. Increase cancel-timing permutations. | Oracle coverage is sufficient empirical evidence. | No formal gap closure. Increases confidence. ~2-3 days. |
| **D: Accept limitation** | Document as accepted gap. Charter SEM-INV-004 has RT oracle as fallback. | RT oracle is correct and comprehensive. | Zero effort. Gap persists. |

**Recommended**: A + B (parallel tracks). A is the permanent solution. B provides independent exhaustive checking during development window.

### 2.2 HOTSPOT-5: Combinator laws (#37-39, #41-43)

**Current state**: 6 concepts in RT+DOC only. No formal model.
**ADR resolution**: Priority (composite 3.15).

| Option | Description | Assumptions | Effects |
|--------|-------------|-------------|---------|
| **A: Full combinator theory** | Define `Join`, `Race`, `Timeout` in Lean. Prove all 6 laws (assoc, comm, never_abandon, timeout_min, race_join_dist). | Full combinator semantics decomposable into Steps. | Complete formal coverage. High effort (~4-6 weeks). |
| **B: Incremental — 3 core laws** | Define `Join` and `Race` in Lean. Prove LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN only. Defer race_never_abandon, race_join_dist. | These 3 laws are the most-used rewrite rules. | 70% coverage of critical laws. ~2-3 weeks. |
| **C: Property-based testing only** | Add QuickCheck-style property tests for all 6 laws against the RT oracle. | Probabilistic coverage sufficient for algebraic laws. | No formal proof. Tests as evidence. ~1 week. |
| **D: Accept limitation** | Document combinators as implementation-defined with algebraic-law testing. | Laws are informally justified by JoinAll/RaceAll implementations. | Zero effort for formal. |

**Recommended**: B (incremental). Proves the 3 most impactful laws. Defer full theory to a later SEM phase.

---

## 3. Standard Divergences (Composite Score 2.0-2.9)

### 3.1 HOTSPOT-7: Determinism (`inv.determinism.replayable` #46, `def.determinism.seed_equivalence` #47)

**Current state**: RT implementation (LabRuntime + DetRng). Not in LEAN/TLA.
**ADR resolution**: Standard (composite 2.90).

| Option | Description | Assumptions | Effects |
|--------|-------------|-------------|---------|
| **A: Scheduler determinization proof** | Define deterministic scheduler as a Lean refinement of nondeterministic Step relation. Prove bisimulation for fixed seed. | Scheduler can be modeled as a deterministic function from (State, Seed) → Step. | Full formal coverage. Very high effort (~months). |
| **B: TLA+ fairness + temporal** | Add weak fairness to TLA+ spec. Check `<>[] AllTasksCompleted` under deterministic schedule. | TLC handles fairness with moderate state-space growth. | Liveness checked for small bounds. Not full determinism proof. ~1-2 weeks. |
| **C: Document as implementation property** | Contract defines determinism requirement. LabRuntime is the implementation. Replay test suite is the evidence. | Formal models are intentionally nondeterministic for DPOR exploration. | Clean scope boundary. No formal effort. |

**Recommended**: C. Determinism is inherently a scheduler-implementation property. Formal nondeterminism is a feature (enables DPOR), not a gap.

### 3.2 HOTSPOT-6: Capability security (`inv.capability.no_ambient` #44, `def.capability.cx_scope` #45)

**Current state**: RT type-system enforcement. Not in LEAN/TLA.
**ADR resolution**: Standard (composite 2.80).

| Option | Description | Assumptions | Effects |
|--------|-------------|-------------|---------|
| **A: Lean capability parameter** | Add `Cap : Type` parameter to Step. Require capability token for operations. Prove `cap_monotone_on_restrict`. | Capability semantics decomposable from type-level to term-level. | Formal capability model. Research-level effort. |
| **B: TLA+ capability variable** | Add `taskCap ∈ SUBSET Capabilities` to TLA+. Actions require subset check. | Finite capability set (5 dimensions). | TLC checks capability isolation. Moderate state-space increase. ~1 week. |
| **C: Document as type-system property** | Contract defines capability enforcement. Rust's sealed-generics mechanism is the verification layer. `Cx` cannot be forged by construction. | Compiler verification is sufficient for type-level properties. | Clean scope boundary. Correct characterization. |

**Recommended**: C. Capability security is a type-system property. The Rust compiler IS the verifier. Small-step models cannot express type-level reasoning.

### 3.3 Outcome severity in TLA+ (#29-32)

**Current state**: RT+LEAN have full severity lattice. TLA uses single "Completed" state.

| Option | Description | Assumptions | Effects |
|--------|-------------|-------------|---------|
| **A: Full severity in TLA+** | Add `taskOutcome ∈ {"Ok","Err","Cancelled","Panicked"}` and `taskSeverity ∈ 0..3`. Encode join semantics. | State-space growth acceptable. | TLC checks severity join properties. ~3-5 days. |
| **B: Cancel severity only** | Add `taskCancelRank ∈ 0..3` for cancel reason ordering. Keep "Completed" for outcomes. | Cancel severity is the high-value check; outcome severity is covered by LEAN. | Moderate improvement. ~2 days. |
| **C: Accept abstraction** | LEAN has full severity proofs (total order, transitivity, antisymmetry). TLA's abstraction is documented. | LEAN proof is primary assurance. TLA focuses on structural safety. | Zero effort. Correct characterization. |

**Recommended**: C. LEAN proofs are comprehensive. TLA's role is structural safety checking, not semantic detail.

---

## 4. Accepted Divergences (Composite Score < 2.0)

These divergences have been analyzed in the rubric and accepted with
documentation. No further options enumeration needed — the rubric's ADR
decisions stand.

### 4.1 HOTSPOT-2: CancelReason granularity (#7, #8)

**Decision**: Canonical 5 kinds in contract + RT extension policy.
**Rationale**: RT's 11 kinds are implementation refinements of the fundamental 5.
**Action**: SEM-04.2 glossary defines canonical kinds with extension mapping.

### 4.2 HOTSPOT-3: Cancel propagation in TLA+ (#6)

**Decision**: Accept TLA+ abstraction. LEAN proof is primary assurance.
**Rationale**: LEAN has mechanized proofs for cancelPropagate + cancelChild.
**Action**: None required. Optional TLA+ enhancement as low-priority bead.

### 4.3 HOTSPOT-4: Finalizer step in TLA+ (#25)

**Decision**: Accept TLA+ abstraction.
**Rationale**: LEAN proves closeRunFinalizer. TLA 3-part quiescence is documented.
**Action**: None required.

### 4.4 HOTSPOT-8: Outcome severity in TLA+ (#29-31)

**Decision**: Accept TLA+ abstraction.
**Rationale**: LEAN has full severity lattice proofs.
**Action**: None required.

### 4.5 Progress properties without liveness (#9, #21, #28)

**Decision**: Accept safety-only TLA+ checking. LEAN proves progress properties.
**Rationale**: Liveness checking requires fairness constraints that significantly
increase TLC state space. LEAN proves bounded termination directly.
**Action**: None required. Optional fairness enhancement for TLA+ v2.

### 4.6 Partial LEAN encodings (#27 quiescence 3-vs-4 part, #45 cx_scope, #46 replayable)

**Decision**: Accept partial encodings.
**Rationale**: LEAN's structural approximations are correct for the concepts they
model. Full encoding would require extending the model beyond its current scope.
**Action**: Track as enhancement opportunities for LEAN model v2.

---

## 5. Summary: Non-Aligned Concept Disposition

| Category | Count | Concepts | Disposition |
|----------|:-----:|---------|-------------|
| Priority — formal proof needed | 7 | #37-43 | LEAN combinator formalization (incremental) |
| Priority — charter invariant gap | 1 | #40 | LEAN proof + TLA+ encoding |
| Standard — document scope boundary | 4 | #44-47 | Contract defines enforcement layer |
| Standard — TLA+ enhancement optional | 4 | #29-32 | Accept with LEAN as primary |
| Accepted — LEAN proof sufficient | 5 | #5-6, #9, #25, #28 | Documented abstractions |
| Accepted — implementation refinement | 2 | #7-8 | Canonical 5 + extension policy |
| **Total non-aligned** | **23** | | |

### Resolution Effort Estimate

| Track | Concepts | Effort | SEM Phase |
|-------|:--------:|:------:|:---------:|
| LEAN combinator formalization | 7 | 2-3 weeks | SEM-08 |
| LEAN loser drain proof | 1 | 1-2 weeks | SEM-08 |
| TLA+ combinator encoding | 1 | 3-5 days | SEM-08 |
| Contract scope documentation | 4 | 2-3 days | SEM-04 |
| Accepted abstractions | 10 | 1 day | SEM-04 |
| **Total** | **23** | **~5-7 weeks** | |

---

## 6. Cross-References

- Drift matrix: `docs/semantic_drift_matrix.md`
- Rubric and ADR decisions: `docs/semantic_divergence_rubric.md`
- Downstream: SEM-03.3 (witnesses), SEM-03.4 (ADR records), SEM-04 (contract)
