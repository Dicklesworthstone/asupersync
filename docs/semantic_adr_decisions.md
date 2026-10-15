# ADR Decision Record for Semantic Divergences (SEM-03.4)

**Bead**: `asupersync-3cddg.3.4`
**Parent**: SEM-03 Decision Framework and ADR Resolution
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_divergence_rubric.md` (SEM-03.1, scoring + ADR details)
- `docs/semantic_candidate_options.md` (SEM-03.2, option enumeration)
- `docs/semantic_witness_pack.md` (SEM-03.3, witnesses/counterexamples)

---

## 1. ADR Index

This document consolidates all Architecture Decision Records from the SEM-03
decision framework. Full scoring details and witnesses are in the referenced
input documents. Each ADR here is self-contained for downstream consumers
(SEM-04 contract, SEM-08 runtime alignment).

---

## ADR-001: Loser Drain Requires Formal Proof

**Status**: Approved
**Hotspot**: HOTSPOT-1 (composite score 3.55)
**Concepts**: `inv.combinator.loser_drained` (#40)
**Charter**: SEM-INV-004

**Decision**: Pursue Lean combinator formalization (Option A) plus strengthened
runtime oracle (Option C) in parallel. Define `Race`, `Join`, `Timeout` as
derived Step sequences in Lean. Prove `race_ensures_loser_drained`.

**Rationale**: SEM-INV-004 is a charter non-negotiable. The current state (LEAN
definition only, no proof) is insufficient. Runtime oracle provides empirical
coverage during the proof development window.

**Rejected**:
- TLA+ encoding alone (Option B): Bounded, not a proof.
- Status quo (Option D): Violates charter SEM-GOAL-002.

**Impact**: New LEAN formalization bead required. SEM-08.4 conformance harness
must test race drain timing.

**Witnesses**: W1.1 (normal drain), W1.2 (masked drain), W1.3 (deadlock
without drain). See `docs/semantic_witness_pack.md §2`.

---

## ADR-002: CancelReason Uses Canonical 5 + Extension Policy

**Status**: Approved
**Hotspot**: HOTSPOT-2 (composite score 1.90)
**Concepts**: `def.cancel.reason_kinds` (#7), `def.cancel.severity_ordering` (#8)
**Charter**: SEM-DEF-003

**Decision**: The semantic contract defines 5 canonical cancel kinds
(explicit, parentCancelled, timeout, panicked, shutdown). RT's 6 additional
kinds (Deadline, PollQuota, CostBudget, RaceLost, ResourceUnavailable,
LinkedExit) are implementation extensions that must map to canonical severity
levels.

**Rationale**: The 5 DOC/LEAN kinds capture fundamental cancel semantics.
RT extensions refine behavior within the existing severity lattice.

**Rejected**:
- Full alignment to 11 RT kinds (Option A): Effort/benefit too high.
- Unresolved status quo (Option C): Unactionable.

**Impact**: SEM-04.2 glossary must define canonical kinds and extension policy.
Contract must require integer severity levels (0-5) for extensions.

---

## ADR-003: Cancel Propagation Accepted as TLA+ Abstraction

**Status**: Approved
**Hotspot**: HOTSPOT-3 (composite score 1.95)
**Concepts**: `inv.cancel.propagates_down` (#6)
**Charter**: SEM-INV-003

**Decision**: Accept that TLA+ does not model cancel propagation. LEAN's
mechanized proofs for `cancelPropagate` (L499-511) and `cancelChild` (L513-528)
are the primary assurance.

**Rationale**: LEAN has full proofs. TLA+ addition is defense-in-depth but not
charter-required (SEM-GOV-003: formal artifacts are authoritative).

**Impact**: None required. Optional TLA+ enhancement tracked as low-priority bead.

---

## ADR-004: Finalizer Step Accepted as TLA+ Abstraction

**Status**: Approved
**Hotspot**: HOTSPOT-4 (composite score 1.60)
**Concepts**: `rule.region.close_run_finalizer` (#25)
**Charter**: SEM-INV-002

**Decision**: Accept that TLA+ skips the finalizer step. LEAN proves
`closeRunFinalizer`. TLA+ 3-part quiescence (without finalizers) is a
documented simplification.

**Rationale**: LEAN proof covers the gap. Finalizer bugs would also be caught
by RT oracle (region_tree oracle checks finalizer completion).

**Impact**: None.

---

## ADR-005: Combinator Laws — Incremental Lean Formalization

**Status**: Approved
**Hotspot**: HOTSPOT-5 (composite score 3.15)
**Concepts**: `comb.join` (#37), `comb.race` (#38), `comb.timeout` (#39),
`law.race.never_abandon` (#41), `law.join.assoc` (#42), `law.race.comm` (#43)
**Charter**: SEM-INV-004, SEM-INV-007

**Decision**: Incremental formalization. Phase 1: Define `Join` and `Race` in
Lean as derived Step sequences. Phase 2: Prove the 3 highest-impact laws
(LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN). Defer remaining laws.

**Rationale**: Full combinator theory is research-level effort (~6 weeks).
Incremental approach delivers machine-checked coverage for the most-used
rewrite rules while managing proof maintenance cost.

**Rejected**:
- Full 6-law theory (Option A): Too expensive for current phase.
- Property testing only (Option C): No formal guarantee.
- Status quo (Option D): Laws unverified.

**Impact**: New LEAN bead for combinator definitions + 3 law proofs.

---

## ADR-006: Capability Security Is a Type-System Property

**Status**: Approved
**Hotspot**: HOTSPOT-6 (composite score 2.80)
**Concepts**: `inv.capability.no_ambient` (#44), `def.capability.cx_scope` (#45)
**Charter**: SEM-INV-006

**Decision**: Document capability security as a Rust type-system invariant
outside the scope of the small-step operational model. The contract (SEM-04)
references the `CapSet` sealed-generics lattice and `Cx` token mechanism as
the enforcement layer.

**Rationale**: Capability enforcement requires type-level reasoning (sealed
generics, SubsetOf proofs). Small-step operational models cannot express
type-system properties. The Rust compiler IS the verifier.

**Rejected**:
- Lean capability parameter (Option A): Research-level effort.
- TLA+ capability variable (Option B): Cannot express type-level guarantees.

**Impact**: SEM-04 contract section on capabilities must reference Rust type
system enforcement with `#![deny(unsafe_code)]` as the audit boundary.

---

## ADR-007: Determinism Is an Implementation Property

**Status**: Approved
**Hotspot**: HOTSPOT-7 (composite score 2.90)
**Concepts**: `inv.determinism.replayable` (#46), `def.determinism.seed_equivalence` (#47)
**Charter**: SEM-INV-007

**Decision**: Document deterministic replay as an implementation property of
`LabRuntime`. The contract defines the determinism requirement. The replay
test suite (seed-based execution + trace certificate comparison) provides
empirical verification.

**Rationale**: Formal models are intentionally nondeterministic to enable
DPOR-style schedule exploration. Determinism is a scheduler-implementation
property, not an abstract semantics property. Proving scheduler determinization
would require a separate refinement proof (~months of effort).

**Rejected**:
- Full scheduler determinization proof (Option A): Months of effort.
- TLA+ fairness checking (Option B): Not full determinism proof.

**Impact**: SEM-04 contract section on determinism defines the requirement and
references LabRuntime as the implementation with test suite as evidence.

---

## ADR-008: Outcome Severity Accepted as TLA+ Abstraction

**Status**: Approved
**Hotspot**: HOTSPOT-8 (composite score 1.60)
**Concepts**: `def.outcome.four_valued` (#29), `def.outcome.severity_lattice` (#30),
`def.outcome.join_semantics` (#31)
**Charter**: SEM-DEF-001

**Decision**: Accept TLA+ abstraction (single "Completed" terminal state).
LEAN has full severity lattice proofs (total order, transitivity, reflexivity,
antisymmetry). TLA+ deliberately simplifies for tractable model-checking.

**Rationale**: LEAN proofs are comprehensive. TLA+'s role is structural safety
checking, not semantic detail.

**Impact**: None.

---

## 2. Decision Summary

| ADR | Decision | Pathway | Follow-up |
|-----|----------|---------|-----------|
| ADR-001 | Lean proof for loser drain | Priority | New LEAN bead |
| ADR-002 | Canonical 5 + extension policy | Accept | SEM-04.2 glossary |
| ADR-003 | TLA+ abstraction accepted | Accept | None |
| ADR-004 | TLA+ abstraction accepted | Accept | None |
| ADR-005 | Incremental Lean for laws | Priority | New LEAN bead (3 laws) |
| ADR-006 | Type-system enforcement | Standard | SEM-04 contract section |
| ADR-007 | Implementation property | Standard | SEM-04 contract section |
| ADR-008 | TLA+ abstraction accepted | Accept | None |

### Action Items Generated

1. **New LEAN bead**: Combinator formalization (Race, Join, Timeout as derived Step sequences)
2. **New LEAN bead**: Prove `race_ensures_loser_drained` theorem
3. **New LEAN bead**: Prove LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN
4. **SEM-04.2**: Glossary defines canonical 5 cancel kinds + extension mapping policy
5. **SEM-04.3**: Contract encodes capability and determinism scope boundaries
6. **SEM-08.4**: Differential conformance harness for race drain timing

---

## 3. Approval Status

All 8 ADRs are approved as of 2026-03-02 per the rubric scoring framework
(SEM-03.1). No C0 escalations were required. Two Priority decisions (ADR-001,
ADR-005) generate follow-up beads for LEAN formalization work.
