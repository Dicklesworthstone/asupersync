# Divergence Evaluation Rubric and Scoring Template

Status: Active
Program: `asupersync-3cddg` (SEM-03.1)
Parent: SEM-03 Decision Framework and ADR Resolution
Author: SapphireHill
Published: 2026-03-02 UTC
Charter Reference: `docs/semantic_harmonization_charter.md`
Drift Matrix Reference: `docs/semantic_drift_matrix.md`

## 1. Purpose

This document defines a formal evaluation rubric for scoring semantic
divergences identified in the drift matrix. Every divergence decision in SEM-03
uses this rubric, ensuring comparable, auditable, and traceable outcomes.

The rubric produces a composite score that determines priority and resolution
pathway for each hotspot.

## 2. Scoring Dimensions

Each divergence is scored on 6 dimensions, each rated 1-5:

### D1: Safety Impact (weight: 0.30)

How severely could this divergence cause correctness or safety violations?

| Score | Meaning | Examples |
|-------|---------|---------|
| 5 | **Critical**: live invariant violation risk | Loser drain failure → orphan tasks |
| 4 | **High**: correctness gap under adversarial scheduling | Cancel propagation gap → missed cancellation |
| 3 | **Medium**: semantic mismatch with bounded blast radius | Severity ordering difference → wrong restart decision |
| 2 | **Low**: cosmetic or documentation-only divergence | Extra RT cancel kinds not in spec |
| 1 | **Negligible**: no observable behavioral difference | Naming convention differences |

### D2: Determinism Impact (weight: 0.15)

Does this divergence affect deterministic replay or seed equivalence?

| Score | Meaning |
|-------|---------|
| 5 | Replay diverges under affected schedules |
| 4 | Non-determinism in edge cases |
| 3 | Determinism preserved but trace format differs |
| 2 | No determinism impact but limits oracle coverage |
| 1 | No impact on determinism |

### D3: Formal Proof Cost (weight: 0.15)

How expensive would it be to close this gap with a Lean/TLA+ proof?

| Score | Meaning |
|-------|---------|
| 5 | Requires new theory development (months) |
| 4 | Major proof effort (weeks, new definitions) |
| 3 | Moderate effort (existing patterns, ~days) |
| 2 | Small extension of existing proofs (~hours) |
| 1 | Already proved or trivial to prove |

### D4: Model-Check Tractability (weight: 0.10)

Can TLC verify this property within feasible state-space bounds?

| Score | Meaning |
|-------|---------|
| 5 | Requires unbounded state space (infeasible) |
| 4 | Requires large constants, impractical runtime |
| 3 | Feasible with moderate constant increase |
| 2 | Feasible with current bounds |
| 1 | Already model-checked |

### D5: Runtime Complexity (weight: 0.15)

What is the implementation complexity of aligning this divergence?

| Score | Meaning |
|-------|---------|
| 5 | Deep architectural change, multi-module refactor |
| 4 | Significant code changes with regression risk |
| 3 | Moderate changes, well-contained |
| 2 | Minor code additions or config changes |
| 1 | No runtime changes needed (spec-only resolution) |

### D6: Operational Maintainability (weight: 0.15)

How does resolving this affect long-term maintenance burden?

| Score | Meaning |
|-------|---------|
| 5 | Creates ongoing synchronization overhead across all layers |
| 4 | Requires periodic re-verification |
| 3 | One-time alignment with stable maintenance |
| 2 | Reduces maintenance by eliminating drift source |
| 1 | Already aligned, no additional maintenance |

## 3. Composite Score Calculation

```
Priority = (D1 × 0.30) + (D2 × 0.15) + (D3 × 0.15) + (D4 × 0.10) + (D5 × 0.15) + (D6 × 0.15)
```

Range: 1.0 (lowest priority) to 5.0 (highest priority).

### Resolution Pathway Mapping

| Composite Score | Resolution Pathway | Charter SLA |
|----------------|-------------------|-------------|
| 4.0 - 5.0 | **Immediate**: escalate per SEM-ESC-001 C0 | Triage 24h, decision 48h |
| 3.0 - 3.9 | **Priority**: ADR with full alternatives analysis | Triage 72h, decision 5d |
| 2.0 - 2.9 | **Standard**: document and schedule for next SEM gate | Next SEM phase gate |
| 1.0 - 1.9 | **Accept**: document as known limitation or accepted abstraction | No action required |

## 4. Decision Record Template

Every scored divergence produces an ADR using this template:

```markdown
### ADR-HOTSPOT-<N>: <Title>

**Hotspot**: HOTSPOT-<N> from drift matrix
**Concepts**: <concept_ids>
**Charter invariants**: <SEM-INV-xxx, SEM-DEF-xxx>

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | N | ... |
| D2 Determinism Impact | N | ... |
| D3 Formal Proof Cost | N | ... |
| D4 Model-Check Tractability | N | ... |
| D5 Runtime Complexity | N | ... |
| D6 Operational Maintainability | N | ... |
| **Composite** | **N.NN** | |

#### Resolution Pathway: <Immediate|Priority|Standard|Accept>

#### Options Considered

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| A | ... | ... | ... |
| B | ... | ... | ... |
| C (status quo) | ... | ... | ... |

#### Decision

**Chosen**: Option <X>
**Rationale**: ...
**Rejected alternatives**: ...
**Owner**: ...
**Due date**: ...
**Follow-up beads**: ...

#### Witnesses/Evidence

- <link to test, trace, or formal artifact>
```

## 5. Hotspot Scoring

### ADR-HOTSPOT-1: Loser Drain Has No Formal Proof

**Hotspot**: HOTSPOT-1 from drift matrix
**Concepts**: `inv.combinator.loser_drained` (#40)
**Charter invariants**: SEM-INV-004

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 5 | Live correctness property — race losers not drained = orphan tasks + resource leaks |
| D2 Determinism Impact | 3 | Loser drain failure visible in replays, but replay still deterministic |
| D3 Formal Proof Cost | 4 | Requires defining combinators as derived Step sequences in Lean (new theory) |
| D4 Model-Check Tractability | 3 | Feasible in TLA+ with combinator encoding + moderate constants |
| D5 Runtime Complexity | 1 | No runtime changes needed — RT implementation is correct, gap is formal |
| D6 Operational Maintainability | 3 | One-time proof; stable once combinators are defined |
| **Composite** | **3.55** | |

#### Resolution Pathway: Priority

#### Options Considered

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| A | Add Lean combinator definitions + LoserDrained proof | Machine-checked assurance; closes gap fully | High effort (weeks); requires new Lean theory |
| B | Add TLA+ combinator actions + TLC invariant check | Exhaustive for bounded case; cheaper than Lean | Not a proof; limited by state-space bounds |
| C | Strengthen runtime oracle + property tests | Increases empirical coverage; no formal model changes | No formal guarantee; gap remains |
| D (status quo) | Document as accepted limitation | Zero effort | Violates charter SEM-GOAL-002 (deterministic evidence) |

#### Decision

**Chosen**: Option A + C (Lean proof + strengthened oracle)
**Rationale**: SEM-INV-004 is a charter non-negotiable. Runtime oracle provides
empirical coverage during the proof development window. LEAN proof provides
the permanent machine-checked guarantee.
**Rejected alternatives**: B (bounded, not sufficient for charter), D (violates charter)
**Owner**: Formal methods contributors (LEAN/TLA+ owners)
**Follow-up beads**: SEM-08.4 (differential conformance), new LEAN bead for combinator formalization

#### Witnesses/Evidence

- RT oracle: `src/lab/oracle/loser_drain.rs:90-99`
- LEAN predicate (definition only): `formal/lean/Asupersync.lean:274`
- FOS invariant: `asupersync_v4_formal_semantics.md` §INV-LOSER-DRAIN (root canonical copy; line 1131 in the now-retired `docs/` snapshot)

---

### ADR-HOTSPOT-2: CancelReason Granularity Divergence

**Hotspot**: HOTSPOT-2 from drift matrix
**Concepts**: `def.cancel.reason_kinds` (#7), `def.cancel.severity_ordering` (#8)
**Charter invariants**: SEM-DEF-003

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 2 | Additional RT kinds don't violate invariants; they refine behavior |
| D2 Determinism Impact | 1 | No determinism impact — all kinds map to existing severity levels |
| D3 Formal Proof Cost | 2 | Extending Lean CancelKind inductive with 6 more constructors is mechanical |
| D4 Model-Check Tractability | 3 | Adding severity to TLA+ increases state space moderately |
| D5 Runtime Complexity | 1 | No runtime changes — gap is spec/formal side only |
| D6 Operational Maintainability | 3 | Adding kinds to spec requires updating all formal layers |
| **Composite** | **1.90** | |

#### Resolution Pathway: Accept (with documentation)

#### Options Considered

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| A | Extend DOC/LEAN/TLA+ to 11 RT kinds | Full alignment | High effort for marginal safety benefit |
| B | Define 5 "canonical" kinds + document RT extensions | Spec stays clean; RT has freedom | Dual taxonomy to maintain |
| C (status quo) | Document divergence in contract | Minimal effort | Unresolved drift |

#### Decision

**Chosen**: Option B
**Rationale**: The 5 DOC/LEAN kinds capture the fundamental cancel semantics.
RT's 6 additional kinds (Deadline, PollQuota, CostBudget, RaceLost,
ResourceUnavailable, LinkedExit) are implementation refinements that map
cleanly to the canonical severity levels. The contract should define the
canonical 5 kinds and declare RT extensions as implementation-specific with
mandatory severity mapping.
**Rejected alternatives**: A (effort/benefit ratio too high), C (unactionable)
**Owner**: SEM-04 contract authors
**Follow-up beads**: SEM-04.2 (glossary should include extension policy)

---

### ADR-HOTSPOT-3: Cancel Propagation Not in TLA+

**Hotspot**: HOTSPOT-3 from drift matrix
**Concepts**: `inv.cancel.propagates_down` (#6)
**Charter invariants**: SEM-INV-003

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 3 | Propagation bug would orphan subtree; but LEAN proof covers |
| D2 Determinism Impact | 1 | No determinism impact |
| D3 Formal Proof Cost | 1 | Already proved in LEAN (cancelPropagate + cancelChild) |
| D4 Model-Check Tractability | 2 | Adding 2 TLA+ actions is straightforward |
| D5 Runtime Complexity | 1 | No runtime changes |
| D6 Operational Maintainability | 2 | Small TLA+ addition, stable |
| **Composite** | **1.95** | |

#### Resolution Pathway: Accept (LEAN proof is sufficient)

#### Decision

**Chosen**: Accept TLA+ abstraction; LEAN proof is primary assurance
**Rationale**: LEAN has full mechanized proofs for cancelPropagate and
cancelChild. Adding to TLA+ would provide defense-in-depth but is not
required by the charter (SEM-GOV-003: formal artifacts are authoritative).
**Follow-up**: Optional TLA+ enhancement can be tracked as a low-priority bead.

---

### ADR-HOTSPOT-4: Finalizer Step Missing in TLA+

**Hotspot**: HOTSPOT-4 from drift matrix
**Concepts**: `rule.region.close_run_finalizer` (#25)
**Charter invariants**: SEM-INV-002

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 2 | Finalizer bugs would affect cleanup but not structural invariants |
| D2 Determinism Impact | 1 | No determinism impact |
| D3 Formal Proof Cost | 1 | Already proved in LEAN (closeRunFinalizer) |
| D4 Model-Check Tractability | 2 | Adding finalizer stack to TLA+ is moderate |
| D5 Runtime Complexity | 1 | No runtime changes |
| D6 Operational Maintainability | 2 | TLA+ finalizer model adds maintenance |
| **Composite** | **1.60** | |

#### Resolution Pathway: Accept

#### Decision

**Chosen**: Accept TLA+ abstraction. LEAN proves finalizer execution.
TLA+ 3-part quiescence (without finalizers) is a documented simplification.

---

### ADR-HOTSPOT-5: Combinator Layer Not Formalized

**Hotspot**: HOTSPOT-5 from drift matrix
**Concepts**: `comb.join` (#37), `comb.race` (#38), `comb.timeout` (#39),
`law.race.never_abandon` (#41), `law.join.assoc` (#42), `law.race.comm` (#43)
**Charter invariants**: SEM-INV-004, SEM-INV-007

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 4 | Algebraic laws are optimization prerequisites; violations cause silent bugs |
| D2 Determinism Impact | 2 | Laws affect optimizer correctness, not runtime determinism directly |
| D3 Formal Proof Cost | 4 | Full combinator theory in Lean is a research-level effort |
| D4 Model-Check Tractability | 3 | TLA+ combinator actions feasible but increase state space significantly |
| D5 Runtime Complexity | 1 | No runtime changes |
| D6 Operational Maintainability | 4 | Combinator proofs must track RT implementation changes |
| **Composite** | **3.15** | |

#### Resolution Pathway: Priority

#### Decision

**Chosen**: Incremental formalization — define combinators in Lean as
derived Step sequences, prove the 3 highest-impact laws first
(LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN), defer the rest.
**Rationale**: Full combinator theory is high effort. Incremental approach
gives machine-checked coverage for the most-used rewrite rules while
managing proof maintenance cost.
**Follow-up beads**: New LEAN formalization bead for combinator definitions + 3 law proofs.

---

### ADR-HOTSPOT-6: Capability Security Not Formally Modeled

**Hotspot**: HOTSPOT-6 from drift matrix
**Concepts**: `inv.capability.no_ambient` (#44), `def.capability.cx_scope` (#45)
**Charter invariants**: SEM-INV-006

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 3 | Ambient authority bypass would undermine isolation guarantees |
| D2 Determinism Impact | 1 | No determinism impact |
| D3 Formal Proof Cost | 5 | Modeling capabilities in small-step semantics is research-level |
| D4 Model-Check Tractability | 5 | Capability checking requires type-system-level reasoning |
| D5 Runtime Complexity | 1 | Already enforced by Rust type system |
| D6 Operational Maintainability | 2 | Rust compiler catches violations at compile time |
| **Composite** | **2.80** | |

#### Resolution Pathway: Standard (document as out-of-scope for small-step model)

#### Decision

**Chosen**: Document capability security as a Rust type-system invariant
outside the scope of the small-step operational model. The contract
(SEM-04) should reference the CapSet lattice and sealed-generics
mechanism as the enforcement layer.
**Rationale**: Modeling capabilities in the small-step semantics would
require a dependent type system. The Rust compiler's enforcement is
the correct verification layer for this property.

---

### ADR-HOTSPOT-7: Determinism Not Formally Verified

**Hotspot**: HOTSPOT-7 from drift matrix
**Concepts**: `inv.determinism.replayable` (#46), `def.determinism.seed_equivalence` (#47)
**Charter invariants**: SEM-INV-007

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 2 | Replay divergence is a testing/debugging concern, not safety |
| D2 Determinism Impact | 5 | This IS the determinism property |
| D3 Formal Proof Cost | 4 | Scheduler determinization proof is substantial |
| D4 Model-Check Tractability | 4 | Requires fairness constraints + deterministic Next |
| D5 Runtime Complexity | 1 | Already implemented (LabRuntime + DetRng) |
| D6 Operational Maintainability | 3 | Proof must track scheduler implementation |
| **Composite** | **2.90** | |

#### Resolution Pathway: Standard

#### Decision

**Chosen**: Document determinism as an implementation property of
LabRuntime. The contract defines the determinism requirement and
the runtime test suite provides empirical verification.
**Rationale**: The formal models are intentionally nondeterministic
to enable DPOR-style schedule exploration. Determinism is a
scheduler-implementation property that would require a separate
refinement proof.

---

### ADR-HOTSPOT-8: Outcome Severity Not in TLA+

**Hotspot**: HOTSPOT-8 from drift matrix
**Concepts**: `def.outcome.four_valued` (#29), `def.outcome.severity_lattice` (#30),
`def.outcome.join_semantics` (#31)
**Charter invariants**: SEM-DEF-001

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| D1 Safety Impact | 2 | Severity affects supervisor restart, not core invariants |
| D2 Determinism Impact | 1 | No determinism impact |
| D3 Formal Proof Cost | 1 | LEAN already has full severity lattice proofs |
| D4 Model-Check Tractability | 2 | Adding severity to TLA+ is straightforward |
| D5 Runtime Complexity | 1 | No runtime changes |
| D6 Operational Maintainability | 2 | Small TLA+ addition |
| **Composite** | **1.60** | |

#### Resolution Pathway: Accept

#### Decision

**Chosen**: Accept TLA+ abstraction. LEAN proves severity lattice properties
(total order, transitivity, reflexivity, antisymmetry). TLA+ deliberately
simplifies for tractable model-checking.

## 6. Priority Summary

| Hotspot | Composite Score | Resolution | Action Required |
|---------|----------------|------------|----------------|
| HOTSPOT-1 (Loser drain) | **3.55** | Priority | Lean combinator proof + oracle strengthening |
| HOTSPOT-5 (Combinators) | **3.15** | Priority | Incremental Lean combinator formalization |
| HOTSPOT-7 (Determinism) | **2.90** | Standard | Document as implementation property |
| HOTSPOT-6 (Capability) | **2.80** | Standard | Document as type-system enforcement |
| HOTSPOT-3 (Cancel propagation) | **1.95** | Accept | LEAN proof sufficient |
| HOTSPOT-2 (Cancel reasons) | **1.90** | Accept | Canonical 5 + RT extensions policy |
| HOTSPOT-4 (Finalizers) | **1.60** | Accept | LEAN proof sufficient |
| HOTSPOT-8 (Severity) | **1.60** | Accept | LEAN proof sufficient |

### Immediate Actions for SEM-03.2+

1. **Priority hotspots** (HOTSPOT-1, -5): SEM-03.2 must enumerate formal
   proof options and schedule LEAN formalization work.
2. **Standard hotspots** (HOTSPOT-6, -7): SEM-03.4 records these as ADR
   decisions with explicit scope boundaries.
3. **Accepted hotspots** (HOTSPOT-2, -3, -4, -8): SEM-03.4 records these
   with LEAN-as-primary-assurance rationale.
