# Consolidated Semantic Drift Matrix and Hotspot Index

Status: Active
Program: `asupersync-3cddg` (SEM-02.6)
Parent: SEM-02 Semantic Inventory and Drift Matrix
Author: SapphireHill
Published: 2026-03-02 UTC
Charter Reference: `docs/semantic_harmonization_charter.md`
Schema Reference: `docs/semantic_inventory_schema.md`

## 1. Purpose

This document merges the four per-layer semantic inventories into a single drift
matrix and generates a hotspot index for high-impact divergences. It is the
primary input for SEM-03 (decision framework) and SEM-04 (canonical contract).

Source inventories:
- RT: `docs/semantic_inventory_runtime.md` (47/47 concepts)
- DOC: `docs/semantic_inventory_formal_docs.md` (83 concepts mapped)
- LEAN: `docs/semantic_inventory_lean.md` (47 concepts, 30 proved)
- TLA: `docs/semantic_inventory_tla.md` (47 concepts, 7 checked)

## 2. Drift Matrix

Legend for alignment status:
- **A** = Aligned (semantics match across layers)
- **D** = Divergent (semantics differ in meaningful ways)
- **Ab** = Abstracted (present but simplified/collapsed)
- **M** = Missing (not present in layer)
- **P** = Partial (structurally encoded but not fully proved/modeled)

### 2.1 Cancellation (domain: `cancel`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 1 | `rule.cancel.request` | A | A | A | A | **Aligned** | — | All 4 layers encode cancel request with task state transition. |
| 2 | `rule.cancel.acknowledge` | A | A | A | A | **Aligned** | — | All layers: mask=0 guard, CancelRequested→Cancelling. |
| 3 | `rule.cancel.drain` | A | A | A | A | **Aligned** | — | All layers model drain transition. TLA uses CloseCancelChildren. |
| 4 | `rule.cancel.finalize` | A | A | A | A | **Aligned** | — | All layers: Cancelling→Finalizing transition. |
| 5 | `inv.cancel.idempotence` | A | A | A | Ab | **Abstracted-TLA** | I2 | TLA collapses CancelReason to BOOLEAN; strengthening monotonicity lost. RT/DOC/LEAN all prove rank-based monotone strengthening. |
| 6 | `inv.cancel.propagates_down` | A | A | A | **M** | **Missing-TLA** | I2 | TLA has no CancelPropagate/CancelChild actions. RT uses symbol_cancel propagation, LEAN has cancelPropagate+cancelChild Step constructors. |
| 7 | `def.cancel.reason_kinds` | A | A | A | Ab | **Abstracted-TLA** | I2 | RT: 11 variants. DOC: 5 variants. LEAN: 5 variants. TLA: BOOLEAN. **DOC↔RT divergent**: DOC/LEAN have 5 kinds vs RT's 11 (RT adds Deadline, PollQuota, CostBudget, RaceLost, ResourceUnavailable, LinkedExit). |
| 8 | `def.cancel.severity_ordering` | A | A | A | Ab | **Abstracted-TLA** | I2 | RT: 6-level severity. DOC: 4-level. LEAN: 4-level rank. TLA: not encoded. **DOC↔RT minor divergence**: RT has finer granularity. |
| 9 | `prog.cancel.drains` | A | A | A | M | **Missing-TLA** | I1 | TLA has no liveness checking (safety-only spec). RT: budget-bounded. LEAN: cancel_protocol_terminates with mask+3 bound. |

### 2.2 Masking (domain: `cancel`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 10 | `rule.cancel.checkpoint_masked` | A | A | A | A | **Aligned** | — | All 4 layers: mask>0 decrements mask. |
| 11 | `inv.cancel.mask_bounded` | A | A | A | A | **Aligned** | — | RT: MAX_MASK_DEPTH. LEAN: maxMaskDepth=64. TLA: MAX_MASK=2 (smaller for model-checking). Same structure. |
| 12 | `inv.cancel.mask_monotone` | A | A | A | A | **Aligned** | — | All layers: mask only decremented by checkpoint, monotone decrease. |

### 2.3 Obligations (domain: `obligation`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 13 | `rule.obligation.reserve` | A | A | A | A | **Aligned** | — | All 4 layers: creates Reserved obligation, adds to ledger. |
| 14 | `rule.obligation.commit` | A | A | A | A | **Aligned** | — | All 4 layers: Reserved→Committed, removes from ledger. |
| 15 | `rule.obligation.abort` | A | A | A | A | **Aligned** | — | All 4 layers: Reserved→Aborted, removes from ledger. |
| 16 | `rule.obligation.leak` | A | A | A | A | **Aligned** | — | All 4 layers: error state when holder completes while reserved. |
| 17 | `inv.obligation.no_leak` | A | A | A | A | **Aligned** | — | All layers: closed regions have empty ledger. TLC model-checked. |
| 18 | `inv.obligation.linear` | A | A | A | A | **Aligned** | — | All layers: terminal states absorbing. LEAN: exhaustive 22-constructor proof. TLA: structural. |
| 19 | `inv.obligation.bounded` | A | A | A | A | **Aligned** | — | All layers: reserved obligations have live holders. |
| 20 | `inv.obligation.ledger_empty_on_close` | A | A | A | A | **Aligned** | — | All layers: close requires empty ledger. |
| 21 | `prog.obligation.resolves` | A | A | A | P | **Partial-TLA** | I1 | TLA: resolution actions modeled but no liveness checking. |

### 2.4 Region Close and Quiescence (domain: `region`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 22 | `rule.region.close_begin` | A | A | A | A | **Aligned** | — | All 4 layers: Open→Closing. |
| 23 | `rule.region.close_cancel_children` | A | A | A | A | **Aligned** | — | All layers: cancel children, Closing→Draining. |
| 24 | `rule.region.close_children_done` | A | A | A | A | **Aligned** | — | All layers: guard on children completed + subs closed. |
| 25 | `rule.region.close_run_finalizer` | A | A | A | **M** | **Missing-TLA** | I2 | TLA skips finalizer step entirely. RT/DOC/LEAN all model LIFO finalizer execution. |
| 26 | `rule.region.close_complete` | A | A | A | A | **Aligned** | — | All layers: Finalizing→Closed with quiescence guard. |
| 27 | `inv.region.quiescence` | A | A | A | P | **Partial-TLA** | I1 | RT/DOC/LEAN: 4-part (children + subs + ledger + finalizers). TLA: 3-part (no finalizers). |
| 28 | `prog.region.close_terminates` | A | A | A | M | **Missing-TLA** | I1 | TLA: no liveness. LEAN: totality step proved. |

### 2.5 Severity Ordering (domain: `outcome`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 29 | `def.outcome.four_valued` | A | A | A | Ab | **Abstracted-TLA** | I2 | TLA: single "Completed" state. No severity tags. |
| 30 | `def.outcome.severity_lattice` | A | A | A | Ab | **Abstracted-TLA** | I2 | TLA: described in comments (L457-484) but not encoded. |
| 31 | `def.outcome.join_semantics` | A | A | A | M | **Missing-TLA** | I2 | TLA: no join/strengthen semantics expressible. |
| 32 | `def.cancel.reason_ordering` | A | A | A | Ab | **Abstracted-TLA** | I2 | TLA: BOOLEAN cancellation, no ordering. |

### 2.6 Structured Ownership (domain: `ownership`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 33 | `inv.ownership.single_owner` | A | A | A | A | **Aligned** | — | All layers: structural single-owner by field type. |
| 34 | `inv.ownership.task_owned` | A | A | A | A | **Aligned** | — | All layers: task's region must exist. |
| 35 | `def.ownership.region_tree` | A | A | A | A | **Aligned** | — | All layers: tree via parent/subregion fields. |
| 36 | `rule.ownership.spawn` | A | A | A | A | **Aligned** | — | All layers: create task in open region, add to children. |

### 2.7 Combinators and Loser Drain (domain: `combinator`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 37 | `comb.join` | A | A | M | M | **Missing-Formal** | I3 | Only RT and DOC. LEAN/TLA operate at primitive level. |
| 38 | `comb.race` | A | A | M | M | **Missing-Formal** | I3 | Only RT and DOC. Key for SEM-INV-004 (loser drain). |
| 39 | `comb.timeout` | A | A | M | M | **Missing-Formal** | I3 | Only RT and DOC. TLA has no time model. |
| 40 | `inv.combinator.loser_drained` | A | A | P | M | **Divergent** | **I0** | **HOTSPOT**: RT has full oracle. DOC has INV-LOSER-DRAINED. LEAN has definition only (no proof). TLA: absent. Critical correctness property with no formal proof. |
| 41 | `law.race.never_abandon` | A | A | M | M | **Missing-Formal** | I3 | RT: oracle-enforced. DOC: specified. No formal proof. |
| 42 | `law.join.assoc` | A | A | M | M | **Missing-Formal** | I2 | RT: structural (JoinAll). DOC: LAW-JOIN-ASSOC. No formal proof. |
| 43 | `law.race.comm` | A | A | M | M | **Missing-Formal** | I2 | RT: structural (RaceAll). DOC: LAW-RACE-COMM. No formal proof. |

### 2.8 Capability and Authority (domain: `capability`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 44 | `inv.capability.no_ambient` | A | A | M | M | **Missing-Formal** | I3 | RT: type-system enforcement (CapSet, sealed generics). DOC: PV4 §5. LEAN/TLA: not modeled. |
| 45 | `def.capability.cx_scope` | A | A | P | M | **Partial-Formal** | I2 | LEAN: task lookups approximate Cx scoping but no explicit capability type. |

### 2.9 Determinism (domain: `determinism`)

| # | concept_id | RT | DOC | LEAN | TLA | Alignment | Impact | Notes |
|---|-----------|-----|-----|------|-----|-----------|--------|-------|
| 46 | `inv.determinism.replayable` | A | A | P | M | **Partial** | I2 | RT: LabRuntime with seed. DOC: §8 oracle. LEAN: stuttering/tick only. TLA: nondeterministic. |
| 47 | `def.determinism.seed_equivalence` | A | A | M | M | **Missing-Formal** | I2 | RT: DetRng. DOC: §7.1 trace-equivalence. Not in LEAN/TLA. |

## 3. Alignment Summary

| Status | Count | Concepts |
|--------|-------|---------|
| **Fully Aligned** (all 4 layers) | 24 | #1-4, 10-20, 22-24, 26, 33-36 |
| **Aligned RT+DOC+LEAN, TLA abstracted** | 7 | #5, 7, 8, 29, 30, 32, 45 |
| **Aligned RT+DOC+LEAN, TLA missing** | 5 | #6, 9, 25, 28, 31 |
| **Aligned RT+DOC, partial/missing formal** | 5 | #21, 27, 40, 46, 47 |
| **Aligned RT+DOC only** | 6 | #37-39, 41-43 |
| **Total** | **47** | |

### Per-Layer Coverage

| Layer | Full | Partial/Abstracted | Missing | Coverage % |
|-------|------|--------------------|---------|-----------|
| RT | 47 | 0 | 0 | 100% |
| DOC | 47 | 0 | 0 | 100% |
| LEAN | 30 | 6 | 11 | 76.6% |
| TLA | 16 | 9 | 22 | 53.2% |

## 4. Hotspot Index

Hotspots are ranked by impact level (I4 = critical, I1 = low) and downstream
risk. These are the divergences that SEM-03 decision work must prioritize.

### HOTSPOT-1: Loser Drain Has No Formal Proof [I0 Critical]

- **Concept**: `inv.combinator.loser_drained` (#40)
- **Charter invariant**: SEM-INV-004
- **Escalation class**: C0 (correctness/safety risk)
- **Status**: RT has full oracle enforcement. DOC specifies INV-LOSER-DRAINED
  (FOS §5 :1131). LEAN defines the predicate (`LoserDrained` L274) but has
  **no proof**. TLA does not model it at all.
- **Risk**: This is a cornerstone correctness property. Without formal proof,
  we rely entirely on runtime oracle testing. A subtle scheduling scenario
  could violate loser drain without detection.
- **Downstream**: Blocks confident claims for SEM-04 contract sections on
  combinator safety. Blocks SEM-08 conformance harness for race semantics.
  Affects 8+ downstream beads.
- **Action**: Formalize `race` and `join` as derived Step sequences in Lean;
  prove LoserDrained theorem. Alternatively, extend TLA+ with combinator
  actions for exhaustive model checking.

### HOTSPOT-2: CancelReason Granularity Divergence [I2 Medium]

- **Concepts**: `def.cancel.reason_kinds` (#7), `def.cancel.severity_ordering` (#8)
- **Charter invariant**: SEM-DEF-003
- **Status**: RT has 11 CancelKind variants with 6-level severity. DOC and
  LEAN have 5 variants with 4-level rank. TLA collapses to BOOLEAN.
- **Risk**: The RT has richer semantics than the spec documents. New RT-only
  cancel kinds (Deadline, PollQuota, CostBudget, RaceLost, ResourceUnavailable,
  LinkedExit) have no formal specification backing. Strengthening monotonicity
  across all 11 kinds is only tested, not proved.
- **Downstream**: SEM-04 must decide whether the canonical contract defines
  5 or 11 cancel kinds. SEM-08 must test strengthening across all RT kinds.
- **Action**: Extend DOC/LEAN cancel kind enumerations to match RT, or
  explicitly document RT-only kinds as implementation-specific extensions.

### HOTSPOT-3: Cancel Propagation Not in TLA+ [I1 High]

- **Concept**: `inv.cancel.propagates_down` (#6)
- **Charter invariant**: SEM-INV-003
- **Status**: RT, DOC, and LEAN all model explicit downward propagation
  (cancelPropagate + cancelChild). TLA relies on implicit regionCancel
  flag without per-task propagation actions.
- **Risk**: TLA model-checking cannot verify propagation correctness.
  If the RT propagation has a subtle bug, TLC won't catch it.
- **Action**: Add CancelPropagate and CancelChild TLA+ actions, or
  document this as an accepted TLA+ abstraction with LEAN proof as
  primary assurance.

### HOTSPOT-4: Finalizer Step Missing in TLA+ [I2 Medium]

- **Concept**: `rule.region.close_run_finalizer` (#25)
- **Charter invariant**: SEM-INV-002 (quiescence depends on finalizer completion)
- **Status**: RT, DOC, and LEAN model LIFO finalizer execution. TLA skips
  from Finalizing directly to Closed.
- **Risk**: TLA quiescence check is 3-part instead of 4-part (no finalizers).
  TLC cannot verify that finalizer ordering is correct or that all finalizers
  run before close.
- **Action**: Add finalizer modeling to TLA+ (LIFO stack with
  CloseRunFinalizer action), or document as accepted abstraction.

### HOTSPOT-5: Combinator Layer Not Formalized [I1 High]

- **Concepts**: `comb.join` (#37), `comb.race` (#38), `comb.timeout` (#39),
  `law.race.never_abandon` (#41), `law.join.assoc` (#42), `law.race.comm` (#43)
- **Charter invariants**: SEM-INV-004, SEM-INV-007 (laws)
- **Status**: RT has full implementations. DOC has FOS §4 (derived
  combinators) and FOS §7 (algebraic laws). Neither LEAN nor TLA
  formalizes combinators or proves algebraic laws.
- **Risk**: Algebraic laws are specified but not machine-checked. Combinator
  rewrites in the optimizer or test oracle could silently violate laws.
- **Downstream**: SEM-04 contract needs verified law statements. SEM-08
  conformance testing needs law-checking oracles.
- **Action**: Define combinator state machines in Lean as derived Step
  sequences. Prove at least LAW-JOIN-ASSOC, LAW-RACE-COMM, and
  LAW-TIMEOUT-MIN.

### HOTSPOT-6: Capability Security Not Formally Modeled [I1 High]

- **Concepts**: `inv.capability.no_ambient` (#44), `def.capability.cx_scope` (#45)
- **Charter invariant**: SEM-INV-006
- **Status**: RT uses Rust's type system (sealed generics, CapSet lattice).
  DOC specifies Cx as algebraic effects (PV4 §5). LEAN/TLA do not model
  capability scoping at all.
- **Risk**: Capability enforcement is entirely in Rust's type system. If
  an `unsafe` block or internal API bypasses Cx, there is no formal check.
- **Action**: Add a capability parameter to Lean Step relation, or document
  that capability security is guaranteed by Rust type system and not
  independently verifiable in the small-step model.

### HOTSPOT-7: Determinism Not Formally Verified [I1 High]

- **Concepts**: `inv.determinism.replayable` (#46), `def.determinism.seed_equivalence` (#47)
- **Charter invariant**: SEM-INV-007
- **Status**: RT has LabRuntime with seed-based determinism. DOC has FOS §7
  (trace equivalence) and §8 (oracle). LEAN has stuttering simulation and
  tick-always-available but no full bisimulation. TLA is nondeterministic.
- **Risk**: Determinism is a runtime property tied to scheduler
  implementation. The formal models are intentionally nondeterministic.
  No machine-checked proof that the lab scheduler is deterministic.
- **Action**: Define deterministic scheduler refinement in Lean (or TLA+
  with fairness), or document determinism as an implementation property
  outside formal model scope.

### HOTSPOT-8: Outcome Severity Not in TLA+ [I2 Medium]

- **Concepts**: `def.outcome.four_valued` (#29), `def.outcome.severity_lattice` (#30),
  `def.outcome.join_semantics` (#31)
- **Charter invariant**: SEM-DEF-001
- **Status**: RT: full 4-valued outcome with severity lattice and join.
  DOC: full specification. LEAN: full encoding with total order proof.
  TLA: single "Completed" state, severity in comments only.
- **Risk**: TLC cannot check severity-dependent properties (e.g.,
  supervisor restart eligibility). If severity join has edge cases,
  they won't be found by model checking.
- **Action**: Add taskOutcome variable to TLA+ with severity, or
  accept as abstraction with LEAN proof as primary assurance.

## 5. Risk Summary by Charter Invariant

| Charter Invariant | Overall Status | Hotspot Refs | Recommendation |
|-------------------|---------------|-------------|----------------|
| SEM-INV-001 Structured Ownership | **Aligned** | — | No action needed. All 4 layers consistent. |
| SEM-INV-002 Region Close = Quiescence | **Mostly Aligned** | HOTSPOT-4 | TLA+ finalizer gap is low risk (LEAN proof covers). Accept or add. |
| SEM-INV-003 Cancellation Protocol | **Mostly Aligned** | HOTSPOT-2, -3 | CancelReason granularity needs decision. TLA+ propagation gap. |
| SEM-INV-004 Loser Drain | **CRITICAL GAP** | HOTSPOT-1, -5 | No formal proof anywhere. Highest priority for SEM-03/04. |
| SEM-INV-005 No Obligation Leak | **Aligned** | — | Fully proved in LEAN, checked in TLA+. |
| SEM-INV-006 No Ambient Authority | **RT-Only** | HOTSPOT-6 | Type-system enforcement only. Document limitation. |
| SEM-INV-007 Deterministic Replayability | **RT-Only** | HOTSPOT-7 | Implementation property. Document scope boundary. |

## 6. Recommended Resolution Priority

For SEM-03 (Decision Framework) and SEM-04 (Canonical Contract):

| Priority | Hotspot | Action | Effort |
|:--------:|---------|--------|:------:|
| P0 | HOTSPOT-1 (loser drain) | Lean combinator formalization | High |
| P0 | HOTSPOT-3 (cancel propagation) | TLA+ action additions | Medium |
| P1 | HOTSPOT-5 (combinator layer) | Lean derived state machines | High |
| P1 | HOTSPOT-6 (no ambient authority) | ADR: accept type-system-only or formalize | Low |
| P1 | HOTSPOT-7 (determinism) | ADR: accept runtime-only or formalize scheduler | Medium |
| P2 | HOTSPOT-2 (severity granularity) | Extend DOC/LEAN to match RT or document RT extensions | Low |
| P2 | HOTSPOT-4 (finalizer in TLA) | TLA+ action addition | Low |
| P2 | HOTSPOT-8 (outcome in TLA) | TLA+ state additions | Low |

## 7. Downstream Dependencies

This drift matrix feeds:
- **SEM-03.1**: Divergence evaluation rubric uses hotspot impact levels
- **SEM-03.2**: Candidate options for each divergent/ambiguous row
- **SEM-03.3**: Witness/counterexample pack for disputed semantics
- **SEM-04.1**: Contract schema must cover all 47 concepts
- **SEM-08.1**: Runtime-vs-contract gap matrix by rule ID
