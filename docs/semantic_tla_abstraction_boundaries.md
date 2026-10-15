# TLA+ Abstraction Boundaries and Runtime Correspondence (SEM-07.5)

**Bead**: `asupersync-3cddg.7.5`
**Parent**: SEM-07 Projection Track: TLA Model and Invariant Alignment
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines where the TLA+ model intentionally abstracts runtime behavior, why those abstractions are sound for the target safety properties, and how each TLA+ construct corresponds to runtime and Lean equivalents. It serves as the reviewer reference for understanding what the model checks, what it deliberately omits, and which other assurance layers cover the gaps.

---

## 2. Abstraction Philosophy

The TLA+ model is a **bounded safety-checking projection** of the asupersync runtime. It trades fidelity for tractable exhaustive exploration:

- **Finite sets** replace dynamic populations (tasks, regions, obligations)
- **Boolean flags** replace rich enums (cancel reason, outcome severity)
- **State transitions** replace effectful operations (finalizer bodies)
- **Nondeterminism** replaces deterministic scheduling (LabRuntime replay)

Each abstraction is approved by a specific ADR decision and covered by an alternative assurance layer (Lean proof, runtime oracle, or type-system enforcement).

---

## 3. Abstraction Inventory

### 3.1 Cancel Reason Collapsed to Boolean (ADR-003)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Cancel kind | 5 canonical + 6 extension CancelKind variants | Single boolean `regionCancel[r]` |
| Severity | Integer 0-5 with rank-based strengthening | Not modeled |
| Propagation | Direct children + subregions with depth | Direct children only (`CloseCancelChildren`) |

**Soundness**: The TLA+ model verifies that cancel *requests* propagate to direct children and that tasks transition through the cancel protocol correctly. Severity strengthening and deep propagation are covered by Lean proofs (`Step.cancelPropagate` L499-511, `Step.cancelChild`).

**Rules affected**: #5 (idempotent), #6 (propagation — Lean only), #7 (severity — Lean only), #8 (mask deferral)

### 3.2 Outcome Severity Abstracted (ADR-008)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Outcome values | Ok(0), Err(1), Cancelled(2), Panicked(3) | Single "Completed" terminal state |
| Severity lattice | max-rank join semantics | Not modeled |
| Restart eligibility | Severity-gated | Not modeled |

**Soundness**: TLA+ verifies task lifecycle completion regardless of outcome kind. The four-valued severity lattice and join semantics are proved in Lean.

**Rules affected**: #29 (severity ordering — Lean), #30 (join max-rank — Lean), #31 (restart — Lean), #32 (outcome determinism — Lean)

### 3.3 Finalizer Body Abstracted (ADR-004)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Finalizer execution | LIFO stack with closure capture and effects | State transition ChildrenDone → Finalizing → Quiescent |
| Side effects | Arbitrary user code | Abstracted away |

**Soundness**: TLA+ verifies the finalizer *protocol* (ordering, preconditions for state transitions) but not the body. Lean proofs cover finalizer effects (`Step.closeRunFinalizer` L571-579).

**Rules affected**: #25 (finalizer ordering — Lean primary, TLA+ state progression)

### 3.4 Mask Depth Bounded (Assumption)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Mask depth range | 0..64 | 0..MAX_MASK (default 2) |
| Overflow behavior | Runtime panics at 64 | `AssumptionEnvelopeInvariant` checks bound |

**Soundness**: TLA+ invariants `MaskBoundedInvariant` and `MaskMonotoneInvariant` hold for any `MAX_MASK` value. Scenario S5 extends to MAX_MASK=3 for deeper coverage.

**Rules affected**: #11 (mask bounded), #12 (mask monotone)

### 3.5 No Time or Deadline Modeling (Abstraction)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Wall-clock time | Full deadline tracking, timeout callbacks | Not modeled |
| Timeout combinator | Deadline-based cancellation | Not modeled |

**Soundness**: Timeout is a derived combinator (ADR-005) covered by runtime oracle tests. TLA+ verifies the underlying cancel and region mechanics that timeouts depend on.

**Rules affected**: #39 (timeout minimum — runtime oracle), #43 (budget cost — runtime oracle)

### 3.6 Obligation Kind Collapsed (Abstraction)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Obligation kinds | Lease, Guard, Spork, Custom | Single generic obligation |
| Kind-specific behavior | Lease renewal, guard release, spork reply | Only state transitions (Reserved → Committed/Aborted/Leaked) |

**Soundness**: TLA+ verifies the universal obligation lifecycle invariants (`NoLeakedObligations`, ledger cleanup on close). Kind-specific semantics are covered by Lean proofs and runtime tests.

**Rules affected**: #17 (leak on close), #18 (reserve precondition), #19 (commit/abort), #20 (close gate)

### 3.7 Combinators Not Modeled (ADR-005)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Join | Associative, commutative multi-task await | Not modeled |
| Race | First-to-complete with loser drain | Not modeled |
| Timeout | Deadline-based cancel with minimum guarantee | Not modeled |

**Soundness**: Combinator rules (#37-43) are tested via runtime oracle law tests. Incremental Lean formalization is pending. TLA+ verifies the primitive task/region/cancel machinery that combinators compose over.

**Rules affected**: #37-43 (all — runtime oracle + pending Lean)

### 3.8 Capability Security Not Modeled (ADR-006)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Cx token | Type-system capability isolation | Not modeled; actions use bare IDs |
| Authority checks | Compile-time Rust type enforcement | Not modeled |

**Soundness**: Capability isolation is enforced by Rust's type system and `#![deny(unsafe_code)]`. It is a compile-time property, not a state-space property.

**Rules affected**: #44 (Cx unforgeable), #45 (ambient denied)

### 3.9 Determinism Not Modeled (ADR-007)

| Aspect | Runtime | TLA+ Model |
|--------|---------|------------|
| Scheduling | LabRuntime provides deterministic replay via SEED | Nondeterministic `Next` relation |
| Reproducibility | Seed-based schedule reconstruction | TLC explores all interleavings |

**Soundness**: TLA+ nondeterminism is *stronger* than determinism for safety checking — if no violation exists under any interleaving, no deterministic schedule can violate either. Deterministic replay is verified by LabRuntime test infrastructure.

**Rules affected**: #46 (replay determinism), #47 (schedule reconstruction)

---

## 4. State Correspondence Table

### 4.1 Variables

| TLA+ Variable | Runtime Type | Location | Notes |
|---------------|-------------|----------|-------|
| `taskState[t]` | `TaskEntry.state` | `src/record/task.rs` | Direct enum correspondence |
| `taskRegion[t]` | `TaskEntry.region_id` | `src/record/task.rs` | Single-owner invariant |
| `taskMask[t]` | `Cx.mask_depth` | `src/cx/cx.rs` | Cancel deferral depth counter |
| `regionState[r]` | `RegionEntry.state` | `src/record/region.rs` | Lifecycle state enum |
| `regionChildren[r]` | `RegionEntry.children` | `src/record/region.rs` | Task membership set |
| `regionSubs[r]` | `RegionEntry.subregions` | `src/record/region.rs` | Region tree structure |
| `regionLedger[r]` | `RegionEntry.obligations` | `src/record/region.rs` | Active reserved obligations |
| `regionCancel[r]` | `RegionEntry.cancel_requested` | `src/record/region.rs` | Boolean cancel flag |
| `obState[o]` | `ObligationEntry.state` | `src/record/obligation.rs` | Lifecycle state enum |
| `obHolder[o]` | `ObligationEntry.holder` | `src/record/obligation.rs` | Task ownership |
| `obRegion[o]` | `ObligationEntry.region` | `src/record/obligation.rs` | Region ledger membership |

### 4.2 State Enums

**Task lifecycle**:
| TLA+ | Lean | Runtime |
|------|------|---------|
| "Spawned" | TaskState.Spawned | TaskState::Spawned |
| "Running" | TaskState.Running | TaskState::Running |
| "CancelRequested" | TaskState.CancelRequested | TaskState::CancelRequested |
| "CancelMasked" | TaskState.CancelMasked | TaskState::CancelMasked |
| "CancelAcknowledged" | TaskState.CancelAcknowledged | TaskState::CancelAcknowledged |
| "Finalizing" | TaskState.Finalizing | TaskState::Finalizing |
| "Completed" | TaskState.Completed | TaskState::Completed |

**Region lifecycle**:
| TLA+ | Lean | Runtime |
|------|------|---------|
| "Open" | RegionState.Open | RegionState::Open |
| "Closing" | RegionState.Closing | RegionState::Closing |
| "ChildrenDone" | RegionState.ChildrenDone | RegionState::ChildrenDone |
| "Finalizing" | RegionState.Finalizing | RegionState::Finalizing |
| "Quiescent" | RegionState.Quiescent | RegionState::Quiescent |
| "Closed" | RegionState.Closed | RegionState::Closed |

**Obligation lifecycle**:
| TLA+ | Lean | Runtime |
|------|------|---------|
| "Reserved" | ObligationState.Reserved | ObligationState::Reserved |
| "Committed" | ObligationState.Committed | ObligationState::Committed |
| "Aborted" | ObligationState.Aborted | ObligationState::Aborted |
| "Leaked" | ObligationState.Leaked | ObligationState::Leaked |

---

## 5. Action Correspondence Table

| TLA+ Action | Lean Step | Runtime Function | Spec Line |
|-------------|-----------|------------------|-----------|
| `Spawn(t, r)` | `Step.spawn` | `region.rs:spawn()` | L176-187 |
| `TaskRun(t)` | `Step.run` | (scheduler dispatch) | L189-195 |
| `CancelRequest(t)` | `Step.cancelRequest` | `cancel.rs:request_cancel()` | L209-219 |
| `CancelMasked(t)` | `Step.cancelMasked` | `cx.rs:checkpoint()` | L221-229 |
| `CancelAcknowledge(t)` | `Step.cancelAcknowledge` | `cancel.rs:acknowledge()` | L231-244 |
| `CancelFinalize(t)` | `Step.cancelFinalize` | `cancel.rs:finalize()` | L246-256 |
| `TaskComplete(t)` | `Step.complete` | `task.rs:complete()` | L258-263 |
| `CloseBegin(r)` | `Step.closeBegin` | `region.rs:close()` | L263-270 |
| `CloseCancelChildren(r)` | `Step.closeCancelChildren` | `region.rs:cancel_children()` | L272-287 |
| `CloseChildrenDone(r)` | `Step.closeChildrenDone` | `region.rs:check_quiescence()` | L289-301 |
| `CloseRunFinalizer(r)` | `Step.closeRunFinalizer` | (finalizer execution) | L303-315 |
| `Close(r)` | `Step.close` | `region.rs:complete()` | L317-325 |
| `ReserveObligation(o,t,r)` | `Step.reserve` | `obligation.rs:reserve()` | L306-319 |
| `CommitObligation(o)` | `Step.commit` | `obligation.rs:commit()` | L321-330 |
| `AbortObligation(o)` | `Step.abort` | `obligation.rs:abort()` | L332-341 |
| `LeakObligation(o)` | `Step.leak` | (leak detection during close) | L343-353 |

---

## 6. Invariant Correspondence

### 6.1 Safety Invariants

| TLA+ Invariant | Canonical Rule | Lean Theorem | Runtime Test |
|----------------|---------------|-------------|-------------|
| `TypeInvariant` | (structural) | `State.wellFormed` | Type system |
| `WellFormedInvariant` | (structural) | `State.wellFormed` | Constructor invariants |
| `NoOrphanTasks` | #34 | `no_orphan_tasks` | Region close tests |
| `NoLeakedObligations` | #17, #20 | `no_leaked_obligations` | Obligation lifecycle tests |
| `CloseImpliesQuiescent` | #27 | `close_implies_quiescent` | Region close tests |
| `MaskBoundedInvariant` | #11 | `mask_bounded` | Cancel mask tests |
| `MaskMonotoneInvariant` | #12 | `mask_monotone` | Cancel mask tests |
| `CancelIdempotenceStructural` | #5 | `cancel_idempotent` | Cancel protocol tests |
| `ReplyLinearityInvariant` | SINV-1 | `reply_linearity` | Spork tests |
| `RegistryLeaseInvariant` | SINV-3 | `registry_lease` | Spork tests |
| `AssumptionEnvelopeInvariant` | (meta) | — | — |

### 6.2 Liveness Property

| TLA+ Property | Canonical Rule | Lean Theorem | Checking Mode |
|---------------|---------------|-------------|--------------|
| `CancelTerminates` | #4 | `cancel_protocol_terminates` | Requires `LiveSpec` with `WF_vars(Next)` fairness |

### 6.3 Invariants Not in TLA+ (Covered Elsewhere)

| Rule | Name | Assurance Layer | Rationale |
|------|------|----------------|-----------|
| #6 | cancel propagation | Lean | ADR-003: subregion depth abstracted |
| #7 | severity strengthening | Lean | ADR-003: severity collapsed |
| #25 | finalizer ordering | Lean (primary) | ADR-004: body abstracted |
| #29-32 | outcome severity | Lean | ADR-008: severity collapsed |
| #37-43 | combinator laws | Runtime oracle | ADR-005: not modeled |
| #44-45 | capability security | Rust type system | ADR-006: compile-time |
| #46-47 | determinism | Runtime (LabRuntime) | ADR-007: implementation property |

---

## 7. ADR Decision Cross-Reference

| ADR | Decision | TLA+ Impact | Alternative Assurance |
|-----|----------|-------------|----------------------|
| ADR-003 | Cancel propagation projected to direct children | `CloseCancelChildren` only does direct children; no severity | Lean `Step.cancelPropagate` + `Step.cancelChild` |
| ADR-004 | Finalizer body abstracted | State transitions modeled; body effects skipped | Lean `Step.closeRunFinalizer` |
| ADR-005 | Combinator rules not modeled | Join/Race/Timeout absent from spec | Runtime oracle law tests |
| ADR-006 | Capability security is type-system property | No Cx token in model; actions use bare IDs | Rust `#![deny(unsafe_code)]` + Cx type |
| ADR-007 | Determinism scoped to LabRuntime | `Next` is intentionally nondeterministic | LabRuntime replay test suite |
| ADR-008 | Outcome severity abstracted | Single "Completed" terminal state | Lean severity lattice proofs |

---

## 8. Spork Integration

The TLA+ model includes two Spork-specific invariants that independently validate Lean proof claims:

### 8.1 ReplyLinearityInvariant (SINV-1)

**Claim**: Every obligation reserved during a region's lifetime must be resolved (committed, aborted, or detected as leaked) before the region transitions to Closed.

**TLA+ formulation**: For all regions `r` in state "Closed", `regionLedger[r] = {}`.

**Lean correspondence**: `reply_linearity` theorem proves that `Step.close` requires empty ledger.

**Runtime correspondence**: `obligation.rs:check_close_gate()` enforces ledger-empty precondition.

### 8.2 RegistryLeaseInvariant (SINV-3)

**Claim**: The obligation registry maintains exclusive ownership — no obligation appears in multiple region ledgers simultaneously.

**TLA+ formulation**: For all obligations `o` in state "Reserved", exactly one region `r` has `o ∈ regionLedger[r]`.

**Lean correspondence**: `registry_lease` theorem proves single-owner via `ObligationEntry.region` uniqueness.

**Runtime correspondence**: `obligation.rs:reserve()` enforces exclusive registration.

---

## 9. Soundness Argument

### 9.1 Why Abstractions Are Safe

The TLA+ model is sound for its target properties because:

1. **Conservative projection**: Every abstraction *removes* information, never adds false capabilities. If a safety property holds in the abstracted model, it holds in any refinement.

2. **Explicit assumption envelope**: The `AssumptionEnvelopeInvariant` explicitly checks that model execution stays within declared bounds. Violations would indicate the model is exploring unreachable states.

3. **Complementary layers**: Each abstracted property has an identified alternative assurance layer (Lean, runtime oracle, or type system) documented in this file and tracked in the verification matrix.

4. **Exhaustive exploration**: Within bounds, TLC explores *every* possible interleaving, providing stronger guarantees than testing for the properties it checks.

### 9.2 Limitations

1. **Population bounds**: Safety guarantees only hold for populations up to the configured constants. Runtime behavior with larger populations relies on structural induction (Lean) or testing.

2. **Liveness not default**: The default `Asupersync_MC.cfg` checks safety only. Liveness (`CancelTerminates`) requires explicit `LiveSpec` configuration.

3. **No composition**: TLA+ checks individual state machines but not their composition with external systems (network, filesystem, user code).

---

## 10. Reviewer Checklist

When reviewing changes to the TLA+ model:

- [ ] Every new action has a corresponding Lean Step constructor documented
- [ ] Every new invariant maps to a canonical rule ID or SINV
- [ ] Abstraction decisions reference the relevant ADR
- [ ] State correspondence table is updated if variables change
- [ ] `AssumptionEnvelopeInvariant` is updated if new bounds are introduced
- [ ] Scenario configurations in `docs/semantic_tla_scenario_config.md` cover the new invariant
- [ ] `formal/tla/Asupersync_MC.cfg` includes new invariants in the INVARIANT block
