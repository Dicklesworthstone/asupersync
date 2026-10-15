# Canonical Glossary and Semantic Term Definitions (SEM-04.2)

**Bead**: `asupersync-3cddg.4.2`
**Parent**: SEM-04 Canonical Semantic Contract (Normative Source)
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_contract_schema.md` (SEM-04.1, rule-ID namespace)
- `docs/semantic_ratification.md` (SEM-03.5, ADR decisions)
- `docs/semantic_inventory_runtime.md` (SEM-02.2, RT layer terms)

---

## 1. Purpose

This glossary defines every term used in the semantic contract. Terms are
canonical — no synonyms, no ambiguity, no conflicting definitions across layers.
Where RT, DOC, LEAN, and TLA+ use different terminology for the same concept,
this glossary establishes the normative name and documents the mapping.

---

## 2. Core Types

### 2.1 Task

A unit of concurrent work owned by exactly one Region. A task has a lifecycle
(Spawned → Running → CancelRequested → Finalizing → Completed) and produces
exactly one Outcome.

**Rule IDs**: #33 (`inv.ownership.task_owned`), #36 (`rule.ownership.spawn`)
**RT term**: `TaskEntry` (`src/record/region.rs`)
**LEAN term**: `Task` (Step.lean)
**TLA+ term**: `task ∈ Tasks` (Spec.tla)

### 2.2 Region

A scope-bounded container for tasks. Regions form a tree (no cycles). Closing
a region cancels all children and waits for quiescence before completing.

**Rule IDs**: #22-28, #35 (`def.ownership.region_tree`)
**RT term**: `RegionHandle` (`src/record/region.rs`)
**LEAN term**: `Region` (Step.lean)
**TLA+ term**: `region ∈ Regions` (Spec.tla)

### 2.3 Outcome

The terminal result of a task. Four-valued: Ok, Cancelled, Err, Panicked.
Ordered by severity (Ok < Cancelled < Err < Panicked).

**Rule IDs**: #29 (`def.outcome.four_valued`), #30 (`def.outcome.severity_lattice`)
**RT term**: `Outcome<T>` (`src/types/outcome.rs`)
**LEAN term**: `Outcome` with `severity : Nat` (Outcome.lean)
**TLA+ term**: `"Completed"` (single terminal state, ADR-008 abstraction)

### 2.4 Obligation

A tracked resource commitment that must be resolved (committed or aborted)
before the owning region can close. Linear: each obligation is created exactly
once and resolved exactly once.

**Rule IDs**: #13-21
**RT term**: `ObligationId` + `ObligationEntry` (`src/record/obligation.rs`)
**LEAN term**: `Obligation` (Obligation.lean)
**TLA+ term**: `obligation ∈ Obligations` (Spec.tla)

### 2.5 Cx (Context Token)

A capability-scoped context handle that gates access to runtime effects.
Cannot be forged, only restricted (SubsetOf). The Rust type system enforces
capability isolation at compile time.

**Rule IDs**: #44 (`inv.capability.no_ambient`), #45 (`def.capability.cx_scope`)
**RT term**: `Cx<C>` where `C: CapSet` (`src/cx/cx.rs`)
**Enforcement**: Rust type system (ADR-006)

---

## 3. Task Lifecycle States

### 3.1 State Definitions

| State | Definition | Absorbing? |
|-------|-----------|:----------:|
| **Spawned** | Task created, not yet polled. Owned by parent region. | No |
| **Running** | Task is executing (being polled by scheduler). | No |
| **CancelRequested** | Cancel signal received. Task has not yet acknowledged. | No |
| **CancelMasked** | Cancel signal received but masked (mask_depth > 0). Task continues executing until mask decrements to 0. | No |
| **CancelAcknowledged** | Task has acknowledged cancellation. Cleanup begins. | No |
| **Finalizing** | Task is running its finalizer (cleanup, resource release). | No |
| **Completed** | Task has produced an Outcome and exited. Terminal state. | Yes |

### 3.2 Disambiguation

| Ambiguous Term | Canonical Term | Meaning |
|---------------|---------------|---------|
| "resolved" | **Completed** | Task has produced an Outcome. Use "Completed" for task lifecycle. |
| "terminal" | **Completed** | Same. The only absorbing state for tasks. |
| "done" | **Completed** | Informal equivalent. Avoid in contract text. |
| "cancelled" | **CancelRequested** or **Completed(Cancelled)** | Distinguish between the request and the outcome. |
| "drained" | **Completed** (after cancel) | A loser is "drained" when it reaches Completed state via the cancel protocol. |

---

## 4. Region Lifecycle States

### 4.1 State Definitions

| State | Definition | Absorbing? |
|-------|-----------|:----------:|
| **Open** | Region is active. Tasks can be spawned into it. | No |
| **Closing** | Region close initiated. No new spawns. Children being cancelled. | No |
| **ChildrenDone** | All child tasks have reached Completed. | No |
| **Finalizing** | Region finalizer is running (ADR-004: LEAN only, TLA+ omits). | No |
| **Quiescent** | Region has no active tasks, no pending obligations, finalizer done. | No |
| **Closed** | Region is fully closed. Terminal state. | Yes |

### 4.2 Quiescence Definition

A region is **quiescent** iff:
1. All spawned tasks are in Completed state.
2. All obligations are resolved (committed or aborted).
3. The region finalizer has completed (if applicable).

**Rule ID**: #27 (`inv.region.quiescence`)

**Disambiguation**: "quiescent" and "closeable" are NOT synonyms. A region
is closeable when close is initiated (state = Closing). A region is quiescent
when all children and obligations are resolved.

---

## 5. Cancellation Protocol Terms

### 5.1 Cancel Kinds (Canonical 5 + Extension Policy)

Per ADR-002, the contract defines 5 canonical cancel kinds:

| Kind | Severity | Definition |
|------|:--------:|-----------|
| **Explicit** | 0 | Programmatic cancel via `cancel()` call |
| **ParentCancelled** | 1 | Inherited from parent region's cancellation |
| **Timeout** | 2 | Deadline expired |
| **Panicked** | 4 | Task panicked during execution |
| **Shutdown** | 5 | Runtime shutdown signal |

### 5.2 Extension Policy

RT may define additional cancel kinds (e.g., Deadline, PollQuota, CostBudget,
RaceLost, ResourceUnavailable, LinkedExit) provided:

1. Each extension kind maps to an integer severity level from {0, 1, 2, 3, 4, 5}.
2. No intermediate levels (no 1.5, no fractional).
3. The `strengthen` operation (cancel strengthening) selects the higher severity.
4. Extension kinds participate in the same monotonic lattice as canonical kinds.

**Rule IDs**: #7 (`def.cancel.reason_kinds`), #8 (`def.cancel.severity_ordering`),
#32 (`def.cancel.reason_ordering`)
**RT source**: `src/types/cancel.rs:340-380`

### 5.3 Masking

Cancel masking allows a task to defer acknowledgment of a cancel signal.
The mask has a bounded depth (integer >= 0). Each checkpoint decrements
the mask. When mask reaches 0, the cancel is acknowledged.

| Term | Definition |
|------|-----------|
| **mask_depth** | Integer >= 0. Number of checkpoints before cancel is acknowledged. |
| **checkpoint** | A yield point where the task checks for pending cancellation. |
| **masked cancel** | Cancel signal received while mask_depth > 0. |

**Rule IDs**: #10 (`rule.cancel.checkpoint_masked`), #11 (`inv.cancel.mask_bounded`),
#12 (`inv.cancel.mask_monotone`)
**Invariant**: mask_depth is monotonically non-increasing during cancel processing.

---

## 6. Severity Lattice

### 6.1 Outcome Severity

```
Ok(0) < Cancelled(1) < Err(2) < Panicked(3)
```

Total order. The `join` operation on Outcomes selects the higher severity:
`join(a, b) = max_severity(a, b)`. On equal severity, left argument wins
(documented left-bias, not commutativity on values).

**Rule IDs**: #30 (`def.outcome.severity_lattice`), #31 (`def.outcome.join_semantics`)

### 6.2 Cancel Severity

```
Explicit(0) < ParentCancelled(1) < Timeout(2) < (reserved:3) < Panicked(4) < Shutdown(5)
```

Total order over 6 integer levels. The `strengthen` operation selects
the higher severity: `strengthen(a, b) = max_severity(a, b)`.

Severity level 3 is reserved for future use. Extension kinds must map
to an existing level.

**Rule ID**: #8 (`def.cancel.severity_ordering`)

---

## 7. Combinator Terms

### 7.1 Definitions

| Term | Definition | Rule ID |
|------|-----------|---------|
| **Join** | Concurrent execution of N tasks. Completes when all tasks complete. Result severity is the max severity of all children. | #37 (`comb.join`) |
| **Race** | Concurrent execution of N tasks. Completes when the first task completes. All losers are cancelled and drained. | #38 (`comb.race`) |
| **Timeout** | Wraps a task with a deadline. If the task doesn't complete by the deadline, it is cancelled with Timeout reason. | #39 (`comb.timeout`) |
| **Loser** | A task in a Race that did not finish first. Must be cancelled and drained to Completed state. | #40 (`inv.combinator.loser_drained`) |
| **Winner** | The first task in a Race to reach Completed state. | — |

### 7.2 Algebraic Laws

| Law | Statement | Status | Rule ID |
|-----|-----------|--------|---------|
| **LAW-JOIN-ASSOC** | `join(join(a, b), c) ≡ join(a, join(b, c))` on severity | Lean proof pending (ADR-005) | #42 |
| **LAW-RACE-COMM** | `race(a, b) ≡ race(b, a)` for fixed schedule | Lean proof pending (ADR-005) | #43 |
| **LAW-TIMEOUT-MIN** | `timeout(d1, timeout(d2, f)) ≡ timeout(min(d1, d2), f)` | Lean proof pending (ADR-005) | — |
| **LAW-RACE-NEVER-ABANDON** | Race never leaves a loser in non-Completed state | Deferred (property tests only) | #41 |

---

## 8. Disambiguation Table

Terms that have been sources of confusion across layers:

| Ambiguous Usage | Canonical Term | Notes |
|----------------|---------------|-------|
| "resolved" (task) | Completed | Task lifecycle terminal state |
| "resolved" (obligation) | Committed or Aborted | Obligation lifecycle terminal states |
| "terminal" | Completed (task) or Closed (region) | Use the specific term for the entity |
| "quiescent" | Quiescent (region only) | Not applicable to tasks |
| "closeable" | Closing (region state) | Distinct from Quiescent |
| "drained" | Completed via cancel protocol | Loser drain means loser reached Completed |
| "cancelled" | CancelRequested (signal) or Cancelled (outcome) | Distinguish signal from result |
| "strength" / "severity" | Severity (canonical) | Always "severity", never "strength" |
| "reason" / "kind" | CancelKind (canonical) | Always "CancelKind", "reason" is informal |
| "scope" / "region" | Region (canonical) | Always "Region" in contract |
| "handle" / "token" | Cx (for capability), RegionHandle (for region access) | Distinguish by purpose |

---

## 9. Downstream Usage

1. **SEM-04.3**: Transition rules use terms defined here without re-definition.
2. **SEM-04.4**: Invariant clauses reference this glossary for term meaning.
3. **SEM-08**: Runtime alignment uses the disambiguation table to verify
   that RT code comments and error messages use canonical terms.
4. **SEM-10**: CI checker validates that DOC artifacts use canonical terms.
