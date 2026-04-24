# Asupersync v4 Formal Semantics ↔ Implementation Refinement Map

**Source spec:** `asupersync_v4_formal_semantics.md` (root, dated 2026-03-02; supersedes the older `docs/` copy).
**Last cross-checked:** 2026-04-24 (commit `4982c3c93`).
**Methodology:** for each small-step rule and invariant in the spec, locate the canonical Rust implementation, the lab oracle that witnesses it (when one exists), and any divergence or gap. Gaps are filed as new beads.

The "Status" column uses:

- **Implemented** — code exists and matches the rule's structure.
- **Implemented (variant)** — code exists but uses a different shape (often more conservative); see notes.
- **Partial** — only some pre/post-conditions are enforced in code; the remainder is convention.
- **Missing** — no implementation found; bead filed.

Every cited file path is a real file at HEAD. Line numbers were verified at commit `4982c3c93` and may drift; treat as anchors for grep.

---

## 1. Domains

| Spec § | Concept | Rust mirror | Status |
|---|---|---|---|
| 1.1 | `RegionId`, `TaskId`, `ObligationId`, `Time` | `src/types/{region,task,obligation,time}.rs`; concretely `RegionId(u64)`, `TaskId(u64)`, `ObligationId(u64)`, `Time` (saturating-add nanos) | Implemented |
| 1.2 | `Outcome` (4-valued, `Ok < Err < Cancelled < Panicked`) | `src/types/outcome.rs:214` `pub enum Outcome<T,E>` + severity ordering | Implemented |
| 1.3 | `CancelReason { kind, message }` and `CancelKind` tier | `src/types/cancel.rs:194` `pub enum CancelKind`; severity tiers and `strengthen()` live alongside | Implemented |
| 1.4 | `Budget { deadline, poll_quota, cost_quota, priority }` with componentwise meet | `src/types/budget.rs` (1.8K LOC) — combine = min on deadline/quota, max on priority | Implemented |
| 1.5 | `TaskState` (Created/Running/CancelRequested/Cancelling/Finalizing/Completed) | `src/record/task.rs:24` `pub enum TaskState` | Implemented |
| 1.6 | `RegionState` (Open/Closing/Draining/Finalizing/Closed) | `src/record/region.rs:72` `pub enum RegionState` | Implemented |
| 1.7 | `ObligationState` (Reserved/Committed/Aborted/Leaked) and `ObligationKind` | `src/record/obligation.rs:134` | Implemented |
| 1.8 | Mazurkiewicz traces / independence | `src/trace/{independence,canonicalize,dpor}.rs`; Foata normalization in `src/trace/canonicalize.rs` | Implemented |
| 1.9 | `Held(t)` linearity discipline | `src/obligation/leak_check.rs` + `src/lab/oracle/obligation_leak.rs` | Implemented |
| 1.10 | Distributed time / vector clocks | `src/trace/distributed/vclock.rs`, `src/trace/distributed/lattice.rs` | Implemented |
| 1.11 | `Lane ::= Cancel \| Timed \| Ready` + EDF | `src/runtime/scheduler/three_lane.rs` (worker dispatch); EDF queue in `src/runtime/scheduler/intrusive.rs` | Implemented |
| 1.12 | `Resolved`, `Quiescent`, `LoserDrained` predicates | `src/runtime/state.rs:2069 is_quiescent`; loser-drain witness in `src/lab/oracle/loser_drain.rs`; obligation-resolved check in `src/obligation/ledger.rs` | Implemented |

## 2. Global state Σ

| Spec § | Concept | Rust mirror | Status |
|---|---|---|---|
| 2.1 | `RegionRecord` (parent/children/subregions/state/budget/cancel/finalizers/policy) | `src/record/region.rs` | Implemented |
| 2.2 | `TaskRecord` (region/state/cont/mask/waiters) | `src/record/task.rs` (state at line 24, mask + waiters in same struct, `cont` represented by `StoredTask` in `src/runtime/stored_task.rs`) | Implemented |
| 2.3 | `ObligationRecord` (kind/holder/region/state) | `src/record/obligation.rs` | Implemented |
| 2.4 | `SchedulerState { cancel_lane, timed_lane, ready_lane }` | `src/runtime/scheduler/three_lane.rs` `WorkerState`; per-worker cancel+ready queues plus shared timed wheel | Implemented |
| 2 (top) | Σ aggregate | `src/runtime/state.rs` `RuntimeState` (sharded per `src/runtime/sharded_state.rs`); region/task/obligation tables in `src/runtime/{region_table,task_table,obligation_table}.rs` | Implemented |

## 3. Transition rules

### 3.0 Scheduling

| Spec rule | Rust implementation | Lab oracle | Status |
|---|---|---|---|
| `ENQUEUE` | `ThreeLaneScheduler::enqueue` family in `src/runtime/scheduler/three_lane.rs`; lane chosen by current `TaskState` | `src/lab/oracle/priority_inversion.rs` | Implemented |
| `SCHEDULE-STEP` / `pick_next` | `ThreeLaneScheduler::next_task` in `src/runtime/scheduler/three_lane.rs` (modes `MeetDeadlines` / `DrainObligations` / `DrainRegions` / `NoPreference`); cancel-streak guard at `cancel_streak < cancel_streak_limit` | `tests/scheduler_lane_fairness.rs`, `tests/cancel_lane_fairness_bounds.rs` | Implemented |
| Bounded fairness lemma | `cancel_streak_limit` field (line ~1503) + fairness-yield counters; `effective_limit` doubles under Drain* | same as above | Implemented |

### 3.1 Task lifecycle

| Spec rule | Rust implementation | Status | Notes |
|---|---|---|---|
| `SPAWN` | `Scope::spawn` (`src/cx/scope.rs:348`), `Scope::spawn_task` (line 493), `RuntimeState::create_task` (`src/runtime/state.rs:1338`) | Implemented | Closing-region rejection covered: `tests::spawn_into_closing_region_should_fail` (`scope.rs:1933`). |
| `SCHEDULE` (Created → Running) | `RuntimeState::create_task` enqueues; first `poll` flips state inside `runtime/state.rs` (`mark_task_running` family) | Implemented | |
| `COMPLETE-OK` | `complete_task_ok` (`src/runtime/state.rs:7976`); waiter wake via `task_completed` (`src/runtime/state.rs:2446`) | Implemented | Apply-policy hook flows through `apply_policy_on_child_outcome` (line 2085). |
| `COMPLETE-ERR` | Same `task_completed` path, error outcome routed through policy aggregation | Implemented | |

### 3.2 Cancellation protocol

| Spec rule | Rust implementation | Status | Notes |
|---|---|---|---|
| `CANCEL-REQUEST` (with descendant propagation) | `RuntimeState::cancel_request` (`src/runtime/state.rs:2168`); descendant traversal via `RegionRecord::subregions` | Implemented | Strengthen-over-existing handled by `CancelReason::strengthen` (`src/types/cancel.rs`). |
| `strengthen` | `CancelReason::strengthen` + `CancelKind` ordering in `src/types/cancel.rs` | Implemented | |
| `CANCEL-ACKNOWLEDGE` | `Cx::checkpoint` (`src/cx/cx.rs:1301`) when `mask = 0`; transitions `CancelRequested → Cancelling` | Implemented | |
| `CHECKPOINT-MASKED` | Same `Cx::checkpoint` when mask > 0; mask decremented monotonically | Implemented | `INV-MASK-BOUNDED` enforced — see `tests/mask_bounded.rs` and oracle `src/lab/oracle/cancellation_protocol.rs`. |
| `CANCEL-DRAIN` (Cancelling → Finalizing) | `RuntimeState::can_region_finalize` (`src/runtime/state.rs:2421`) gate; per-task transition inside `task_completed` for Cancelling tasks | Implemented | |
| `CANCEL-FINALIZE` | `task_completed` (`src/runtime/state.rs:2446`) records `Completed(Cancelled(_))`; `MaskedFinalizer` (`src/runtime/state.rs:176`) runs locally | Implemented | |
| Idempotence (3.2.2) | `strengthen` is associative/commutative/idempotent in `src/types/cancel.rs`; replayed `cancel_request` only tightens | Implemented | Tested in `tests/cancel_idempotence.rs` and `lab/oracle/cancellation_protocol.rs`. |
| Bounded cleanup (3.2.3) | `cleanup_budget` propagation in `RuntimeState::cancel_request`; finalizer time bound via `FINALIZER_TIME_BUDGET_NANOS` (`src/record/finalizer.rs:23`) | Implemented | |
| Canonical automaton (3.2.5) | Codified by `TaskState` discriminants + transitions in `state.rs`; `state_verifier.rs` validates legal transitions | Implemented | `src/runtime/state_verifier.rs:StateTransitionVerifier`. |

### 3.3 Region lifecycle

| Spec rule | Rust implementation | Status | Notes |
|---|---|---|---|
| `CLOSE-BEGIN` | `RuntimeState` transitions inside `task_completed` when last child of root-of-scope completes; explicit close via `Scope::close` (drop path in `src/cx/scope.rs`) | Implemented | |
| `CLOSE-CANCEL-CHILDREN` (Closing → Draining) | Triggered by the same `cancel_request` flow with reason `implicit_close` (`CancelKind::ParentCancelled`) | Implemented | |
| `CLOSE-CHILDREN-DONE` (Draining → Finalizing) | `can_region_finalize` (`src/runtime/state.rs:2421`) checks all children completed and sub-regions closed | Implemented | |
| `CLOSE-RUN-FINALIZER` (LIFO) | `FinalizerStack` (`src/record/finalizer.rs:90`); LIFO drain via `drain_ready_async_finalizers` (`src/runtime/state.rs:2567`); per-task masked execution via `MaskedFinalizer` (`src/runtime/state.rs:176`) | Implemented | LIFO covered by `finalizer_stack_lifo_order` test (line 204 of finalizer.rs). |
| `CLOSE-COMPLETE` | Transition to `RegionState::Closed(_)` once `can_region_finalize` && `ledger(r) = ∅` (region's `pending_obligation_count_for_kind` zero across kinds — `src/runtime/state.rs:2049`) | Implemented | |

### 3.4 Obligations (two-phase)

| Spec rule | Rust implementation | Status | Notes |
|---|---|---|---|
| `RESERVE` | `RuntimeState::create_obligation` (`src/runtime/state.rs:1635`); checked against region capacity at line 1659 | Implemented | |
| `COMMIT` | `RuntimeState::commit_obligation` (`src/runtime/state.rs:1749`); `ObligationLedger::commit` (`src/obligation/ledger.rs:274`) | Implemented | Token-bound holder check enforced. |
| `ABORT` | `RuntimeState::abort_obligation` (`src/runtime/state.rs:1822`); `ObligationLedger::abort` / `abort_by_id` (`src/obligation/ledger.rs:290,312`) | Implemented | Cancel-drain path uses `abort_by_id` to release without leak accounting. |
| `LEAK` | `RuntimeState::mark_obligation_leaked` (`src/runtime/state.rs:1916`); detection in `src/obligation/leak_check.rs`; oracle `src/lab/oracle/obligation_leak.rs` | Implemented | `set_obligation_leak_response` (line 864) wires panic vs. log behavior. |
| Marking / VASS view (3.4.0 box) | `marking(r,k)` mirrored by `pending_obligation_count_for_kind` (line 2049); region close gate uses sum across kinds | Implemented | |
| Linear logic embedding (3.4.1–3.4.2) | `ObligationToken` (one-shot, holder-bound) in `src/obligation/ledger.rs`; only `commit/abort` consume it | Implemented (variant) | The token is a runtime witness rather than a typed linear handle; lint coverage via `src/obligation/no_aliasing_proof.rs`. |
| Lab oracle (3.4.3) | `Held(t) ≠ ∅ ⇒ leak` enforced in `src/lab/oracle/obligation_leak.rs` | Implemented | |
| Ledger-empty-on-close (3.4.5) | Precondition checked by `can_region_finalize` and again by `pending_obligation_count` zero check before `Closed` | Implemented | |
| No-silent-drop (3.4.6) | Combination of `mark_obligation_leaked` always firing on completion-with-Held (state.rs `task_completed` path) and `LeakDetector` in `src/obligation/leak_check.rs` | Implemented | |
| Cancel-drain interaction (3.4.7) | Documented in `src/cx/scope.rs` Drop path and exercised by `src/lab/oracle/cancel_correctness.rs` | Implemented | |

### 3.5 Joining

| Spec rule | Rust implementation | Status |
|---|---|---|
| `JOIN-BLOCK` | `JoinHandle::join` / `join_with_drop_reason` (`src/runtime/task_handle.rs:139,160`); waiter recorded via `TaskRecord.waiters` | Implemented |
| `JOIN-READY` | `JoinFuture::poll` (`src/runtime/task_handle.rs:299`) returns immediately when child already completed | Implemented |
| `JoinFuture::drop` aborts | `JoinFuture::Drop` (line 337) — preserves race-loser drain even on early drop | Implemented |

### 3.6 Time

| Spec rule | Rust implementation | Status | Notes |
|---|---|---|---|
| `TICK` (virtual time) | `LabRuntime::advance_time` / `advance_time_to` (`src/lab/runtime.rs:888,909`); deadline cancel via `DeadlineMonitor` (`src/runtime/deadline_monitor.rs`) | Implemented | Production wall clock via `time::wall_now` (`src/time/sleep.rs:98`). |
| Sleep wakeup on tick | Hierarchical wheel in `src/time/wheel.rs` (`tick_level0` line 747) collects expired timers | Implemented | |

### 3.7 Distributed extensions

| Spec rule | Rust implementation | Status | Notes |
|---|---|---|---|
| `DEDUP-NEW / DEDUP-DUPLICATE / DEDUP-CONFLICT` | `IdempotencyStore::check` (`src/remote.rs:1444`) returns `DedupDecision::{New, Duplicate, Conflict}` | Implemented | Spec models computation match by `cn` (computation name); impl uses `IdempotencyRequestFingerprint` — equivalent. |
| `RECORD-NEW` | `IdempotencyStore::record` (`src/remote.rs:1471`); inserts only on vacant entry | Implemented | |
| `RECORD-COMPLETE` | `IdempotencyStore::record_completion` (search nearby) | Implemented (variant) | Outcome cached on existing record; evicted records correctly rejected. |
| `EVICT` | `check()` evicts on read when `now >= expires_at`; periodic sweep via `IdempotencyStore::evict_expired` | Implemented | "Read-side eviction" is stricter than spec's periodic-only model; safer. |
| `SAGA-STEP-OK` / `SAGA-STEP-FAIL` / `SAGA-ABORT` / `SAGA-COMPLETE` | `Saga` state machine in `src/remote.rs:1676..1830`; `SagaState` enum at line 1577 | Implemented | LIFO compensation in `Saga::run_compensations` (line 1813). |
| Compensation reverse-order invariant | `run_compensations` iterates `compensations` in reverse (verified by `tests::saga_*` in `src/obligation/saga.rs`) | Implemented | |

## 4. Derived combinators

| Spec § | Rust mirror | Status | Notes |
|---|---|---|---|
| 4.1 `join` | `Scope::join`, `Scope::join_all` (`src/cx/scope.rs`); raw `combinator/join.rs` | Implemented | Policy `FailFast` aggregates via `apply_policy_on_child_outcome` (state.rs:2085). |
| 4.2 `race` (with loser drain) | `Scope::race`, `Scope::race_all` (`src/cx/scope.rs:1314..1356`) — abort losers with `CancelReason::race_loser()`, then `join` to drain | Implemented | Spec lemma L-LOSER-DRAINED witnessed by `src/lab/oracle/loser_drain.rs`. |
| 4.3 `timeout` | `combinator/timeout.rs` defined as `race(f, sleep(d).then(Err))` | Implemented | LAW-TIMEOUT-MIN test in `combinator/timeout_metamorphic.rs`. |

## 5. Invariants

| Invariant | Enforcement site | Lab oracle / property test | Status |
|---|---|---|---|
| `INV-TREE` | `RegionTable` parent/child links (`src/runtime/region_table.rs`) | `src/lab/oracle/region_tree.rs` | Implemented |
| `INV-TASK-OWNED` | `TaskTable::insert` requires region; orphan removal on completion (`src/runtime/task_table.rs`) | `src/lab/oracle/task_leak.rs`, `src/lab/oracle/region_leak.rs` | Implemented |
| `INV-QUIESCENCE` | `can_region_finalize` precondition (`state.rs:2421`); `is_quiescent` predicate (`state.rs:2069`) | `src/lab/oracle/quiescence.rs` | Implemented |
| `INV-CANCEL-PROPAGATES` | `cancel_request` recurses descendants (`state.rs:2168..`) | `src/lab/oracle/cancel_correctness.rs`, `src/lab/oracle/cancel_signal_ordering.rs` | Implemented |
| `INV-OBLIGATION-BOUNDED` | `mark_obligation_leaked` fires whenever holder completes with Reserved → state machine prevents Reserved + Completed coexistence | `src/lab/oracle/obligation_leak.rs` | Implemented |
| `INV-OBLIGATION-LINEAR` | Absorbing terminal states enforced by `ObligationLedger` (commit/abort/leak set state once; double-resolve panics — `tests::abort_by_id_double_resolve_panics_without_pending_underflow`, ledger.rs:1580) | `src/obligation/leak_check.rs` | Implemented |
| `INV-LEDGER-EMPTY-ON-CLOSE` | `pending_obligation_count` check before `Closed` | `src/lab/oracle/quiescence.rs` | Implemented |
| `INV-MASK-BOUNDED` | `Cx::checkpoint` decrements monotonically; mask is `u8`/`u32` so finite | `src/lab/oracle/cancellation_protocol.rs` | Implemented |
| `INV-DEADLINE-MONOTONE` | `Budget::combine` componentwise meet (`src/types/budget.rs`); child region inherits via `create_child_region` (`state.rs:1147`) | `src/lab/oracle/deadline_monotone.rs` | Implemented |
| `INV-LOSER-DRAINED` | `Scope::race` always `join`s losers post-abort (`scope.rs:1314..1356`) | `src/lab/oracle/loser_drain.rs` | Implemented |
| `INV-SCHED-LANES` | `enqueue` selects lane from `TaskState`; lane invariants validated in `src/runtime/scheduler/three_lane.rs` worker dispatch | `src/lab/oracle/priority_inversion.rs` | Implemented |

## 6. Progress properties

| Property | Witness | Status |
|---|---|---|
| `PROG-TASK` | Bounded-fairness lemma + `tests/scheduler_lane_fairness.rs` | Implemented |
| `PROG-CANCEL` | `cancel_streak_limit` guard ensures cancel lane drains (`tests/cancel_lane_fairness_bounds.rs`) | Implemented |
| `PROG-REGION` | `can_region_finalize` becomes true once children quiescent + obligations resolved; `MaskedFinalizer` cannot block forever (budgeted) | Implemented |
| `PROG-OBLIGATION` | Either lab oracle leaks (forcing the LEAK transition) or the `commit/abort` paths in normal scope-close flow | Implemented |

## 7. Algebraic laws

| Law | Witness | Status |
|---|---|---|
| LAW-JOIN-ASSOC | `combinator/laws.rs` (associativity test under deterministic policy) | Implemented |
| LAW-JOIN-COMM | `combinator/laws.rs` | Implemented |
| LAW-RACE-COMM | `combinator/race_metamorphic.rs` | Implemented |
| LAW-TIMEOUT-MIN | `combinator/timeout_metamorphic.rs` | Implemented |
| LAW-RACE-NEVER | `combinator/laws.rs` (`race_with_never_*` tests) | Implemented |
| LAW-RACE-JOIN-DIST | _Not directly tested as a metamorphic equivalence_ | Partial — see new bead below. |
| 7.1 trace equivalence (Mazurkiewicz) | `src/trace/canonicalize.rs` (Foata normal form), `src/trace/dpor.rs` | Implemented |
| 7.2 side-condition schema for rewrites | `src/plan/certificate.rs` | Implemented |

## 8. Test oracle usage

| Spec § | Implementation |
|---|---|
| `no_task_leaks` | `src/lab/oracle/task_leak.rs` |
| `no_obligation_leaks` | `src/lab/oracle/obligation_leak.rs` |
| `all_finalizers_ran` | `src/lab/oracle/finalizer.rs` |
| `quiescence_on_close` | `src/lab/oracle/quiescence.rs` |
| `losers_always_drained` | `src/lab/oracle/loser_drain.rs` |
| 8.1 optimal DPOR | `src/trace/dpor.rs` (source/sleep/wakeup sets) |
| 8.2 static obligation leak analysis | `src/obligation/leak_check.rs` (sound abstract tracker) |
| 8.3 trace certificate | `src/plan/certificate.rs`; serialized form in `src/trace/integrity.rs` |

## 9. Mechanization plan (Lean)

`formal/lean/` — milestones M1–M4 are tracked in the existing Lean coverage report (`formal/lean/coverage/baseline_report_v1.md`).

Code-alignment cross-references named in §9.3 of the spec (`src/runtime/state.rs`, `src/runtime/scheduler/three_lane.rs`, `tests/scheduler_lane_fairness.rs`, `tests/cancel_lane_fairness_bounds.rs`, `tests/lab_execution.rs`, `src/trace/*`) are all present.

## 10. TLA+ sketch

`formal/tla/` exists; the modules cover spawn / complete / cancel-request actions. Out of scope for this map — depth tracked separately.

---

## Gaps and follow-up beads

The cross-examination found no rule whose runtime implementation is fundamentally divergent from the spec. The gaps are mostly in **test coverage of stated equivalences**, plus a couple of doc-vs-code naming inconsistencies. Filed beads:

1. **`asupersync-lhsgh9`** — LAW-RACE-JOIN-DIST has no metamorphic test. Spec §7 calls it out as a speculative-execution rewrite; without a test we cannot certify rewrite-engine correctness for it. Add `combinator/race_join_dist_metamorphic.rs`.

2. **`asupersync-4nw2lb`** — Two copies of the formal-semantics doc, `asupersync_v4_formal_semantics.md` (root, newer, 1773 LOC) and `docs/asupersync_v4_formal_semantics.md` (older, 1577 LOC). Future readers may pin to the stale copy. Owner decision required (RULE 1).

3. **`asupersync-fy12my`** — `RECORD-COMPLETE` semantics drift (minor): spec writes `D'[k].outcome = Some(outcome)` unconditionally; impl accepts it only on records that have not expired. The impl is the safer ("fail-closed") variant. Tighten spec wording rather than loosen impl.

4. **`asupersync-7ntvjs`** — `§3.2.5` canonical cancellation automaton has 12 transition cells; ~8 have direct property-test coverage. Fill in the four missing cells.

These have been filed via `br create` (see `.beads/issues.jsonl` in this commit).
