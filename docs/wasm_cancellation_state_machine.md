# WASM Cancellation State Machine Contract

Contract ID: `wasm-cancel-state-machine-v1`  
Bead: `asupersync-umelq.6.1`

## Purpose

Define the browser/wasm execution contract for Asupersync cancellation so that native and wasm backends preserve the same protocol and invariants:

- task protocol: `Running -> CancelRequested -> Cancelling -> Finalizing -> Completed(Cancelled)`,
- region protocol: close/drain/finalize/close-complete quiescence path,
- no obligation leaks,
- idempotent and severity-monotone cancellation strengthening,
- deterministic replay-compatible evidence.

This document is normative for downstream beads `6.2`, `6.3`, `8.1`, `8.3`, and `12.1`.

## Scope and Ground Truth

This contract is derived from current runtime behavior in:

- `src/record/task.rs` (`TaskState`, `TaskPhase`, cancel transitions, witness rules),
- `src/runtime/state.rs` (`cancel_request`, region cascade, cause-chain limits, close advancement),
- `src/runtime/scheduler/three_lane.rs` (cancel lane routing, cancel ack consumption, poll-path transitions),
- `src/cx/cx.rs` (`checkpoint` cancellation acknowledgement behavior),
- `src/types/cancel.rs` (severity lattice, cleanup budget policy, `CancelWitness` validation).

## Non-Negotiable Invariants

1. Cancellation phase is monotone (no phase regression).
2. Cancellation severity can only strengthen, never weaken.
3. Cleanup budget can only tighten (meet/combine), never widen.
4. Completed is absorbing.
5. Region close completion requires: no live tasks, no children, no unresolved obligations, no pending finalizers.
6. Browser adapter must not introduce ambient authority or implicit fallback paths.

## Task-Level Protocol

## State Set

- `Created`
- `Running`
- `CancelRequested { reason, cleanup_budget }`
- `Cancelling { reason, cleanup_budget }`
- `Finalizing { reason, cleanup_budget }`
- `Completed(outcome)`

## Legal Transitions

- `Created -> Running | CancelRequested | Completed`
- `Running -> CancelRequested | Completed`
- `CancelRequested -> CancelRequested | Cancelling | Completed`
- `Cancelling -> Cancelling | Finalizing | Completed`
- `Finalizing -> Finalizing | Completed`
- `Completed -> (none)`

These match `TaskPhase::is_valid_transition` in `src/record/task.rs`.

## Transition Semantics

### T1 Request

- Trigger: `request_cancel_with_budget(reason, budget)` from runtime cascade or wake path.
- Effect:
- `CancelRequested` entered if task was `Created`/`Running`.
- Existing cancel state is strengthened (`reason.strengthen`, `budget.combine`).
- `CxInner.cancel_requested = true`.
- `cancel_epoch` increments on first/new cancellation epoch.

### T2 Acknowledge

- Trigger: checkpoint observes `cancel_requested && mask_depth == 0`.
- Effect:
- `CancelRequested -> Cancelling` via `acknowledge_cancel()`.
- Cleanup budget applied to `CxInner.budget` and `polls_remaining`.

### T3 Cleanup Complete

- Trigger: runtime observes cleanup path completion.
- Effect:
- `Cancelling -> Finalizing` via `cleanup_done()`.

### T4 Finalization Complete

- Trigger: finalizers done.
- Effect:
- `Finalizing -> Completed(Cancelled(reason))` via `finalize_done_with_witness()`.

### T5 Terminal Absorption

- Trigger: any later cancel signal on `Completed`.
- Effect:
- no state change.

## Region-Level Cancellation Cascade

## Cascade Law

`cancel_request(region, reason, source_task)` must:

1. Collect target region plus descendants.
2. Process parents before children (depth-ascending) to build deterministic cause chains.
3. Mark regions closing and propagate `ParentCancelled` causality to descendants.
4. Request cancellation on tasks in affected regions with proper chained reason.
5. Return cancel-scheduling set for lane injection.

## Cause-Chain Limits

Cause chains are bounded by `CancelAttributionConfig`:

- `max_chain_depth`,
- `max_chain_memory`.

Truncation must be explicit and auditable, never silent.

## Quiescence Completion

Region close completes only when:

- `task_count == 0`,
- `pending_obligations == 0`,
- `child_count == 0`,
- finalizers drained.

`advance_region_state()` drives `Closing/Draining -> Finalizing -> Closed`.

## Browser/JS Execution Mapping

## Host Model

- Single-threaded cooperative execution on main thread for v1.
- Cancellation signals can arrive from host callback turns and microtask pumps.

## Required Adapter Semantics

### B1 Non-Reentrant Pump

- Host callback must enqueue cancel/wake signals only.
- It must not recursively poll runtime while runtime is already polling.
- Reentrancy is deferred to next scheduled pump cycle.

### B2 Cancel Ack Timing

- Ack occurs at cancellation checkpoints (`checkpoint`) when not masked.
- Browser adapter must preserve this rule; it may not auto-ack on signal receipt.

### B3 Mask Respect

- If `mask_depth > 0`, cancellation remains pending but not acknowledged.
- Unmasking must permit checkpoint to observe and acknowledge cancellation.

### B4 Late Wake Handling

- Wakes arriving after terminal completion are stale diagnostics, not panic.
- Generation/wake-dedup rules still apply.

### B5 Lane Routing

- If `cancel_requested == true`, wake scheduling routes task to cancel lane with cleanup-priority.
- Otherwise route to ready lane.

### B6 Deterministic Metadata

Every cancel-protocol event emitted by browser adapter must include:

- `task_id`
- `region_id`
- `cancel_epoch`
- `cancel_phase`
- `cancel_kind`
- `decision_seq`
- `host_turn_id`
- `microtask_batch_id`

## Idempotence and Race Contract

## R1 Multiple Cancel Requests

- Repeated cancel requests are valid and must strengthen severity/budget monotonically.
- No duplicated epoch regression.

## R2 Cancel vs Completion Race

- If task completes before ack, terminal completion remains valid.
- If cancellation protocol is already active, completion must resolve to `Cancelled` path when required by state.

## R3 Cancel During Finalizing

- Additional cancel requests may strengthen reason/budget but cannot leave `Finalizing` for earlier phases.

## R4 Parent/Child Cascade Race

- Parent cancellation propagation order must remain deterministic (depth-sorted traversal).

## Deterministic Unit Fixture Matrix

Required fixture identifiers for wasm port conformance:

- `cancel.task.request_to_ack_when_unmasked`
- `cancel.task.masked_defers_ack`
- `cancel.task.cleanup_to_finalizing_to_completed_cancelled`
- `cancel.task.completed_absorbing`
- `cancel.task.reason_strengthen_monotone`
- `cancel.task.budget_combine_monotone`
- `cancel.task.witness_phase_monotone`
- `cancel.region.cascade_parent_before_child`
- `cancel.region.cause_chain_bounded`
- `cancel.region.no_new_spawn_after_cancel`
- `cancel.region.no_new_obligation_after_cancel`
- `cancel.scheduler.cancel_lane_routing_on_pending_wake`
- `cancel.scheduler.late_wake_nonpanic`

Each fixture must include:

- seed,
- initial snapshot id,
- scripted operations,
- expected phase/event fingerprint,
- deterministic repro command.

## Native vs Browser Parity Scenarios

Run native and browser-adapter backends on identical scripts and compare:

1. single-task cancel checkpoint lifecycle,
2. masked section cancel deferral then unmask ack,
3. nested-region cascade with chained reasons,
4. cancel plus late wake race,
5. cancel with obligation discharge/finalizer progression.

Parity assertions:

- same terminal outcomes,
- same cancellation phase sequence per task,
- same obligation closure set,
- equivalent trace fingerprints (allowing host-only metadata fields).

## CI Gate Expectations

Port is CI-blocking if any of the following fail:

1. any `cancel.*` deterministic fixture mismatch,
2. parity mismatch native vs browser adapter,
3. missing required cancellation trace fields,
4. witness validation detects phase regression or reason weakening.

Required failure artifacts:

- fixture id and seed,
- task/region id set,
- native and browser traces,
- first divergence step,
- repro command.

## Reproduction Commands

Use `rch` for cargo-heavy commands:

```bash
rch exec -- cargo test -p asupersync cancel_request -- --nocapture
rch exec -- cargo test -p asupersync cancel_drain_finalize -- --nocapture
rch exec -- cargo test --all-targets cancel -- --nocapture
rch exec -- cargo run --features cli --bin asupersync -- trace verify --strict artifacts/cancel_wasm.trace
```

## Downstream Contract Surface

This contract is the semantic baseline for:

- `asupersync-umelq.6.2` loser-drain browser correctness,
- `asupersync-umelq.6.3` obligation parity in wasm,
- `asupersync-umelq.8.1` ABI schema for cancel phase/witness fields,
- `asupersync-umelq.8.3` AbortSignal/token interoperability,
- `asupersync-umelq.12.1` browser trace schema.

Any change to cancellation phase meaning, cause-chain semantics, or witness validation rules requires a contract version bump and parity fixture updates.
