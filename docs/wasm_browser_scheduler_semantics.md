# Browser Scheduler Semantics Contract

Contract ID: `wasm-browser-scheduler-semantics-v1`  
Bead: `asupersync-umelq.5.1`  
Depends on: `asupersync-umelq.4.1`, `asupersync-umelq.18.1`

## Purpose

Define how Asupersync scheduler semantics map to the browser JavaScript event loop without violating core runtime invariants:

1. Structured ownership (task belongs to exactly one region).
2. Region close implies quiescence.
3. Cancellation protocol remains `request -> drain -> finalize`.
4. No obligation leaks.
5. No ambient authority.
6. Deterministic replay remains possible with explicit trace metadata.

This contract is scheduler law for browser backends and adapter code.

## Runtime Model and Host Assumptions

### Browser Host Model

- Single-threaded cooperative execution on the main thread for v1.
- Scheduler pump is driven by JS queue sources:
- `queueMicrotask` (primary low-latency pump trigger).
- `MessageChannel` or `setTimeout(0)` (fairness handoff when microtask burst budget is exhausted).
- Timer readiness is produced by browser timer APIs and fed into runtime wakeup/cancel machinery.

### Event Loop Terminology in This Contract

- Host turn: one JS event-loop task turn.
- Microtask drain: sequence of microtasks run before returning to host task queue.
- Scheduler step: one `next_task()` decision and associated poll path.

## Semantic Mapping: Three-Lane Scheduler -> Browser Queue

Current runtime scheduler semantics are defined by the three-lane scheduler (`cancel > timed > ready`) with bounded fairness (`src/runtime/scheduler/three_lane.rs`). Browser adaptation must preserve the same decision law.

### Rule S1: Lane Priority

Inside each scheduler step:

- Cancel lane has precedence.
- Timed lane is next.
- Ready lane follows.
- Local non-stealable ready queue preserves `!Send` locality semantics (modeled as same-thread affinity in browser v1).

### Rule S2: Fairness Bound Preservation

If ready or timed work is pending, lower-priority work must be dispatched within bounded cancel preemption:

- Base bound: at most `cancel_streak_limit` consecutive cancel dispatches before a non-cancel opportunity.
- Drain modes (`DrainObligations` / `DrainRegions`) allow up to `2 * cancel_streak_limit`.
- If only cancel work exists, fallback cancel dispatch is allowed and streak resets.

Browser adapter must not create an unbounded cancel monopoly by repeatedly scheduling only cancel microtasks.

### Rule S3: Wake Dedup and Enqueue Idempotence

Wakeup dedup semantics from runtime `wake_state.notify()` must hold:

- Multiple wake requests for the same runnable task in one epoch cannot produce duplicate runnable entries.
- A wake on a terminal task is treated as stale wake diagnostic, not panic.
- Dedup must be stable across host-turn boundaries.

### Rule S4: Non-Reentrant Scheduler Pump

Host callbacks must never re-enter scheduler polling recursively.

Required pump state machine:

- `Idle`: no pending pump.
- `Scheduled`: one pump is queued in host loop.
- `Running`: scheduler currently executing.

If a wake arrives during `Running`, adapter sets a pending flag and exits current loop normally; it must schedule another pump turn instead of recursive poll.

### Rule S5: Yield Semantics

`yield_now()` must preserve "cooperative relinquish" semantics:

- First poll returns `Pending` and issues wake request.
- Task is eligible again under normal lane rules.
- Browser adapter must ensure this cannot starve unrelated tasks by unlimited same-turn refiring.

### Rule S6: Deterministic Ordering Metadata

Every scheduler decision emitted by browser adapter must carry stable ordering metadata compatible with replay:

- `decision_seq` (monotonic u64 in adapter scope).
- `decision_hash` (same schema family as seam contract events).
- `host_turn_id` and `microtask_batch_id`.

These fields are mandatory for native/browser parity diffing.

## Browser Pump Policy

### P1: Microtask First, Bounded Burst

- Default pump trigger uses `queueMicrotask`.
- Adapter executes scheduler steps up to `microtask_burst_limit` per drain cycle.
- On limit hit with remaining runnable work, adapter hands off via task queue (`MessageChannel` preferred, `setTimeout(0)` fallback).

Purpose: preserve runtime progress while preventing UI starvation and perpetual microtask monopolization.

### P2: Timer Injection Ordering

- Timer expirations observed in same host turn are normalized into deterministic order key `(deadline, timer_id, generation)`.
- Late timer events after cancellation become typed stale-timer diagnostics.
- Timer callback must enqueue wake signals, not inline task polling.

### P3: Authority Boundary

- Scheduler adapter only receives explicit capabilities from `Cx`/authority seam.
- Browser APIs (`setTimeout`, channel post, entropy/time reads) must route through capability-scoped handles.
- No direct global API usage in semantic core.

## Failure Semantics

### F1 Reentrancy Attempt

- Condition: pump invoked while state is `Running`.
- Behavior: set pending flag, emit `scheduler_reentrancy_deferred`, return.
- Invariant impact: no ownership or obligation mutation in deferred path.

### F2 Late Wake / Stale Token

- Condition: wake references terminal or generation-mismatched task.
- Behavior: emit typed stale event; no panic; no enqueue.

### F3 Host Throttle / Suspend Gap

- Condition: tab suspension or long host delay causes large timer catch-up.
- Behavior: process catch-up in bounded batches, yielding between batches; do not violate fairness bound.

### F4 Capability Denial

- Condition: missing/invalid authority for host callback path.
- Behavior: fail closed with explicit authorization error and provenance; no ambient fallback.

## Deterministic Test Matrix

The following fixtures are required for this bead's semantic contract:

- `sched.browser.lane_precedence.cancel_timed_ready`
- `sched.browser.fairness.cancel_streak_bound`
- `sched.browser.fairness.drain_mode_double_bound`
- `sched.browser.wake.dedup_cross_turn`
- `sched.browser.reentrancy.defer_not_reenter`
- `sched.browser.yield.single_wake_pending_then_ready`
- `sched.browser.timer.late_wakeup_after_cancel`
- `sched.browser.timer.catchup_bounded_batches`
- `sched.browser.authority.fail_closed_no_fallback`

Each fixture must publish:

- seed,
- initial runtime snapshot id,
- operation script,
- expected decision/event fingerprint,
- deterministic repro command.

## Native vs Browser Parity Scenarios

Run native backend and browser-adapter backend on identical scenario definitions:

1. Sustained cancel pressure with concurrent ready work.
2. Timer cancellation race with late wake.
3. Mixed wake storms with duplicate wake requests.
4. Yield-heavy cooperative workload.
5. Capability-denied callback path.

Parity assertions:

- terminal `Outcome` equivalence,
- cancellation phase transitions equivalent,
- obligation closure set equivalent,
- scheduler event fingerprint equivalent modulo allowed host metadata fields.

## Trace and Observability Contract

Scheduler adapter must emit structured events sufficient for replay forensics:

- `scheduler_step_begin`
- `scheduler_step_decision`
- `scheduler_step_end`
- `scheduler_reentrancy_deferred`
- `scheduler_burst_limit_reached`
- `scheduler_host_handoff`

Mandatory fields per event:

- `task_id`
- `region_id`
- `lane`
- `decision_seq`
- `decision_hash`
- `host_turn_id`
- `microtask_batch_id`
- `cancel_streak`
- `cancel_streak_limit`
- `error_class` (on failures)

## CI Gate Expectations

Conformance is CI-blocking when any condition fails:

1. Deterministic fixture mismatch for any `sched.browser.*` case.
2. Native/browser parity scenario mismatch.
3. Missing required scheduler event fields.
4. Repro command does not regenerate failure artifact.

Required artifacts:

- failing fixture id,
- seed and scenario id,
- native/browser event logs,
- parity diff summary,
- deterministic repro command block.

## Reproduction Commands

Use remote offload for cargo-heavy commands:

```bash
rch exec -- cargo test --all-targets sched_browser -- --nocapture
rch exec -- cargo test -p asupersync --features test-internals parity_browser_scheduler -- --nocapture
rch exec -- cargo run --features cli --bin asupersync -- trace verify --strict artifacts/browser_scheduler.trace
```

## Downstream Dependency Contract

This document is normative input for:

- `asupersync-umelq.5.2` (timer backend adaptation),
- `asupersync-umelq.5.3` (fairness and starvation controls),
- `asupersync-umelq.6.1` (wasm cancellation state machine port).

Any semantic change requires:

- contract version bump,
- explicit compatibility note in dependent beads,
- updated deterministic fixtures and parity artifacts.
