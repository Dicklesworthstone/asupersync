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

## 3.1 Worker Offload Strategy Contract (`asupersync-umelq.5.4`)

CPU-heavy runtime paths may offload to Web Workers only under explicit policy
control. Canonical policy artifacts:

- `.github/wasm_worker_offload_policy.json`
- `scripts/check_wasm_worker_offload_policy.py`
- `artifacts/wasm_worker_offload_summary.json`

### W0: Browser Execution-Ladder Contract

The worker-offload policy file now also carries the authoritative browser
execution ladder under `execution_ladder`. Scheduler adaptation must stay
consistent with that lane-selection contract:

1. Lane ids are stable and ordered:
   - `lane.browser.main_thread.direct_runtime`
   - `lane.browser.dedicated_worker.direct_runtime`
   - `lane.next.server.bridge`
   - `lane.next.edge.bridge`
   - `lane.unsupported`
2. Host-role classification is explicit:
   - `browser_main_thread` and `dedicated_worker` can resolve to direct-runtime
     lanes
   - `next_server` and `next_edge` resolve to bridge-only lanes
   - `service_worker`, `shared_worker`, and `non_browser_or_unknown` fail
     closed to `lane.unsupported`
3. Lane selection is host-adaptive, not host-transforming:
   - scheduler policy may choose the best lane for the current host role
   - scheduler policy may not silently convert a caller into a different host
     role just to preserve a direct-runtime claim
4. Structured diagnostics emitted by later browser/Next adapters must include:
   - `lane_id`
   - `lane_kind`
   - `lane_rank`
   - `host_role`
   - `support_class`
   - `reason_code`
   - `fallback_lane_id`
   - `lane_health_status`
   - `lane_health_failure_count`
   - `lane_health_retry_budget_remaining`
   - `lane_health_cooldown_until_ms`
   - `lane_health_last_trigger`
   - `demoted_lane_id`
   - `policy_schema_version`
   - `repro_command`
5. Lane health is explicit and bounded:
   - default policy is `max_consecutive_failures=2`, `cooldown_ms=30000`
   - failure triggers include `runtime_init_failure`,
     `worker_bootstrap_timeout`, `worker_crash`,
     `replay_integrity_failure`, `prerequisite_drift`, and
     `overload_instability`
   - after the retry budget is exhausted, the lane demotes fail-closed to
     `lane.unsupported` until either the cooldown elapses or
     `manual_reset` is recorded

### W1: Offload Trigger Law

Offload from main-thread scheduler is permitted only when all of these are
true:

1. Estimated compute cost exceeds `min_estimated_cpu_ns`.
2. Inline execution would exceed `max_main_thread_slice_ns`.
3. Queue pressure exceeds `queue_backpressure_threshold` OR inline retry count
   exceeded `max_inline_retry_count`.

This prevents opportunistic offload that would hide scheduling policy bugs.

### W2: Ownership and Region Affinity

Worker jobs remain owned by the originating region/task tuple:

1. Worker envelopes must carry `region_id`, `task_id`, and `obligation_id`.
2. Cross-region handoff is forbidden.
3. Stale generation messages must fail with typed errors (no panic, no silent
   drop).

### W3: Worker Message Protocol

Worker control uses typed envelopes with deterministic sequencing:

1. Required envelope metadata includes `message_id`, `seq_no`,
   `decision_seq`, `seed`, `issued_at_turn`, and `replay_hash`.
2. Ownership-bearing job messages carry `job_id`, `region_id`, `task_id`,
   `obligation_id`, `op`, and any payload bytes.
3. Request operations are limited to:
   - `spawn_job`
   - `poll_status`
   - `cancel_job`
   - `drain_job`
   - `finalize_job`
   - `shutdown_worker`
4. Event operations are limited to:
   - `bootstrap_ready`
   - `bootstrap_failed`
   - `status_snapshot`
   - `job_completed`
   - `cancel_acknowledged`
   - `drain_completed`
   - `finalize_completed`
   - `shutdown_completed`
   - `diagnostic`
5. The concrete v1 non-SAB lane uses owned byte payloads with
   structured-clone semantics. Shared memory is forbidden; any future
   transferable `ArrayBuffer` widening must preserve the same ownership and
   cancellation law.
6. Terminal states are only `completed` or `failed`.

### W4: Cancellation Across Worker Boundary

Worker lifecycle must preserve runtime cancellation semantics:

1. Cancel request (`cancel_job`) is acknowledged within `request_timeout_ms`.
2. After `cancel_acknowledged`, the coordinator emits explicit `drain_job` and
   `finalize_job` control messages rather than silently collapsing the phases.
3. Worker executes bounded drain (`drain_job`) and bounded finalize
   (`finalize_job`) under those explicit control points.
4. Required trace events:
   - `worker_cancel_requested`
   - `worker_cancel_acknowledged`
   - `worker_drain_started`
   - `worker_drain_completed`
   - `worker_finalize_completed`

### W5: Deterministic Replay Contract

Offloaded execution remains replay-safe only when the worker envelope includes:

1. `seed`
2. `decision_seq`
3. `issued_at_turn` (host turn identifier)
4. `replay_hash`

Missing any of these is a policy violation.

### W6: Required Worker-Offload Test Matrix

The following scenarios are release-blocking for worker-offload policy:

1. `WKR-OFFLOAD-CPU-BURST`
2. `WKR-CANCEL-PROPAGATION`
3. `WKR-OWNERSHIP-NO-CROSS-REGION`
4. `WKR-DETERMINISTIC-REPLAY`
5. `WKR-PAYLOAD-BOUNDARY`

Deterministic validation commands:

```bash
python3 scripts/check_wasm_worker_offload_policy.py --self-test
python3 scripts/check_wasm_worker_offload_policy.py \
  --policy .github/wasm_worker_offload_policy.json
```

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

Timer backend adaptation contract (`asupersync-umelq.5.2`) binds this to explicit policy:

- Use a monotonic browser clock adapter fed by host samples (for example `performance.now()`).
- First host sample after bootstrap or resume establishes baseline and does not jump runtime time.
- Regressed host samples are clamped (runtime time never moves backward).
- Small sub-floor jitter deltas are accumulated, then released deterministically.
- Large forward deltas are capped per observation via `max_forward_step`, with remaining debt drained across subsequent observations.
- Visibility suspend/resume must call clock suspend/resume so hidden-tab gaps do not explode timer deadlines in a single turn.

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

For `asupersync-umelq.5.2`, artifacts must additionally include:

- browser clock policy config (`max_forward_step`, `jitter_floor`),
- deferred catch-up progression snapshot,
- suspend/resume transition evidence.

## Reproduction Commands

Use remote offload for cargo-heavy commands:

```bash
rch exec -- cargo test --all-targets sched_browser -- --nocapture
rch exec -- cargo test -p asupersync --features test-internals parity_browser_scheduler -- --nocapture
rch exec -- cargo test -p asupersync browser_clock -- --nocapture
rch exec -- cargo test -p asupersync timer_driver_with_browser_clock -- --nocapture
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

## Browser Trace Schema v1 Contract (`asupersync-umelq.12.1`)

Browser incident forensics requires a deterministic trace payload contract that
is stable across replay tooling and browser adapters.

Canonical implementation surface:

- `src/trace/event.rs`:
  - `BROWSER_TRACE_SCHEMA_VERSION`
  - `BrowserTraceSchema`
  - `browser_trace_schema_v1()`
  - `validate_browser_trace_schema(...)`
  - `decode_browser_trace_schema(...)`
  - `redact_browser_trace_event(...)`
  - `browser_trace_log_fields(...)`

Normative event taxonomy categories:

- `scheduler`
- `timer`
- `host_callback`
- `capability_invocation`
- `cancellation_transition`

Required structured-log fields for browser trace diagnostics:

- `capture_host_time_ns`
- `capture_host_turn_seq`
- `capture_replay_key`
- `capture_source`
- `capture_source_seq`
- `trace_id`
- `schema_version`
- `event_kind`
- `seq`
- `time_ns`
- `sequence_group`
- `validation_status`
- `validation_failure_category`

Capture metadata policy (`asupersync-umelq.12.2`):

- Browser adapters should sample and attach host metadata for time/event/input
  callbacks using deterministic counters:
  - `capture_source`: one of `time`, `event`, `host_input`.
  - `capture_host_turn_seq`: monotonic host turn index.
  - `capture_source_seq`: monotonic source-local sequence index.
  - `capture_host_time_ns`: sampled host timestamp in nanoseconds.
- When explicit capture metadata is unavailable, runtime reconstruction uses
  deterministic fallback values derived from `(seq, time_ns)` and marks source
  as `runtime`.
- `capture_replay_key` is canonicalized as
  `{capture_source}:{capture_host_turn_seq}:{capture_source_seq}:{capture_host_time_ns}`.

Backward decode policy:

- v1 readers must decode `browser-trace-schema-v0` payloads through the
  compatibility alias path and normalize to v1 semantics.
- v0 payloads that only provide `event_kind` entries are promoted to full v1
  event specs using canonical category/required-field/redaction defaults.
- Unknown legacy event kinds fail closed during decode.
- Unsupported schema versions fail closed with explicit validation errors.

Redaction policy:

- `user_trace.message` is redacted for browser-oriented diagnostic payloads.
- `chaos_injection.detail` is redacted for browser-oriented diagnostic payloads.

## Replay Engine Artifact Contract (`asupersync-umelq.12.3`)

Browser incident replay must emit structured artifacts that are replayable in CI
and local debugging.

Canonical implementation surface:

- `src/trace/replayer.rs`:
  - `TraceReplayer::browser_replay_report(...)`
  - `BrowserReplayReport`
  - `BrowserReplayReport::to_json_pretty(...)`

Required report fields:

- `trace_id`
- `schema_version`
- `seed`
- `event_count`
- `replayed_events`
- `completed`
- `divergence_index`
- `divergence_context`
- `minimization_prefix_len`
- `minimization_reduction_pct`
- `artifact_pointer`
- `rerun_commands`

Minimization policy:

- On divergence, replay artifacts must include a deterministic minimal prefix
  length derived from the first divergent index.
- `minimization_reduction_pct` quantifies how much shorter the prefix is than
  the full trace for fast repro loops.
