# Scheduler Internals

## Table of Contents

- [Three-Lane Architecture](#three-lane-architecture)
- [Adaptive Cancel Preemption](#adaptive-cancel-preemption-default-on)
- [Lyapunov Governor](#lyapunov-governor)
- [Runtime State Backing](#runtime-state-backing)
- [Worker Coordination](#worker-coordination)
- [Local Queue Discipline](#local-queue-discipline)
- [Global Injector](#global-injector)
- [Region Heap](#region-heap)
- [Blocking Pool](#blocking-pool)
- [Timer Wheel](#timer-wheel)
- [Runtime Builder Presets](#runtime-builder-presets)
- [Panic Containment](#panic-containment)

## Three-Lane Architecture

The scheduler (`src/runtime/scheduler/three_lane.rs`) uses three priority lanes:

| Lane | Ordering within lane | Source |
|------|----------------------|--------|
| **Cancel Lane** | task priority `0..=255`, then FIFO tie-break | Tasks explicitly injected or promoted for cancellation |
| **Timed Lane** | earliest deadline first, then FIFO tie-break | Due tasks with active deadlines |
| **Ready Lane** | task priority `0..=255`, then FIFO tie-break | Normal runnable tasks |

Lane membership, not a `200` priority threshold, gives cancellation its normal
preemption. Even a low-priority cancel-lane task precedes a priority-255 ready
task unless a fairness or governor rule temporarily selects another lane.

### Dispatch Path (Multi-Phase)

1. Drain handle-cancel/deferred-cancel commands, process timers, and admit
   mailbox plus owner-local spawns.
2. Consult the governor and fairness gates.
3. Probe global and local cancel/timed lanes in the governor-selected order;
   local priority lanes share one `PriorityScheduler` lock acquisition.
4. Probe owner-pinned local-ready, stolen fast-ready, global-ready, then local
   ready work.
5. Steal ready work from peers.
6. If the cancel fairness limit was reached but no other work exists, dispatch
   one fallback cancel task.

### Cancel Preemption

- Default `cancel_streak_limit = 16`: ready/timed work gets dispatch within `limit + 1` steps per worker
- During `DrainObligations` and `DrainRegions`: effective bound widens to `2 * cancel_streak_limit`
- Workers track `fairness_yields` and `max_cancel_streak` telemetry

These are worker-local successful-dispatch bounds, not wall-clock latency or a
global priority order. A future that monopolizes one `poll`, or cross-worker
stealing, is outside the bound.

### Adaptive Cancel Preemption (Default-On)

Deterministic nonstationary stochastic-bandit controller, **enabled by default**
(`enable_adaptive_cancel_streak = true`, epoch steps default 128):

- HEAD implements a discounted-UCB1 policy (`AdaptiveCancelStreakPolicy` in
  `three_lane.rs`) over the fixed candidate arm set `{4, 8, 16, 32, 64}`
  (default arm = 16), with an e-process monitor over epoch rewards
- Reward in [0, 1] blends Lyapunov decrease + fairness pressure + deadline
  pressure (+ fallback penalty)
- Preserves deterministic replay semantics
- Knobs: `enable_adaptive_cancel_streak(bool)`,
  `adaptive_cancel_streak_epoch_steps(n)`

Do not conflate this scheduler policy with ATP transport's separately seeded
EXP3 controller. Scheduler cancel preemption is discounted UCB1; ATP's transport
controller is the surface where EXP3 remains an accurate term. The scheduler
implementation makes no adversarial or stochastic no-regret theorem claim.

### Lyapunov Governor

Optional governor steers lane ordering from runtime snapshots:
- Off by default; configurable interval (default 32)
- When enabled, can be modulated by decision contract with Bayesian posterior over {healthy, congested, unstable, partitioned}
- Source: `src/runtime/scheduler/decision_contract.rs`

## Runtime State Backing

`ShardedState` defines independently locked tables
(`src/runtime/sharded_state.rs`):

| Shard | Contents |
|-------|----------|
| A (tasks) | Task table, stored futures, intrusive queue links |
| B (regions) | Region ownership tree, state transitions |
| C (obligations) | Permit/ack/lease lifecycle, leak tracking |
| D (instrumentation) | Trace and metrics surfaces |
| E (config) | Immutable runtime config |

Multi-shard `ShardGuard` operations acquire the mechanically tracked table locks
in `B -> A -> C` order. The wider rank vocabulary is
`E -> D -> B -> A -> C`: E is immutable, while D uses internal synchronization
and is not represented by `LockShard`.

Shards A/B/C are Arc-shared `ContendedMutex` instances with exact-handle
accessors. Shard D is internally synchronized (the trace handle owns a short
mutex and metrics are thread-safe); shard E is read-only. The optional
`lock-metrics` feature measures wait/hold times.

Backing shape is `RuntimeStateShape`: default `Unified` (single-lock state);
`RuntimeBuilder::with_sharded_state(true)` opts into `Sharded`, where workers
dispatch against shard A and obligation mint/settlement targets shard C via
wrapper-side resolution in `src/runtime/state.rs` (A-then-C guard order,
buffered effect sinks, post-release drain). This is currently a hybrid route:
region records remain embedded in the unified `RuntimeState`, so shard B and
`region_shard_handle` are not the public runtime's lifecycle owner yet. Do not
describe `with_sharded_state(true)` as a full A/B/C cutover.

`Unified` remains the v0.4.3-compatible default. Sharding is an opt-in
implementation choice, not permission to change public signatures or
documented cancellation behavior.

## Worker Coordination

- Round-robin targeted unparks with bitmask fast path (power-of-two worker count)
- Centralized wake dedup: `Idle -> Polling -> Notified` state machine
- Permit-style `Parker` with queue rechecks after wakeups (closes lost-wakeup races)
- I/O polling: leader/follower -- worker acquiring I/O driver lock runs reactor turn

## Local Queue Discipline

- Owner operations: LIFO (cache locality)
- Thief operations: FIFO (steal older work, reduce starvation)
- Local `!Send` tasks pinned to owner workers, routed through non-stealable queues
- Local spawn/wake/cancel TLS fast paths verify the runtime-unique scheduler or
  `SpawnMailbox` owner, not only the numeric worker id; a foreign-runtime
  `Cx::spawn_local` fails with `LocalSchedulerUnavailable` before allocation
- Steal paths explicitly reject moving pinned tasks across workers
- Queue-tag membership checks on intrusive links (O(1) pop without allocation)
- Local ready queue uses O(1) lazy-tombstone cancellation (`LocalReadyQueueInner`),
  so mass cancellation avoids O(n^2) scan-and-remove
- Optional topology-aware steal ordering: explicit `worker_cohorts(...)` mapping
  plus `scheduler_placement_mode(...)` (`LocalityFirst` default / `LatencyFirst` /
  `ThroughputFirst`); deterministic victim ordering only, no host probing

## Global Injector

- Timed counters incremented before heap insert, saturating decrements on pop
- Cached earliest-deadline fast path: workers skip timed-lane mutex when no deadline work
- Ready-queue limits emit capacity warnings (not drops) -- preserves structured concurrency

## Region Heap

Stable handles (`HeapIndex`) with slot index, generation, and type tag:
- Generation increments on reuse -- ABA prevention
- Deterministic reuse order for identical sequences
- Reclamation wired to region close/quiescence, not opportunistic frees

Source: `src/runtime/region_heap.rs`

## Blocking Pool

`src/runtime/blocking_pool.rs`:
- Expansion only when pending work exists and all active workers busy
- Idle retirement uses atomic claim (cannot retire below `min_threads`)
- Panicking tasks wrapped for completion signaling
- Failed spawns roll back accounting immediately
- The live worker cap can change within the configured min/max bounds; cohort
  affinity is optional and does not guarantee one live worker per cohort

## Timer Wheel

`src/time/wheel.rs`, `src/time/driver.rs`:
- Generation-based O(1) cancel
- Overflow spill for long deadlines, promoted back in range
- Coalescing windows batch nearby wakeups with minimum-group gating
- A point-in-time 2026-06-01 `release-perf` run recorded a ~27x cancel-path
  advantage over `BTreeMap` at the 10K corpus and a 2.15x mixed-workload win
  (`benches/timer_wheel.rs`). Those host-dependent historical measurements are
  not a current performance guarantee; rerun the benchmark's documented command
  before citing present-day numbers.

## Runtime Builder Presets

```rust
RuntimeBuilder::current_thread()   // CLI, simple services, determinism-first (1 worker)
RuntimeBuilder::multi_thread()     // Deterministic default worker count (4, host-independent)
RuntimeBuilder::low_latency()      // Request/response APIs (steal batch 4, poll budget 32)
RuntimeBuilder::high_throughput()  // Queue-heavy, fan-out (2x default workers, steal batch 32)
```

Key knobs: `blocking_threads(min, max)`, `poll_budget(n)` (default 128),
`steal_batch_size(n)` (default 16), `cancel_lane_max_streak(n)` (default 16),
`enable_adaptive_cancel_streak(bool)` (default true),
`adaptive_cancel_streak_epoch_steps(n)`, `enable_governor(bool)`,
`governor_interval(n)`, `with_sharded_state(bool)`, `spawn_admission(mode)`
(`Direct` default / `Mailbox` lock-free spawn mailbox), `worker_cohorts(...)`,
`scheduler_placement_mode(...)`, `adaptive_ready_batch(...)` (disabled by
default), `browser_ready_handoff_limit(...)`, `blocking_affinity_profile(...)`,
`capacity_hints(...)` / `expected_concurrent_tasks(n)`,
`arena_temperature_policy(...)`,
`trace_storage_profile(...)`, `root_region_limits(...)`,
`deadline_monitoring(...)`, `logical_clock_mode(...)`,
`cancel_attribution_config(...)`, `obligation_leak_response(...)`,
`enable_time()`, `observability(...)`, `metrics(...)`.

Configuration layering: defaults < TOML/JSON (`from_toml()` / `from_toml_str()`
/ `from_json()` / `from_json_str()` with the `config-file` feature) < env
(`with_env_overrides()`) < programmatic.

Runtime CPU work added `runtime-metrics`, `runtime::metrics::snapshot()`, a
scheduler CPU/churn benchmark, and a validation script for idle busy-spin,
idle-CPU, and timer-thread churn regressions. Treat measured bench results as
the authority; the late-June spin-over-yield hypothesis was bench-refuted.

## Panic Containment

Task polling is guarded: ordinary unwinds become `Outcome::Panicked`, and the
runtime continues dependent/finalizer cleanup instead of intentionally losing
the worker lane. This does not cover `panic = "abort"`, a process abort, or
every foreign callback/destructor; use the out-of-lock effect rules in
`LOCK-ORDERING.md` for those boundaries.
