# Scheduler Internals

## Three-Lane Architecture

The scheduler (`src/runtime/scheduler/three_lane.rs`) uses three priority lanes:

| Lane | Priority | Source |
|------|----------|--------|
| **Cancel Lane** | 200-255 (highest) | Tasks in CancelRequested/Cancelling/Finalizing states |
| **Timed Lane** | EDF by deadline | Tasks with active deadlines, ordered earliest-deadline-first |
| **Ready Lane** | Default priority | Normal runnable tasks |

### Dispatch Path (Multi-Phase)

1. Global lanes check
2. Fast ready paths
3. Single local-lane lock acquisition (cancel/timed/ready under one lock)
4. Steal attempts from other workers
5. Fallback cancel handling

### Cancel Preemption

- Default `cancel_streak_limit = 16`: ready/timed work gets dispatch within `limit + 1` steps per worker
- During `DrainObligations` and `DrainRegions`: effective bound widens to `2 * cancel_streak_limit`
- Workers track `fairness_yields` and `max_cancel_streak` telemetry

### Adaptive Cancel Preemption (EXP3/Hedge)

Optional deterministic no-regret online controller:

```text
p_t(a) = (1 - gamma) * w_t(a) / sum(w_t) + gamma / K
w_{t+1}(a) = w_t(a) * exp((gamma / K) * r_hat_t(a))
```

- Selects cancel-streak limits per epoch from candidate set (e.g., {4, 8, 16, 32})
- Reward blends Lyapunov decrease + fairness pressure + deadline pressure
- Preserves deterministic replay semantics
- Enable: `RuntimeBuilder::enable_adaptive_cancel_streak(true)`

### Lyapunov Governor

Optional governor steers lane ordering from runtime snapshots:
- Off by default; configurable interval (default 32)
- When enabled, can be modulated by decision contract with Bayesian posterior over {healthy, congested, unstable, partitioned}
- Source: `src/runtime/scheduler/decision_contract.rs`

## Sharded Runtime State

State split into independently locked shards (`src/runtime/sharded_state.rs`):

| Shard | Contents |
|-------|----------|
| A (tasks) | Task table, stored futures, intrusive queue links |
| B (regions) | Region ownership tree, state transitions |
| C (obligations) | Permit/ack/lease lifecycle, leak tracking |
| D (instrumentation) | Trace and metrics surfaces |
| E (config) | Immutable runtime config |

Multi-shard operations use `ShardGuard` with canonical order: `E -> D -> B -> A -> C`.

Shard locks are `ContendedMutex` instances. Optional `lock-metrics` feature measures wait/hold times.

## Worker Coordination

- Round-robin targeted unparks with bitmask fast path (power-of-two worker count)
- Centralized wake dedup: `Idle -> Polling -> Notified` state machine
- Permit-style `Parker` with queue rechecks after wakeups (closes lost-wakeup races)
- I/O polling: leader/follower -- worker acquiring I/O driver lock runs reactor turn

## Local Queue Discipline

- Owner operations: LIFO (cache locality)
- Thief operations: FIFO (steal older work, reduce starvation)
- Local `!Send` tasks pinned to owner workers, routed through non-stealable queues
- Steal paths explicitly reject moving pinned tasks across workers
- Queue-tag membership checks on intrusive links (O(1) pop without allocation)

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

## Timer Wheel

`src/time/wheel.rs`, `src/time/driver.rs`:
- Generation-based O(1) cancel
- Overflow spill for long deadlines, promoted back in range
- Coalescing windows batch nearby wakeups with minimum-group gating
- Benchmarked 2.67x cancel-path advantage over BTreeMap at 10K corpus

## Runtime Builder Presets

```rust
RuntimeBuilder::current_thread()   // CLI, simple services, determinism-first
RuntimeBuilder::low_latency()      // Request/response APIs, latency-sensitive
RuntimeBuilder::high_throughput()  // Queue-heavy, fan-out, high concurrency
```

Key knobs: `blocking_threads(min, max)`, `poll_budget(n)`, `cancel_lane_max_streak(n)`, `enable_adaptive_cancel_streak(bool)`, `enable_governor(bool)`, `governor_interval(n)`, `root_region_limits(...)`, `deadline_monitoring(...)`, `logical_clock_mode(...)`, `cancel_attribution_config(...)`, `obligation_leak_response(...)`, `enable_time()`, `observability(...)`, `metrics(...)`.

Configuration layering: defaults < TOML (`from_toml()` / `from_toml_str()` with
the `config-file` feature) < env (`with_env_overrides()`) < programmatic.

Runtime CPU work added `runtime-metrics`, `runtime::metrics::snapshot()`, a
scheduler CPU/churn benchmark, and a validation script for idle busy-spin,
idle-CPU, and timer-thread churn regressions. Treat measured bench results as
the authority; the late-June spin-over-yield hypothesis was bench-refuted.

## Panic Containment

Task polling guarded: panics converted to `Outcome::Panicked`, dependents/finalizers still driven, one bad task does not take down a worker lane.
