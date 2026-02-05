# RuntimeState Contention + Access Inventory (bd-23kbc)

## RuntimeState Struct Definition

**File:** `src/runtime/state.rs` lines 318-372

| # | Field | Type | Hot Path? |
|---|-------|------|-----------|
| 1 | `regions` | `RegionTable` | Warm |
| 2 | `tasks` | `TaskTable` (includes stored futures) | **HOT** |
| 3 | `obligations` | `ObligationTable` | Warm |
| 4 | `now` | `Time` | Read-only (prod) |
| 5 | `root_region` | `Option<RegionId>` | Cold |
| 6 | `trace` | `TraceBufferHandle` | Warm (append-only, internally atomic) |
| 7 | `metrics` | `Arc<dyn MetricsProvider>` | Hot (Arc clone) |
| 8 | `io_driver` | `Option<IoDriverHandle>` | Warm |
| 9 | `timer_driver` | `Option<TimerDriverHandle>` | Warm |
| 10 | `logical_clock_mode` | `LogicalClockMode` | Read-only after init |
| 11 | `cancel_attribution` | `CancelAttributionConfig` | Read-only after init |
| 12 | `entropy_source` | `Arc<dyn EntropySource>` | Read-only after init |
| 13 | `observability` | `Option<RuntimeObservability>` | Read-only after init |
| 14 | `blocking_pool` | `Option<BlockingPoolHandle>` | Warm |
| 15 | `obligation_leak_response` | `ObligationLeakResponse` | Read-only after init |
| 16 | `leak_escalation` | `Option<LeakEscalation>` | Read-only after init |
| 17 | `leak_count` | `u64` | Cold |

**Current synchronization:** Single `Arc<Mutex<RuntimeState>>` shared by all workers.

## Access Frequency Summary

### HOT (every poll cycle)

- `tasks.get/get_mut` — start_running, begin_poll, complete, wake_state reads
- `stored_futures` — remove before poll, insert after Pending
- `tasks` intrusive links — LocalQueue push/pop/steal
- `metrics` Arc clone — once per poll start
- `tasks.get().wake_state.notify()` — inject_cancel, inject_ready, inject_timed, spawn, wake (dedup check)

### WARM (per task/obligation lifecycle)

- `tasks` insert/remove — spawn/complete
- `regions` add_task/remove_task/advance_state — task lifecycle
- `obligations` insert/commit/abort — obligation lifecycle
- `trace` push_event — spawn/complete/cancel events
- `now` read — timestamps on lifecycle events

### COLD (periodic/rare)

- Full arena iteration — Lyapunov snapshots, quiescence checks, diagnostics
- Region tree walk — cancel_request
- `now` write — Lab mode only
- Config field reads — task creation (Cx building)

## Cross-Entity Operations (multi-field atomic access)

| Operation | Fields Touched | Frequency |
|-----------|---------------|-----------|
| `task_completed` | tasks + obligations + regions + trace + metrics + now + leak_count | Per task complete |
| `cancel_request` | regions + tasks + trace + metrics + now | Per cancellation |
| `advance_region_state` | regions + tasks + obligations + trace + now | Per region transition |
| `create_task` | tasks + regions + now + trace + metrics + config | Per spawn |
| `create/commit/abort_obligation` | obligations + regions + trace + metrics + now | Per obligation |
| `drain_ready_async_finalizers` | regions + tasks + now + trace | After task_completed |
| `snapshot` / `is_quiescent` | ALL arenas + trace + now | Diagnostics only |

## Proposed Shard Boundaries

### Shard A: TaskShard (tasks + stored_futures)
- **Hottest data** — accessed on every poll cycle
- IntrusiveStack (LocalQueue) operates on `&mut Arena<TaskRecord>`
- Splitting from other shards eliminates contention with obligation/region ops
- **Expected impact: VERY HIGH contention reduction**

### Shard B: RegionShard (regions + root_region)
- Warm access (per task lifecycle via advance_region_state)
- Independent from per-poll hot path

### Shard C: ObligationShard (obligations + leak_count + leak config)
- Own lifecycle (create/commit/abort/leak)
- Only accessed from hot path via task_completed (orphan abort)

### Shard D: InstrumentationShard (trace + metrics + now)
- `trace` and `metrics` are already internally thread-safe (Arc + atomics)
- Can likely be extracted from Mutex entirely (see Quick Wins)

### Shard E: ConfigShard (io_driver, timer_driver, clock mode, entropy, etc.)
- Read-only after initialization
- Should be `Arc<ShardedConfig>` with no lock needed

## Quick Wins (low risk, high impact)

1. **Extract `trace` + `metrics` from Mutex** — both wrap Arc with internal atomics. Clone once at scheduler init. Removes instrumentation from lock path.

2. **Extract config as `Arc<ShardedConfig>`** — fields 10-16 are never written after init. Zero-cost reads.

3. **Make `now` an `AtomicU64` in production** — read-only in prod (only Lab writes). Eliminates from lock path.

4. **Move `wake_state` dedup out of Mutex** — `inject_cancel/ready/timed`, `spawn`, `wake` all lock Mutex just to call `tasks.get(id).wake_state.notify()`. Since wake_state is already atomic, maintain a separate `HashMap<TaskId, Arc<TaskWakeState>>` for lock-free dedup.

## Key Constraint: task_completed Bottleneck

`task_completed` (state.rs:1835-1913) touches ALL shards on every task completion:
1. Remove from tasks (A)
2. Iterate + abort orphan obligations (C)
3. Remove task from region, advance state (B)
4. Emit trace (D)
5. Potentially recurse via advance_region_state -> parent cascade

**Recommended lock order:** E -> D -> B -> A -> C

This ensures `task_completed` acquires locks in the canonical order (E→D→B→A→C) while performing task removal, obligation scan, region update, and trace emission under the corresponding guards.

## Canonical Lock Order (bd-20way)

### Global Lock Order

When multiple shard locks must be held simultaneously, acquire in this
fixed order to prevent deadlocks:

```
E (Config) → D (Instrumentation) → B (Regions) → A (Tasks) → C (Obligations)
```

**Mnemonic:** **E**very **D**ay **B**rings **A**nother **C**hallenge.

### Rationale

1. **E (Config)** first — read-only after init, so locks are brief or zero-cost
   (`Arc<ShardedConfig>` needs no lock). Listed first because it's accessed
   earliest in task creation (building Cx).

2. **D (Instrumentation)** second — trace/metrics are append-only and may
   become lock-free. When locked, hold briefly for event emission.

3. **B (Regions)** before A/C — region operations (create, close, advance_state)
   gate task and obligation operations (admission checks). Region state
   determines whether a task can be created or an obligation resolved.

## Shard Responsibilities (bd-2ijqf)

- **E (Config)**: Immutable `ShardedConfig` and read-only handles. Prefer `Arc`
  and avoid locks entirely after initialization.
- **D (Instrumentation)**: Trace/metrics handles and any structured logging
  buffers. Keep read-mostly and avoid holding across task polling.
- **B (RegionTable)**: Region ownership tree, child lists, cancellation flags,
  and region-level counters/limits.
- **A (TaskTable)**: Task records (scheduling state, wake_state, intrusive
  links) plus stored futures for polling. This is the hot path shard.
- **C (ObligationTable)**: Obligation records and lifecycle state for permits,
  acks, leases, and in-flight resource tracking.

## Extending Safely (New Shards / New Ops)

- **Preserve canonical order**: E→D→B→A→C (or a strict prefix) for any
  multi-shard acquisition.
- **Minimize hold time**: keep cross-shard windows small; snapshot and release
  when possible before acquiring the next shard in order.
- **Avoid reverse edges**: never acquire A before B or C before A/B.
- **Keep effects explicit**: cancellation, obligation, and region state updates
  must remain atomic and deterministic.

## Contention Metrics + E2E Harness

Run the contention harness with structured artifacts:

```bash
cargo test --test contention_e2e --features lock-metrics -- --nocapture
```

Artifacts are written to `target/contention/` when the directory exists or
`CI=1` is set. You can also force a custom location:

```bash
ASUPERSYNC_CONTENTION_ARTIFACTS_DIR=target/contention \
  cargo test --test contention_e2e --features lock-metrics -- --nocapture
```

Related E2E tests (structured logs + traces):

```bash
cargo test --test runtime_e2e -- --nocapture
cargo test --test obligation_lifecycle_e2e -- --nocapture
```

4. **A (Tasks)** before C — task completion triggers orphan obligation abort.
   The natural flow is: complete task (A) → scan+abort obligations (C).

5. **C (Obligations)** last — obligation commit/abort triggers
   `advance_region_state(B)`, but B is already held. If B were after C,
   this would deadlock.

### Lock Combination Rules

| Operation | Locks Needed | Acquisition Order |
|-----------|-------------|-------------------|
| **poll (execute)** | A | A only |
| **push/pop/steal** | A | A only |
| **inject_cancel/ready/timed** | (none with QW#4) or A | A only |
| **spawn/wake** | (none with QW#4) or A | A only |
| **task_completed** | E → D → B → A → C | Full order |
| **cancel_request** | E → D → B → A | Skip C |
| **create_task** | E → D → B → A | Skip C |
| **create_obligation** | E → D → B → C | Skip A (unless logical time from task) |
| **commit/abort_obligation** | E → D → B → C | Skip A |
| **advance_region_state** | E → D → B → A → C | Full order (recursive) |
| **drain_ready_async_finalizers** | E → D → B → A | Skip C |
| **snapshot / is_quiescent** | Read-lock all: E → D → B → A → C | All shards, read-only |
| **Lyapunov snapshot** | Read-lock all: E → D → B → A → C | All shards, read-only |

### Disallowed Lock Sequences (deadlock risk)

These sequences MUST NOT occur:

- **A → B** — Tasks before Regions (violates B → A order)
- **C → A** — Obligations before Tasks (violates A → C order)
- **C → B** — Obligations before Regions (violates B → C order; would deadlock
  commit_obligation → advance_region_state)
- **A → D** — Tasks before Instrumentation (violates D → A order)

### Guard Helpers (proposed API)

```rust
/// Multi-shard lock guard that enforces canonical ordering at the type level.
/// Fields are Option<MutexGuard> acquired in order during construction.
pub struct ShardGuard<'a> {
    config: &'a Arc<ShardedConfig>,              // E: no lock needed
    regions: Option<ContendedMutexGuard<'a, RegionShard>>,     // B
    tasks: Option<ContendedMutexGuard<'a, TaskShard>>,         // A
    obligations: Option<ContendedMutexGuard<'a, ObligationShard>>, // C
}

impl<'a> ShardGuard<'a> {
    /// Lock only the task shard (hot path).
    pub fn tasks_only(shards: &'a ShardedState) -> Self { ... }

    /// Lock for task_completed: E → D → B → A → C.
    pub fn for_task_completed(shards: &'a ShardedState) -> Self { ... }

    /// Lock for cancel_request: E → D → B → A.
    pub fn for_cancel(shards: &'a ShardedState) -> Self { ... }

    /// Lock for obligation lifecycle: E → D → B → C.
    pub fn for_obligation(shards: &'a ShardedState) -> Self { ... }
}
```

### Extending the Order for New Shards

When adding a new shard:

1. Determine which existing shards it interacts with.
2. Place it in the ordering such that:
   - It comes BEFORE any shard it gates/controls.
   - It comes AFTER any shard that triggers operations on it.
3. Update the `ShardGuard` struct and all `for_*` constructors.
4. Add a test that attempts the disallowed reverse order and deadlocks
   (use a timeout-based deadlock detector in tests).

### Deadlock Detection in Tests

```rust
#[cfg(test)]
mod lock_order_tests {
    /// Verify that the documented lock order prevents deadlocks
    /// by attempting concurrent cross-order acquisitions with timeout.
    #[test]
    fn canonical_order_no_deadlock() {
        // Spawn threads that acquire locks in canonical order.
        // All should complete within timeout. If any deadlocks,
        // the test fails via timeout.
    }
}
```

## Trace/Metrics Handle Audit (bd-12389)

### TraceBufferHandle Internals

**Definition:** `src/trace/buffer.rs:110-119`

```
TraceBufferHandle { inner: Arc<TraceBufferInner> }
TraceBufferInner  { buffer: Mutex<TraceBuffer>, next_seq: AtomicU64 }
```

- `next_seq()` (buffer.rs:136) → `fetch_add(1, Ordering::Relaxed)` — **truly lock-free**.
- `push_event()` (buffer.rs:139-147) → acquires internal `Mutex<TraceBuffer>`.
- `Clone` is cheap (Arc clone).

### MetricsProvider Internals

**Definition:** `src/observability/metrics.rs:294`

```rust
pub trait MetricsProvider: Send + Sync + 'static { ... }
```

Stored as `Arc<dyn MetricsProvider>` in RuntimeState (state.rs:332). Trait contract
mandates internal thread-safety; implementations use atomics for hot-path counters.
Access is read-only Arc clone — no external lock needed.

### Current Access Pattern

| Path | What Happens | Lock Cost |
|------|-------------|-----------|
| Worker init (worker.rs:64) | `guard.trace_handle()` — Arc clone under lock | One-time |
| Worker poll (worker.rs:192-196) | `state.metrics_provider()` — Arc clone, then `drop(state)` before use | Minimal |
| `next_trace_seq()` (state.rs:1426) | `self.trace.next_seq()` — lock-free atomic | **Zero** (but caller holds RuntimeState lock) |
| `cancel_request` (state.rs:1520-1722) | `next_seq()` + `push_event()` under RuntimeState lock | Nested: RuntimeState → TraceBuffer |
| `task_completed` path | `push_event()` under RuntimeState lock | Nested: RuntimeState → TraceBuffer |
| Test snapshots (builder.rs:1403+) | `guard.trace.snapshot()` | Test-only |

### Extraction Recommendation

**Verdict: Both TraceBufferHandle and MetricsProvider CAN be extracted from the Mutex.**

1. **TraceBufferHandle** — Clone once per worker at scheduler init (already done in
   worker.rs:64). Pass as a standalone field on `ShardedState` or clone into each
   component that needs it. `next_seq()` calls become fully lock-free. `push_event()`
   uses its own internal Mutex, independent of any shard lock.

2. **MetricsProvider** — Clone `Arc<dyn MetricsProvider>` once per worker/component.
   All metric calls are already lock-free via internal atomics. No shard lock needed.

3. **`now` field** — In production mode, `Time` is read-only (set at runtime init).
   Replace with `AtomicU64` for lock-free reads. Lab mode writes remain sequentially
   consistent via Lab's single-threaded execution model.

### Determinism Invariants

- **Sequence allocation** is non-deterministic under concurrency (atomic race on
  `next_seq`). This is acceptable: trace consumers sort by sequence number, and
  Lab mode runs single-threaded where allocation is deterministic.

- **Buffer insertion order** may differ from sequence order under concurrency
  (thread A gets seq=100, thread B gets seq=101 and pushes first). Consumers
  must sort by `seq`, not insertion order. Already the case today.

- **Lab mode** preserves determinism: single-threaded execution means both
  sequence allocation and buffer insertion are sequential.

### Migration Notes for Shard D

When implementing Shard D (Instrumentation), the extraction is straightforward:

```rust
pub struct ShardedState {
    // Shard D: no lock needed — internally synchronized
    pub trace: TraceBufferHandle,           // Arc<TraceBufferInner>
    pub metrics: Arc<dyn MetricsProvider>,  // Arc with internal atomics
    pub now: AtomicU64,                     // read-only in prod

    // Shards A/B/C: locked
    pub tasks: Mutex<TaskShard>,
    pub regions: Mutex<RegionShard>,
    pub obligations: Mutex<ObligationShard>,
    pub config: Arc<ShardedConfig>,         // Shard E: read-only
}
```

State methods that currently call `self.trace.push_event()` or `self.trace.next_seq()`
under the RuntimeState lock will instead receive `&TraceBufferHandle` as a parameter
or access it from the `ShardedState` without locking. This eliminates the nested lock
pattern (RuntimeState → TraceBuffer) entirely.

## Expected Contention Reduction

| Scenario | Current | After Sharding |
|----------|---------|---------------|
| N workers polling | All contend on single Mutex | Each touches TaskShard only |
| Cancel injection during polling | Blocks behind poll lock | Lock-free wake_state check (QW #4) |
| Obligation commit during polling | Blocks behind poll lock | ObligationShard independent |
| Lyapunov snapshot during polling | Blocks all polls | RwLock per shard; read-only |
| Spawn during polling | Blocks behind poll lock | Region check (B) + task insert (A) pipelined |

## Invariants to Preserve (bd-1tc1m)

The sharding refactor MUST NOT change any observable behavior. These invariants
are hard constraints:

### INV-1: Determinism

Under Lab mode (single-threaded, fixed seed), all trace event sequences,
task scheduling order, and obligation state transitions must be identical
before and after sharding. Verified by: Lab oracle replay + trace diffing.

### INV-2: Cancel-Correctness

`cancel_request(region)` must atomically:
1. Mark the region's cancel flag (B)
2. Propagate to all descendant tasks (A) via wake_state injection
3. Emit trace events (D) for each cancellation

All three must complete as a unit. Partial cancellation (flag set but tasks
not notified) violates cancel-correctness. The lock order E→D→B→A ensures
all shards are held during the operation (E is typically lock-free but still
first in the canonical order).

### INV-3: Obligation Linearity (No Leaks, No Double-Commit)

Every obligation must transition through exactly one of:
`Reserved → Committed` or `Reserved → Aborted` or `Reserved → Leaked`.

`task_completed` must scan and abort orphan obligations atomically with
task removal. Lock order E→D→B→A→C ensures the task is removed (A) before
orphan scan (C), preventing the window where a new obligation could be
created for a dead task.

### INV-4: Region State Machine

Region transitions (Open → Closing → Draining → Finalizing → Closed) must be
monotonic and consistent with child task/obligation counts. The
`advance_region_state` cascade (B→A→C) must not skip states or
leave a region stuck in Closing with zero children.

### INV-5: No Ambient Authority

Tasks must only access state through their `Cx` handle. The sharding
refactor must not expose shard locks to task code. All shard access
goes through `ShardGuard` or equivalent accessor methods.

## Affected Modules (bd-1tc1m)

### High Complexity (API redesign required)

| Module | Shards | Notes |
|--------|--------|-------|
| `src/runtime/state.rs` | ALL | Source module — split into shard structs |
| `src/runtime/builder.rs` | ALL | Runtime init: creates all shards, configures |
| `src/runtime/scheduler/worker.rs` | A, D, E | Hot path: poll loop, task_completed, metrics clone |
| `src/runtime/scheduler/three_lane.rs` | A | Scheduler lanes: tasks arena access |
| `src/runtime/scheduler/local_queue.rs` | A | LocalQueue + Stealer: intrusive stack on tasks arena |
| `src/cx/scope.rs` | A, B, C, D, E | Spawn infrastructure: create_task, create_region, create_obligation |
| `src/lab/runtime.rs` | ALL | Lab runtime: direct mutable state access |

### Medium Complexity (read-only or narrow access)

| Module | Shards | Notes |
|--------|--------|-------|
| `src/runtime/io_op.rs` | C | Obligation create/commit/abort only |
| `src/obligation/lyapunov.rs` | A, B, C, E | Read-only arena iteration for snapshots |
| `src/observability/diagnostics.rs` | A, B, C, E | Read-only arena iteration + timer_driver |
| `src/observability/obligation_tracker.rs` | C, E | Obligation iteration + timer_driver |
| `src/observability/otel.rs` | A, B, D | Arena iteration for metrics export |
| `src/actor.rs` | A | tasks.get_mut() only |
| `src/distributed/bridge.rs` | A, B | Arena access for coordination |
| `src/distributed/encoding.rs` | A, B, C | Arena access for serialization |
| `src/distributed/recovery.rs` | A, B, C | Arena access for state recovery |
| `src/distributed/snapshot.rs` | ALL | Full state serialization |
| `src/lab/snapshot_restore.rs` | ALL | Full state serialization |

### Low Complexity (minimal surface)

| Module | Shards | Notes |
|--------|--------|-------|
| `src/time/sleep.rs` | D, E | timer_driver + trace only |
| `src/trace/divergence.rs` | A, B, C | Read-only trace analysis |
| `src/trace/tla_export.rs` | A, B, C | Read-only TLA+ export |
| `src/record/region.rs` | A, B, C | Record management |

### Test Files (~100+ files)

All test files that construct `RuntimeState` or call `.lock()` on the
state mutex will need updating. Key categories:

- **Scheduler tests** (`tests/cancel_lane_fairness_bounds.rs`, etc.): Shards A, B
- **E2E tests** (`tests/runtime_e2e.rs`, `tests/obligation_lifecycle_e2e.rs`): ALL
- **Benchmarks** (`benches/phase0_baseline.rs`, etc.): Varies
- **Lab oracles** (`src/lab/oracle/*.rs`): A, B, C (read-only iteration)

## Test Strategy (bd-1tc1m)

### Phase 1: Unit Tests (per-shard correctness)

| Test Category | What to Verify | Shard(s) |
|---------------|---------------|----------|
| TaskShard CRUD | insert/get/get_mut/remove + intrusive links | A |
| RegionShard lifecycle | create/advance_state/close + child counts | B |
| ObligationShard lifecycle | create/commit/abort/leak + orphan scan | C |
| ConfigShard reads | All config fields readable without lock | E |
| InstrumentationShard | trace.push_event + metrics calls without state lock | D |
| ShardGuard construction | Correct lock ordering for each `for_*` constructor | All |
| Disallowed orders | Attempt reverse acquisitions → timeout/deadlock detection | All |

### Phase 2: Lab Tests (determinism + invariant preservation)

| Test Category | What to Verify |
|---------------|---------------|
| Trace replay | Lab run produces identical trace sequences pre/post sharding |
| Cancel cascade | cancel_request propagates to all descendants atomically |
| Obligation linearity | No leaked/double-committed obligations after sharding |
| Region state machine | advance_region_state cascades correctly across shards |
| Lyapunov stability | Snapshot values match pre-sharding baseline |
| task_completed atomicity | Remove task + abort orphans + advance region in one guard |

### Phase 3: E2E Tests (structured logging + trace artifacts)

| Test Category | Structured Logging Fields | Trace Artifacts |
|---------------|--------------------------|-----------------|
| Multi-worker poll contention | `lock_wait_ns`, `shard`, `worker_id` | Per-shard lock timing histograms |
| Cross-shard task_completed | `shards_held`, `lock_order`, `duration_ns` | Lock acquisition waterfall |
| Concurrent spawn + cancel | `task_id`, `region_id`, `cancel_seq` | Cancel propagation graph |
| Obligation commit under load | `obligation_id`, `shard_wait_ns` | Obligation lifecycle timeline |
| Snapshot during active work | `snapshot_duration_ns`, `stale_reads` | Read-lock contention profile |

### Required Structured Logging Fields

All shard operations should emit structured log events with:

```
shard: "A" | "B" | "C" | "D" | "E"
operation: "lock" | "unlock" | "try_lock" | "read_lock" | "read_unlock"
worker_id: u64
wait_ns: u64  // time spent waiting for lock
held_ns: u64  // time lock was held
caller: &str  // method name (e.g., "task_completed", "spawn")
```

Feature-gated behind `cfg(feature = "lock-metrics")`.

## Reviewer Checklist (bd-1tc1m)

When reviewing sharding PRs, verify:

- [ ] **Lock order compliance**: Every multi-shard acquisition follows E→D→B→A→C
- [ ] **No reverse acquisitions**: No code path acquires A before B, C before A, etc.
- [ ] **ShardGuard usage**: All multi-shard operations use `ShardGuard::for_*()` constructors
- [ ] **Trace determinism**: Lab oracle tests pass with identical trace output
- [ ] **Cancel atomicity**: cancel_request holds E+D+B+A for the entire cascade
- [ ] **Obligation orphan scan**: task_completed holds A+C simultaneously
- [ ] **No shard leak**: Shard locks not exposed to task code (only through Cx/scope)
- [ ] **Config immutability**: Shard E has no lock; all fields are read-only after init
- [ ] **Instrumentation lock-free**: Shard D trace/metrics accessed without any shard lock
- [ ] **Test coverage**: New tests for each affected cross-shard operation
- [ ] **Benchmark comparison**: Pre/post contention numbers from bd-3urgh baseline
