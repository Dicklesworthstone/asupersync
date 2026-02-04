# RuntimeState Contention + Access Inventory (bd-23kbc)

## RuntimeState Struct Definition

**File:** `src/runtime/state.rs` lines 318-364

| # | Field | Type | Hot Path? |
|---|-------|------|-----------|
| 1 | `regions` | `Arena<RegionRecord>` | Warm |
| 2 | `tasks` | `Arena<TaskRecord>` | **HOT** |
| 3 | `obligations` | `Arena<ObligationRecord>` | Warm |
| 4 | `now` | `Time` | Read-only (prod) |
| 5 | `root_region` | `Option<RegionId>` | Cold |
| 6 | `trace` | `TraceBufferHandle` | Warm (append-only, internally atomic) |
| 7 | `metrics` | `Arc<dyn MetricsProvider>` | Hot (Arc clone) |
| 8 | `stored_futures` | `HashMap<TaskId, StoredTask>` | **HOT** |
| 9-15 | Config fields | Various | Read-only after init |
| 16-18 | Leak tracking | Various | Cold |

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
| `advance_region_state` | regions + tasks + obligations + trace + stored_futures + now | Per region transition |
| `create_task` | tasks + regions + now + trace + metrics + config | Per spawn |
| `create/commit/abort_obligation` | obligations + regions + trace + metrics + now | Per obligation |
| `drain_ready_async_finalizers` | regions + tasks + stored_futures + now + trace | After task_completed |
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
- Should be `Arc<RuntimeConfig>` with no lock needed

## Quick Wins (low risk, high impact)

1. **Extract `trace` + `metrics` from Mutex** — both wrap Arc with internal atomics. Clone once at scheduler init. Removes instrumentation from lock path.

2. **Extract config as `Arc<RuntimeConfig>`** — fields 9-15 are never written after init. Zero-cost reads.

3. **Make `now` an `AtomicU64` in production** — read-only in prod (only Lab writes). Eliminates from lock path.

4. **Move `wake_state` dedup out of Mutex** — `inject_cancel/ready/timed`, `spawn`, `wake` all lock Mutex just to call `tasks.get(id).wake_state.notify()`. Since wake_state is already atomic, maintain a separate `HashMap<TaskId, Arc<TaskWakeState>>` for lock-free dedup.

## Key Constraint: task_completed Bottleneck

`task_completed` (state.rs:1835-1913) touches ALL shards on every task completion:
1. Remove from tasks (A)
2. Iterate + abort orphan obligations (C)
3. Remove task from region, advance state (B)
4. Emit trace (D)
5. Potentially recurse via advance_region_state -> parent cascade

**Recommended lock order:** D -> E -> B -> A -> C

This ensures task_completed acquires: A (task removal) -> C (orphan scan) -> B (region update) -> D (trace emit), following the ordering convention.

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
   (`Arc<RuntimeConfig>` needs no lock). Listed first because it's accessed
   earliest in task creation (building Cx).

2. **D (Instrumentation)** second — trace/metrics are append-only and may
   become lock-free. When locked, hold briefly for event emission.

3. **B (Regions)** before A/C — region operations (create, close, advance_state)
   gate task and obligation operations (admission checks). Region state
   determines whether a task can be created or an obligation resolved.

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
| **task_completed** | D → B → A → C | Full order |
| **cancel_request** | D → B → A | Skip C |
| **create_task** | E → D → B → A | Skip C |
| **create_obligation** | D → B → C | Skip A (unless logical time from task) |
| **commit/abort_obligation** | D → B → C | Skip A |
| **advance_region_state** | D → B → A → C | Full order (recursive) |
| **drain_ready_async_finalizers** | D → B → A | Skip C |
| **snapshot / is_quiescent** | Read-lock all: D → B → A → C | All shards, read-only |
| **Lyapunov snapshot** | Read-lock all: D → B → A → C | All shards, read-only |

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
    config: &'a Arc<RuntimeConfig>,        // E: no lock needed
    instrumentation: Option<InstrGuard>,   // D: trace + metrics
    regions: Option<MutexGuard<'a, RegionShard>>,     // B
    tasks: Option<MutexGuard<'a, TaskShard>>,         // A
    obligations: Option<MutexGuard<'a, ObligationShard>>, // C
}

impl<'a> ShardGuard<'a> {
    /// Lock only the task shard (hot path).
    pub fn tasks_only(shards: &'a ShardedState) -> Self { ... }

    /// Lock for task_completed: D → B → A → C.
    pub fn for_task_completed(shards: &'a ShardedState) -> Self { ... }

    /// Lock for cancel_request: D → B → A.
    pub fn for_cancel(shards: &'a ShardedState) -> Self { ... }

    /// Lock for obligation lifecycle: D → B → C.
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

## Expected Contention Reduction

| Scenario | Current | After Sharding |
|----------|---------|---------------|
| N workers polling | All contend on single Mutex | Each touches TaskShard only |
| Cancel injection during polling | Blocks behind poll lock | Lock-free wake_state check (QW #4) |
| Obligation commit during polling | Blocks behind poll lock | ObligationShard independent |
| Lyapunov snapshot during polling | Blocks all polls | RwLock per shard; read-only |
| Spawn during polling | Blocks behind poll lock | Region check (B) + task insert (A) pipelined |
