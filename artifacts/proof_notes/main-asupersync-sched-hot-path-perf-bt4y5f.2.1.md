# Scheduler Lock-Site Inventory Proof Note

Bead: `asupersync-sched-hot-path-perf-bt4y5f.2.1`

Source basis: committed `HEAD` at `9218f4d0f` plus the existing
`docs/runtime_state_contention_inventory.md` contention map. The local worktree
also contained peer A2.2 spawn API WIP while this note was written; those dirty
files were not used as evidence.

This note is the Phase 6 inventory/spec artifact for converting scheduler and
builder paths away from a unified `RuntimeState` mutex. It does not claim that
the conversion has landed, that benchmarks improved, or that broad Cargo gates
are green.

## Canonical Order

When multiple shard locks are required, the project order is:

`E (Config) -> D (Instrumentation) -> B (Regions) -> A (Tasks) -> C (Obligations)`

The current `ShardedState` model makes E and D effectively lock-free handles in
most paths, so the enforced table-lock suffix is normally `B -> A -> C`.

## Site Inventory

| Site | Current unified-lock reason | Shards touched | Required order | Conversion plan |
| --- | --- | --- | --- | --- |
| `NativeThreadHostServices::start_deadline_monitor` | Periodic monitor snapshots `now` and `tasks_iter()` under state lock. | D + A | D -> A | Make time/metrics read handles lock-free and snapshot the task shard only. Keep deadline analysis outside the lock, as it already does after `drop(guard)`. |
| `RuntimeHandle::is_quiescent` | Calls `RuntimeState::is_quiescent()` for a full runtime liveness answer. | B + A + C + D | D -> B -> A -> C | Keep as a diagnostic whole-state read. Sharded implementation should take read snapshots in canonical order, then compute quiescence after releasing guards when possible. |
| `RuntimeHandle::draining_region_count` | Reads cleanup debt through `draining_region_count_for_snapshot()`. | B | B only | Route directly to the region shard cached/snapshot counter. |
| `RuntimeHandle::resource_monitor` | Clones the runtime resource monitor handle. | D | D only | Move to instrumentation/config handle storage so the call is lock-free. |
| `RuntimeHandle::trace_buffer_capacity` | Reads trace-buffer capacity. | D | D only | Expose from trace handle/config without acquiring task/region/obligation shards. |
| `Runtime::initialize_root_region` | Applies config knobs, installs timer default, creates root region and optional root limits. | E + D + B | E -> D -> B | Builder-time initialization may remain serialized, but the sharded path should copy config into immutable E/D handles first, then create/update only the region shard. |
| `Runtime::new` spawn-mailbox bootstrap | Clones trace handle, root region pending-spawn counter, and timer driver while attaching the mailbox. | D + B | D -> B | Read D handles from lock-free runtime handles; read root pending-spawn counter from B. Do not touch task or obligation shards. |
| `Runtime::new` blocking-pool install | Stores a blocking pool handle into runtime state after pool creation. | E | E only | Treat as builder-time config/handle wiring; move to immutable runtime handles or a dedicated config/handle cell before workers start. |
| `RuntimeInner::spawn` mailbox mode | Enqueues request and wakes scheduler without `RuntimeState` lock. | B handle only via reserved counter | B only before enqueue | Already the desired direction. E1.2 should preserve pending-spawn reservation as a region-owned credit and keep enqueue/wake outside table locks. |
| `RuntimeInner::spawn` legacy fallback | Calls `create_task()` under state lock, then injects ready. | B + A + D | D -> B -> A | Prefer mailbox mode. If fallback remains, split admission into region admission (B), task insertion (A), and trace/metrics (D) in canonical order. |
| `RuntimeInner::spawn_with_cx` | Builds system Cx, creates task infrastructure, stores the future. | E + D + B + A | E -> D -> B -> A | Snapshot immutable handles and instrumentation first, admit into the root region, then insert/store the task future in A. Keep user factory execution outside locks. |
| `current_runtime_has_live_tasks` | Reads `live_task_count()` for block-on liveness. | A | A only | Route to a task-shard live-count accessor. |
| request-Cx handle snapshot in builder | Clones timer/logical-clock, observability, IO, blocking, entropy, trace, and loser-drain handles for a request-scoped Cx. | E + D + B | E -> D -> B | Move immutable handles to E/D. Region-specific observability remains a B read keyed by root/request region. |
| `LocalQueue::TaskSource::RuntimeState::with_tasks_arena_mut` | Local queue mutates task arena through unified state when no direct task table is provided. | A | A only | Existing `TaskSource::TaskTable` path is the conversion shape. Production sharded scheduler should construct local queues with `Arc<ContendedMutex<TaskTable>>`. |
| `ThreeLaneScheduler::with_task_table_ref` | Wake-state/locality checks read task records through unified state unless a task table is supplied. | A | A only | Existing optional `task_table` parameter is the conversion seam. Route scheduler construction through task-table backing. |
| `ThreeLaneWorker::with_task_table` / `with_task_table_ref` | Poll loop task lookup, task mutation, stored-future remove/restore, and cancel-ack consumption. | A | A only | Keep these on the task shard. This is the hot path and must not acquire B or C for ordinary poll/remove/store operations. |
| `inject_ready`, `inject_timed`, `inject_cancel`, `schedule_internal` | Atomic wake-state check plus queue injection. | A + scheduler queues | A only | Wake-state dedup belongs to the task shard or a lock-free wake-state map. Scheduler queue locks are independent and must not be held while acquiring B/C. |
| local-task routing inside `inject_cancel` / `schedule_internal` | Moves pinned local work between local scheduler/local-ready queues after reading task locality. | A + local queue locks | A before local queue mutation, no B/C | Read locality under A, release A, then mutate local scheduler queues. Do not acquire region/obligation locks from queue critical sections. |
| `ThreeLaneWorker::drain_spawn_admissions` | Batch-admits mailbox requests through `RuntimeState::admit_spawn_request()`. | B + A + D | D -> B -> A | Admission should lock B for region state/pending credit, then A for task creation. D trace/metrics handles should be pre-cloned/lock-free. Denied/admitted completion callbacks must remain outside locks. |
| `ThreeLaneWorker::governor_suggest` | Builds Lyapunov state snapshot and optional wait graph under state lock, then runs expensive analysis after drop. | D + B + A + C | D -> B -> A -> C | Preserve the current "extract minimal snapshot, analyze after drop" shape. In sharded mode, collect read snapshots in canonical order and keep Tarjan/BTree work outside locks. |
| `StateSnapshot::from_runtime_state` callers in scheduler | Reads region/task/obligation counters for control decisions. | B + A + C + D | D -> B -> A -> C | Convert to a sharded snapshot constructor that reads B/A/C counters in order. Keep cached O(1) counters authoritative where available. |
| `RuntimeStateBacking` trait surface | Defines minimal scheduler operations still served by unified `RuntimeState`. | A, plus B/C for completion/finalizers | A only for poll; B -> A -> C for completion | Keep `task`, `task_mut`, `store_spawned_task`, and `remove_stored_future` on A. Implement `task_completed` and `drain_ready_async_finalizers` with explicit B/A/C guards because they can close regions and resolve obligations. |

## Justified Unified Sites

The following sites are acceptable to keep as whole-state operations until the
E1.2 conversion introduces real sharded backing:

- Builder-time root initialization, because it happens before worker threads
  start and is not a scheduler hot path.
- Whole-runtime diagnostics such as `is_quiescent`, provided the sharded version
  snapshots in canonical order and does not hold locks during expensive analysis.
- Legacy non-mailbox spawn fallback, provided mailbox mode remains the preferred
  production path and fallback is converted before enabling sharded scheduler
  backing by default.

## E1.2 Specification

1. Construct scheduler/local queues with task-shard backing rather than the
   unified `RuntimeState` path.
2. Route task hot-path operations through A-only guards:
   `task`, `task_mut`, `store_spawned_task`, `remove_stored_future`, wake-state
   dedup, and local/global scheduling decisions.
3. Route lifecycle operations through canonical multi-shard guards:
   `task_completed`, finalizer drain, spawn admission, cancellation snapshots,
   and quiescence snapshots.
4. Keep instrumentation/config handles outside table locks wherever the current
   code only clones handles or appends trace/metric events.
5. Preserve the existing invariant that user futures, completion callbacks, and
   expensive graph analysis never run under runtime table locks.

## Review Result

The committed source already contains the key conversion seam:
`src/runtime/scheduler/state_backing.rs` defines `RuntimeStateBacking`, and
`three_lane.rs`/`local_queue.rs` already accept an optional direct `TaskTable`
backing for A-only scheduler hot paths. The remaining E1.2 work is wiring real
sharded construction and replacing the documented unified fallback sites, not
inventing a new shard order.
