# Scheduler Lock-Site Inventory Proof Note

Bead: `asupersync-sched-hot-path-perf-bt4y5f.2.1`

Source basis: committed `HEAD` `f69cde091f9d8588eda4cc699b396925f12f0cb4`.
The audited source paths had no worktree diff at inventory time. Their committed
blob IDs were:

| Path | Blob |
| --- | --- |
| `src/runtime/builder.rs` | `091f1300df00dd2ffcdf6a55b26b13f4d9ae8c33` |
| `src/runtime/scheduler/local_queue.rs` | `f09f5bb32f1241d4a6f2eecedebd9bde14e70227` |
| `src/runtime/scheduler/worker.rs` | `446338ff4032f427ff6a1c479ff9602184bc52eb` |
| `src/runtime/scheduler/three_lane.rs` | `8dfa514f65b175ae6d80fe3a919146e18600c1b4` |
| `src/runtime/scheduler/state_backing.rs` | `541490aa0f2680662ec29401cab0fedf6d3cc02a` |
| `src/runtime/sharded_state.rs` | `e186f8e629b203fb033f377a04512e44a06a981e` |

This is the Phase 6 inventory and the implementation specification for E1.2.
It classifies every production acquisition of the unified `RuntimeState` mutex
in builder and scheduler code. It does not claim that conversion has landed,
that behavior is equivalent between state shapes, that performance improved, or
that broad Cargo gates are green.

## Scope and completeness

The inventory found 46 production acquisitions:

| Path | Production acquisitions |
| --- | ---: |
| `src/runtime/builder.rs` | 13 |
| `src/runtime/scheduler/local_queue.rs` | 1 |
| `src/runtime/scheduler/worker.rs` | 9 |
| `src/runtime/scheduler/three_lane.rs` | 23 |
| **Total** | **46** |

The audit included all scheduler files that retain
`Arc<ContendedMutex<RuntimeState>>`. `state_backing.rs` defines the conversion
seam but does not itself acquire the mutex. `stealing.rs` has no production
`RuntimeState` acquisition.

The following matches are deliberately excluded:

- `builder.rs:4353` locks `std::sync::Mutex<JoinState>`, not `RuntimeState`.
- `builder.rs:4573+`, `local_queue.rs:628+`, and `worker.rs:1104+` are inline
  test modules.
- `three_lane.rs:7803+` is the test module; the isolated `#[cfg(test)]` helper
  at line 1387 has no `RuntimeState` acquisition.
- Queue, parker, `Cx`, protocol-validator, trace-buffer, and scheduler-policy
  mutexes are not unified `RuntimeState` acquisitions and are outside this
  count.

Line anchors below identify acquisitions in the pinned blobs, not stable API
locations.

## Canonical order and labels

The reviewed conceptual order is:

`E (Config) -> D (Instrumentation/time) -> B (Regions) -> A (Tasks) -> C (Obligations)`

E and D are lock-free handles in the current `ShardedState` model. The enforced
mutable-table suffix is therefore normally `B -> A -> C`. A row may use a strict
subsequence such as A-only, `B -> A`, or `B -> C`; it must never introduce
`A -> B`, `C -> A`, or `C -> B`.

The tables classify the semantic state used by each critical section, including
runtime-owned task protocol state as A. Scheduler queues and callbacks are not
shards. “Extract” means move immutable or scheduler-owned state out of the
unified mutex. “Convert” means use the named shard guard. “Justified unified”
is temporary and does not permit enabling sharded mode without an equivalent
ordered implementation.

## Builder inventory: 13 acquisitions

| ID and source anchor | Unified critical section | Shards | Required order | E1.2 conversion or verdict |
| --- | --- | --- | --- | --- |
| B01 `builder.rs:410`, `NativeThreadHostServices::start_deadline_monitor` | Copies cached time and every task deadline snapshot. | D + A | D -> A | Extract the time handle and snapshot A only. Keep deadline analysis after guard release. |
| B02 `builder.rs:3489`, `Runtime::is_quiescent` | Computes whole-runtime liveness. | D + B + A + C | D -> B -> A -> C | Justified diagnostic whole-state read; implement with `ShardGuard::all`, copy counters, then decide after release. |
| B03 `builder.rs:3504`, `Runtime::draining_region_count` | Reads the draining-region counter. | B | B only | Convert to a B snapshot/counter accessor. |
| B04 `builder.rs:3515`, `Runtime::resource_monitor` | Clones the resource-monitor handle. | D | D only | Extract as a lock-free instrumentation handle. |
| B05 `builder.rs:3526`, `Runtime::trace_buffer_capacity` | Reads trace configuration. | D | D only | Extract through the lock-free trace handle. |
| B06 `builder.rs:3952`, `RuntimeInner::initialize_root_region` | Installs configuration/instrumentation and creates/configures the root region. | E + D + B | E -> D -> B | Justified builder-time serialization before workers start; sharded construction must copy E/D first and use B for root creation. |
| B07 `builder.rs:4036`, `RuntimeInner::new` mailbox bootstrap | Reads trace/timer handles and root pending credit, then installs the spawn gateway. | E + D + B | E -> D -> B | Extract E/D handles; read B once for the pending counter; install the gateway outside table guards. |
| B08 `builder.rs:4067`, `RuntimeInner::new` blocking-pool install | Stores an immutable blocking-pool handle. | E | E only | Extract into builder-owned/config handle storage before worker start. |
| B09 `builder.rs:4198`, `RuntimeInner::spawn` legacy fallback | Creates task infrastructure/future under one mutex. | E + D + B + A | E -> D -> B -> A | Convert with `ShardGuard::for_spawn`; snapshot E/D first, mutate B then A, and dispatch effects after release. |
| B10 `builder.rs:4230`, `RuntimeInner::spawn_with_cx` | Builds system Cx, admits the task, and stores its future. | E + D + B + A | E -> D -> B -> A | Convert with `ShardGuard::for_spawn`; factory construction and effect dispatch remain outside guards. |
| B11 `builder.rs:4290`, `RuntimeInner::drop` | Clones the spawn-gateway mailbox before shutdown. | E | E only | Extract the gateway handle; shutdown must not acquire table shards merely to clone it. |
| B12 `builder.rs:4415`, `current_runtime_has_live_tasks` | Reads the live-task counter. | A | A only | Convert to an A counter accessor. |
| B13 `builder.rs:4524`, `build_request_cx_from_inner` | Clones Cx driver/config/trace handles and the root pending-spawn counter. | E + D + B | E -> D -> B | Snapshot E/D lock-free and read B only for the region-owned pending counter. |

The mailbox branch of `RuntimeInner::spawn` has no unified-state acquisition:
it reserves the B-owned pending credit through an existing handle, enqueues,
and wakes the scheduler. E1.2 must preserve that lock-free producer shape.

## Local queue inventory: 1 acquisition

| ID and source anchor | Unified critical section | Shards | Required order | E1.2 conversion or verdict |
| --- | --- | --- | --- | --- |
| L01 `local_queue.rs:39`, `TaskSource::with_tasks_arena_mut` unified fallback | Mutates the task arena during local queue operations. | A | A only | Use the existing `TaskSource::TaskTable` branch for sharded construction; never take B or C from queue operations. |

## Legacy worker inventory: 9 acquisitions

| ID and source anchor | Unified critical section | Shards | Required order | E1.2 conversion or verdict |
| --- | --- | --- | --- | --- |
| W01 `worker.rs:174`, `Worker::new` | Clones IO, timer, trace, and metrics handles. | E + D | E -> D | Extract handles before constructing workers; no table guard is required. |
| W02 `worker.rs:334`, `TaskExecutionGuard::drop` | Panic completion, lifecycle retirement, finalizer drain, and waiter routing. | D + B + A + C | D -> B -> A -> C | Convert through the completion guard; copy wake/effect payloads and dispatch after release. |
| W03 `worker.rs:416`, `Worker::execute` poll detach/start | Removes the future and marks/reads its task record. | A | A only | Convert to A-only task-table access. |
| W04 `worker.rs:520`, `Worker::execute` panic-isolation owner lookup | Reads `TaskRecord::owner`. | A | A only | Read from A and release before polling. |
| W05 `worker.rs:546`, `Worker::execute` ready completion | Reconciles cancel ack, completes/retires task, drains finalizers, and routes waiters. | D + B + A + C | D -> B -> A -> C | Convert through the completion guard; poll outcome and callbacks stay outside guards. |
| W06 `worker.rs:659`, `Worker::execute` pending global task | Restores stored future, cached waker, and cancel acknowledgement. | A | A only | Convert to one A critical section. |
| W07 `worker.rs:673`, `Worker::execute` pending local task | Restores cached task metadata and cancel acknowledgement. | A | A only | Keep thread-local future storage lock-free; update only A metadata. |
| W08 `worker.rs:710`, `Worker::execute` isolated panic completion | Records panic completion, retires lifecycle state, drains finalizers, and routes waiters. | D + B + A + C | D -> B -> A -> C | Same completion-guard conversion as W05. |
| W09 `worker.rs:791`, `Worker::schedule_ready_finalizers` | Drains region-ready async finalizers into runnable tasks. | B + A | B -> A | Convert with a B/A lifecycle guard; publish scheduler lanes and effects after release. |

## Three-lane scheduler and worker inventory: 23 acquisitions

| ID and source anchor | Unified critical section | Shards | Required order | E1.2 conversion or verdict |
| --- | --- | --- | --- | --- |
| T01 `three_lane.rs:1669`, `ThreeLaneScheduler::new_with_options_and_task_table` | Clones IO and timer handles. | E + D | E -> D | Pass extracted handles into construction. |
| T02 `three_lane.rs:1692`, same constructor | Installs the pending-cancel coordinator and clones its readiness handle. | E | E only | Make this scheduler-owned control state; remove it from table backing. |
| T03 `three_lane.rs:2348`, `ThreeLaneScheduler::with_task_table_ref` fallback | Reads task wake/locality state. | A | A only | Route sharded construction through the existing direct `TaskTable` branch. |
| T04 `three_lane.rs:4080`, `ThreeLaneWorker::with_task_table` fallback | Mutates task records/futures on the poll path. | A | A only | Route to A directly. |
| T05 `three_lane.rs:4095`, `ThreeLaneWorker::with_task_table_ref` fallback | Reads task records on the poll path. | A | A only | Route to A directly. |
| T06 `three_lane.rs:4223`, `emit_scheduler_evidence_for_suggestion` | Builds a whole-state scheduler evidence snapshot. | D + B + A + C | D -> B -> A -> C | Use `ShardGuard::all`, copy the minimal snapshot, and emit after release. |
| T07 `three_lane.rs:4276`, `capture_adaptive_snapshot` | Builds the adaptive-policy whole-state snapshot. | D + B + A + C | D -> B -> A -> C | Same ordered snapshot conversion as T06. |
| T08 `three_lane.rs:4966`, `drain_handle_cancel_requests` external-table validation | Validates a copied task-handle cancellation after A mutation. | A | A only | Co-locate protocol validation with A or expose an A-owned validator handle; do not reacquire B/C. |
| T09 `three_lane.rs:4988`, `drain_handle_cancel_requests` unified fallback | Applies task-handle cancellation and captures deferred wakes. | A | A only | Convert task and protocol mutation to A; publish lanes and wakes after release. |
| T10 `three_lane.rs:5079`, delegated handle-cancel fallback | Transitions the task publication gate while inserting a scheduler lane. | A | A only | Use A for the authoritative record; retain callback-free queue publication and forbid B/C nesting. |
| T11 `three_lane.rs:5164`, `drain_deferred_cancel_dispatches` | Takes runtime-owned deferred task-cancel batches. | A | A only | Move the batch queue beside the scheduler/task backing; publish and dispatch after release. |
| T12 `three_lane.rs:5304`, `drain_spawn_admissions` | Batch-admits Send tasks, registers protocol state, creates Cx, and stores futures. | E + D + B + A | E -> D -> B -> A | Snapshot E/D, use `ShardGuard::for_spawn` for B/A, then publish lanes, denials, observers, and wakes after release. |
| T13 `three_lane.rs:5405`, `drain_local_spawn_admissions` | Batch-admits and pins local tasks, creates Cx, and updates task wake state. | E + D + B + A | E -> D -> B -> A | Same ordered spawn conversion; thread-local storage and callback work remain outside guards. |
| T14 `three_lane.rs:5970`, `governor_suggest` | Copies Lyapunov state and optional wait-graph inputs. | D + B + A + C | D -> B -> A -> C | Use an ordered minimal snapshot; keep BTree/Tarjan work after release as current code does. |
| T15 `three_lane.rs:6231`, `current_scheduler_time` fallback | Reads cached runtime time. | D | D only | Read a lock-free timer/time handle. |
| T16 `three_lane.rs:6806`, three-lane `TaskExecutionGuard::drop` | Panic completion, lifecycle retirement, finalizer drain, and waiter routing. | D + B + A + C | D -> B -> A -> C | Convert through the completion guard; retire detached records and dispatch effects after release. |
| T17 `three_lane.rs:7090`, ready completion with external task table | Validates detached A record, completes B/C lifecycle bookkeeping, drains finalizers, and routes waiters. | D + B + A + C | D -> B -> A -> C | Replace residual unified state with ordered lifecycle guards; never nest the already-released A guard. |
| T18 `three_lane.rs:7121`, ready completion unified fallback | Completes the task and all cross-cutting lifecycle bookkeeping. | D + B + A + C | D -> B -> A -> C | Convert through `ShardGuard::for_task_completed`. |
| T19 `three_lane.rs:7189`, pending-poll cancel-ack validation | Validates checkpoint cancellation after the A record/future is restored. | A | A only | Keep protocol validation in the A transaction or use an A-owned sidecar; dispatch diagnostics after release. |
| T20 `three_lane.rs:7297`, panic completion with external task table | Validates detached A record, completes B/C lifecycle bookkeeping, and drains finalizers. | D + B + A + C | D -> B -> A -> C | Same ordered external-record completion conversion as T17. |
| T21 `three_lane.rs:7328`, panic completion unified fallback | Completes the panicked task and all lifecycle bookkeeping. | D + B + A + C | D -> B -> A -> C | Convert through `ShardGuard::for_task_completed`. |
| T22 `three_lane.rs:7423`, `schedule_ready_finalizers` | Drains region-ready finalizer tasks. | B + A | B -> A | Convert with a B/A lifecycle guard; publish lanes/effects after release. |
| T23 `three_lane.rs:7451`, `consume_cancel_ack` validation | Validates a copied checkpoint cancellation receipt. | A | A only | Co-locate validation with A or use an A-owned sidecar; no B/C acquisition is needed. |

## Conversion seams and justified unified sites

`RuntimeStateBacking` already expresses the scheduler-facing operations.
`three_lane.rs` and `local_queue.rs` already accept an optional direct
`TaskTable`, which is the correct A-only hot-path shape. This interface is not
yet sufficient for B/A/C completion or B/A spawn operations; E1.2 must add
explicit ordered lifecycle/admission backing rather than hiding those
operations behind another whole-state lock.

Temporary justified-unified sites are limited to:

- B06, builder-time root initialization before worker threads start.
- B02, whole-runtime diagnostic reads, until an ordered sharded snapshot exists.
- B09, the legacy non-mailbox spawn fallback, only while unified mode remains
  selected and before sharded mode can be enabled.

All scheduler-worker acquisitions W02-W09 and T03-T23 require conversion before
the sharded shape is considered complete. Constructor handle reads W01/T01/T02
must be extracted so sharded workers do not retain a unified state object.

## E1.2 executable specification

1. Make scheduler construction accept the real `ShardedState` backing and
   extracted E/D handles; do not construct an unused unified state alongside it.
2. Route poll/remove/store, wake-state, locality, cancellation-record, and
   protocol-validation operations through A-only access.
3. Route spawn admission through E/D snapshots followed by
   `ShardGuard::for_spawn` (`B -> A`).
4. Route completion through `ShardGuard::for_task_completed`
   (`B -> A -> C`), including external-record completion, region advancement,
   obligation retirement, finalizer discovery, and waiter extraction.
5. Route finalizer drain through B/A and whole-state snapshots through
   `ShardGuard::all` (`B -> A -> C`).
6. Keep scheduler queues, task polling, user factories, observer callbacks,
   Waker dispatch, record destruction, and graph analysis outside table guards.
7. Extend lock-order label tests for every new B/A, B/C, or B/A/C call site and
   prove unified/sharded replay fingerprints are identical before performance
   claims.

## Review result

All 46 production unified-state acquisitions are accounted for and reviewed
against `E -> D -> B -> A -> C`. The dominant ordinary dispatch path can be
A-only; the remaining cross-shard work is concentrated in spawn, completion,
finalizer, and snapshot boundaries. The existing task-table option is a useful
seam, but E1.2 must replace the residual unified lifecycle object rather than
merely routing task lookups around it.
