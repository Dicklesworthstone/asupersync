# Scheduler hot-read inventory and replacement specification

<!-- BEGIN SCHEDULER HOT READ INVENTORY -->

Bead: `asupersync-sched-hot-path-perf-bt4y5f.4.1`

Machine artifact: `artifacts/scheduler_hot_read_inventory_v1.json`

Static contract: `tests/scheduler_hot_read_inventory_contract.rs`

## Disposition

The live scheduler does not have the uniform locked read described by
`benches/task_state_hot_reads.rs`. Its scalar phase snapshot, wake-dedup state,
and ordinary-waker cancellation publication state are already atomic. Rich `TaskState`,
cancellation reasons, cleanup priorities, stored futures, and record ownership
remain behind the task-table or `CxInner` lock that makes their lifetime and
payload coherent.

HOTREAD-1 freezes that boundary and specifies the production-shaped comparison
that HOTREAD-2 may implement after its scheduler-final-shape dependencies are
satisfied. It makes no production conversion and no performance claim. The
six existing `sched/task_state/` baseline rows remain byte-for-byte historical
evidence for their original synthetic workload; they are not a baseline for a
new operation ID.

## Ownership and lifetime model

| Surface | Authority | Lifetime and generation boundary | Synchronization and payload |
|---|---|---|---|
| Rich task lifecycle | `TaskRecord` while owned by `TaskTable` | A `TaskId` contains an arena slot and generation. `Arena::get` rejects a vacant or generation-mismatched slot. Removal advances the generation; generation exhaustion retires the slot. | `TaskState` is read and mutated while the owning task table or embedded runtime state is locked. It owns non-scalar outcome, reason, and cleanup-budget payloads. |
| Phase snapshot | `TaskRecord::phase: TaskPhaseCell` | The cell is part of the record and does not independently retain the record. A caller still needs a generation-valid record reference. | `AtomicU8`, Acquire load and Release store. It is a scalar lifecycle projection, not ownership for `TaskState`. |
| Wake dedup | `TaskRecord::wake_state: Arc<TaskWakeState>` | Wakers clone the `Arc` while the record is valid. Recycled records reset the cell in place only when uniquely owned; otherwise they receive a fresh `Arc`, so an old waker cannot notify a new generation. | `AtomicU8` state machine: `Idle`, `Polling`, `Notified`. Notify is Release; finish-poll failure is Acquire; begin-poll is under the record-owner lock. |
| Cancellation publication state | `CxInner::fast_cancel: Arc<AtomicBool>` (named `CxCancellationState` inside the scheduler) | Wakers retain the original stable `Arc` and only a `Weak<CxInner>` for rich state. The bit says cancellation may need routing; it does not own the reason. Direct replacement of the public compatibility field cannot retarget already-created wakers. | Writers call `CxInner::set_cancel_requested` under the write lock, which updates the lock-backed bit and publishes Release to both the stable scheduler handle and any replacement compatibility handle. `Cx::checkpoint` and ordinary wakers query Acquire. A waker that observes true reacquires the `CxInner` read lock before reading the reason. |
| Rich cancellation state | `CxInner::{cancel_requested,cancel_reason,cancel_wakers_pending}` | Lives with the `CxInner`; readers upgrade or retain the context before locking it. | `parking_lot::RwLock<CxInner>` keeps the flag, strongest reason, cleanup priority, publication gate, and waker registry coherent. |
| Stored future and queue ownership | `TaskTable` plus scheduler queues | Future removal, record mutation, reinsertion, completion, removal, and recycling all validate the same generation-bearing `TaskId`. | The selected task-table backing is locked. Queue publication additionally follows `TaskWakeState` and the cancel-lane promotion rules. |

The production builder can provide an external
`Arc<ContendedMutex<TaskTable>>`; otherwise scheduler helpers use the
`RuntimeState`-embedded table. `ThreeLaneScheduler::with_task_table_ref` and
`ThreeLaneWorker::with_task_table` are the authority-switching seams. A
comparator must exercise the selected final backing rather than construct an
unrelated `RuntimeState` solely to create lock contention.

## Live read inventory

The machine artifact records every direct production read anchor. The reader
classes are summarized here.

| Reader class | Exact live anchors | Expected frequency | Meaning |
|---|---|---|---|
| Phase accessor and bookkeeping | `TaskRecord::phase` at `src/record/task.rs:596`; `TaskTable::{count_in_phase,insert,remove,insert_task_with,insert_pooled_task_with,update_task,live_task_count}` at `src/runtime/task_table.rs:301,329,343,456,485,517,615` | lifecycle bookkeeping or whole-table telemetry; `update_task` brackets each mutation | Scalar phase only. Every in-tree caller already holds a valid record/table reference. |
| Rich task state | `Worker::execute_task` at `src/runtime/scheduler/worker.rs:391,607,770`; `ThreeLaneWorker::{execute_task,complete_polled_record}` at `src/runtime/scheduler/three_lane.rs:7553,7886`; `TaskSnapshot::from_record` at `src/runtime/state.rs:8884` | poll completion/unwind or cold snapshot | Non-scalar lifecycle and outcome semantics under the record owner lock. |
| Public cancellation query | `Cx::is_cancel_requested` at `src/cx/cx.rs:2140` | caller-selected | Reads the restored 0.4.3 `cancel_requested` flag under the `CxInner` read lock with its original semantics; it does not clone the rich cancellation reason. Standard runtime publication still uses the stable envelope. |
| Checkpoint publication query | `Cx::checkpoint` at `src/cx/cx.rs:2205` | cooperative progress checkpoint | Acquire-queries the stable cancellation envelope while holding a `CxInner` read guard; cancellation and budget handling then use the locked slow path. |
| Ordinary global wake | `ThreeLaneWaker::schedule` at `src/runtime/scheduler/three_lane.rs:7951` | every ordinary global wake that wins dedup | `TaskWakeState::notify`, then Acquire-query the stable cancellation envelope; a true result triggers a locked reason/priority read. |
| Ordinary local wake | `ThreeLaneLocalWaker::schedule` at `src/runtime/scheduler/three_lane.rs:8014` | every ordinary local wake that wins dedup | Same stable-envelope query, followed by locked reason/priority lookup before local cancel-lane promotion. |
| Reason-bearing global cancel wake | `CancelLaneWaker::schedule` at `src/runtime/scheduler/three_lane.rs:8075` | cancellation wake | Reads `cancel_requested` and reason-derived cleanup priority together under the `CxInner` read lock, then promotes unconditionally. |
| Reason-bearing local cancel wake | `ThreeLaneLocalCancelWaker::schedule` at `src/runtime/scheduler/three_lane.rs:8134` | local cancellation wake | Same coherent locked payload read, then local cancel-lane promotion. |

`TaskPhaseCell` has nine direct in-tree production load positions: the accessor,
the whole-table count, insert bookkeeping, remove bookkeeping, closure-based
insert bookkeeping, pooled closure-based insert bookkeeping, the before and
after sides of `update_task`, and `live_task_count`. There is no production
poll-loop call equivalent to the benchmark's repeated
`state_name() + state.is_cancelling()` pair.

## Writer and publication order

`TaskRecord` lifecycle methods are the phase writers:
`request_cancel_with_budget_and_publication`, `start_running`,
`reconcile_checkpoint_cancel`, `complete`, `acknowledge_cancel`, `cleanup_done`,
and `finalize_done_with_witness`. Their rich-state mutation and Release phase
store occur while a caller owns the record mutably.

The direct cancellation-publication writer set is pinned in the artifact. It includes
task-record cancellation, task-handle cancellation, checkpoint budget
exhaustion, the explicit `Cx` cancellation APIs, actor/server aborts, and the
deterministic lab quota path. Each writer runs under the `CxInner` write lock.
The required interpretation is:

1. lock `CxInner` for writing;
2. set `cancel_requested` and any producer-specific fields ordered before the
   scalar hint;
3. call `set_cancel_requested`, which publishes the matching requested bit with Release;
4. finish the reason, cleanup-budget, and pending-waker mutation under the same
   write guard (individual producers may have completed some of these fields
   before step 3);
5. unlock `CxInner`;
6. snapshot, publish, dispatch, or retire waker effects only at the owning
   scheduler boundary and outside locks where the API requires it.

Some live writers store the hint before the final reason assignment while the
write guard is still held. An ordinary waker therefore must not treat the
Acquire load as ownership of the reason: it must acquire the `CxInner` read
lock, which cannot succeed until the writer releases the coherent state.

Wake publication has two different policies:

- ready and timed publication is gated by `TaskWakeState::notify()` so duplicate
  notifications coalesce;
- cancellation publication calls `notify()` for poll coordination but promotes
  to the cancel lane even when the task was already notified in a lower lane.

The machine artifact pins admission, finalizer, injection, local scheduling,
dependent-wake, poll begin/finish, ordinary-waker, cancel-waker, and legacy
worker call sites. A replacement comparator must retain this distinction; a
single atomic swap loop is not an equivalent scheduler workload.

## Why the incumbent rows are historical

`benches/task_state_hot_reads.rs` owns three operation IDs on two host families:

- `sched/task_state/locked_read_cycle`;
- `sched/task_state/locked_read_contended/4`;
- `sched/task_state/locked_read_contended/8`.

The six rows remain valid observations of that binary at their recorded source
revisions and hosts. They are not representative of the live scheduler because
the binary:

1. builds a synthetic `RuntimeState` even when production uses an external
   task-table shard;
2. takes the broad runtime-state lock for every read;
3. reads rich `TaskState` through `state_name()` and `is_cancelling()` even
though ordinary production wakers use `TaskWakeState` plus the stable
cancellation publication envelope;
4. never runs queue publication, cancel-lane promotion, reason-priority lookup,
   stored-future ownership, generation mismatch, removal, or recycling;
5. uses fresh records that never enter cancellation, so its asserted semantic
   result is always zero;
6. measures 256 synthetic reads rather than one named production operation.

No HOTREAD owner may rewrite or relabel those rows under their existing IDs.
They remain under `sched/task_state/` with
`evidence_class=HISTORICAL_NON_EQUIVALENT` in this inventory. New measurements
must use the `sched/hotread/v2/` namespace.

## Replacement comparator contract

HOTREAD-2 may implement these exact operation IDs after the final-shape
dependencies are satisfied. The machine artifact owns their outcome-checksum
fields and full comparator rules.

| Operation ID | Production path | Required semantic result |
|---|---|---|
| `sched/hotread/v2/task_table_lookup/rich_state` | generation-valid selected task-table lookup and rich-state read | observed rich state matches the seeded record |
| `sched/hotread/v2/task_table_lookup/phase` | generation-valid selected task-table lookup and phase-cell read | observed phase matches the seeded record |
| `sched/hotread/v2/task_table_lookup/stale_generation_miss` | stale generation lookup against an occupied slot | lookup misses without observing the replacement record |
| `sched/hotread/v2/phase_scan/mixed_1024` | selected task-table backing, 1,024 generation-valid live records, `live_task_count` plus per-phase scan | counts equal the seeded mixed phase distribution |
| `sched/hotread/v2/poll_cycle/global` | remove stored future, `update_task`, begin poll, pending reinsertion, finish poll | one generation-valid global task remains owned and runnable |
| `sched/hotread/v2/poll_cycle/local` | local stored-future seam plus task-table record mutation and finish poll | task remains pinned and never enters a stealable structure |
| `sched/hotread/v2/inject_ready/global_idle` | global ready admission from an idle wake state | one ready publication is admitted |
| `sched/hotread/v2/inject_ready/global_dedup` | duplicate global ready admission | duplicate publication is coalesced |
| `sched/hotread/v2/inject_timed/global_idle` | timed publication from an idle wake state | one timer publication is admitted |
| `sched/hotread/v2/inject_cancel/global_promotion` | cancellation publication for already-notified and idle cases | cancel-lane promotion is retained in both cases |
| `sched/hotread/v2/waker/ordinary_global_healthy` | ordinary global waker, healthy cancellation hint | exactly one effective ready publication per dedup epoch |
| `sched/hotread/v2/waker/ordinary_global_cancelled` | ordinary global waker, true hint plus locked reason lookup | publication routes to the global cancel lane with the coherent priority |
| `sched/hotread/v2/waker/ordinary_local_healthy` | ordinary local waker, healthy cancellation hint | exactly one local ready publication without a stealable transition |
| `sched/hotread/v2/waker/ordinary_local_cancelled` | ordinary local waker, true hint plus locked reason lookup | publication routes locally to cancel while preserving pinning |
| `sched/hotread/v2/waker/cancel_global_reason` | reason-bearing global cancel waker | strongest reason priority is published even if already ready or timed |
| `sched/hotread/v2/waker/cancel_local_reason` | reason-bearing local cancel waker | strongest reason priority and local pinning are preserved |
| `sched/hotread/v2/checkpoint/healthy` | healthy checkpoint hint and initialization paths | checkpoint outcome and remaining budget match the incumbent |
| `sched/hotread/v2/checkpoint/cancel_requested` | true hint plus coherent checkpoint slow path | cancellation outcome, reason, and budget match the incumbent |
| `sched/hotread/v2/recycle_generation/1024` | remove, recycle, reuse, stale-ID lookup, old-waker notification | stale IDs miss and old `Arc<TaskWakeState>` cannot notify the new record |

Every operation has an incumbent cell and a candidate cell in the same process.
The incumbent means the exact current production path at the captured source
revision, not the old benchmark. A candidate is eligible only after HOTREAD-2
profiles that exact site and records `GO`; `NO_GO` is a valid result.

### Profile corpus

| Profile ID | Inputs |
|---|---|
| `steady_healthy_r1` | 1,024 running tasks, 256 measured operations, one reader, no writers |
| `steady_healthy_r4` | same steady corpus with four readers |
| `steady_healthy_r8` | same steady corpus with eight readers |
| `cancel_transition_r4_w1` | four readers, one writer, 65,536 operations, deterministic reason-strengthening transitions every 64 reads |
| `wake_idle` | 65,536 attempts beginning at `Idle`, 90:10 global/local split, healthy and cancelled cells |
| `wake_dedup` | same wake corpus beginning at `Notified`, covering ordinary coalescing and unconditional cancel promotion |
| `lifecycle_churn_6p25` | 1,024 slots, 4,096 deterministic remove/recycle/reinsert operations, equal current/stale generation lookup ratios, retained old wake-state arcs |
| `mixed_phase_scan` | 1,024 records distributed across running, cancellation, finalization, and completed phases |
| `mixed_poll` | 65,536 poll cycles with 70% pending, 20% ready, 10% cancellation acknowledgement and a 90:10 global/local split |
| `checkpoint_healthy` | 65,536 healthy checkpoints with fixed budget, mask depth, and initialization inputs |
| `checkpoint_cancelled` | 65,536 cancelled checkpoints with fixed budget, mask depth, reason, and initialization inputs |

Each cell records fixed work counts, state distribution, producer/worker counts,
global/local ratio, cancellation ratio, starting lane, priority corpus, table
backing, pool limit, and deterministic corpus revision. Setup, thread creation,
and teardown are outside the timed region unless the operation ID explicitly
names them.

### Host and run identity

Every observation records: operation ID, profile ID, comparator role, source
revision, dirty-overlay digest, target triple, toolchain string, build profile,
feature set, process ID, run timestamp, sample count, repetition index,
`environment=host:<hostname>`, RCH worker label when applicable, OS, kernel,
architecture, CPU model, sockets, physical cores, logical CPUs, threads per
core, NUMA nodes, total memory, allocator, and timer source. Missing identity
fails the observation closed; it is never borrowed from a sibling row.

### Migration rules

1. Preserve all current `sched/task_state/` rows and their values.
2. Add only `sched/hotread/v2/` observations; never overwrite an old operation
   with a new semantic path.
3. Keep row identity `(operation, environment)` and compare only matching host
   identities.
4. Record at least three back-to-back incumbent/candidate repetitions in the
   same process and retain spread plus interval fields.
5. Do not create a gate row until the comparator exercises the same ownership,
   generation, reason, wake, and queue-publication semantics.
6. Do not promote a micro-result into a scheduler claim. Site-specific `GO` or
   `NO_GO` is the only HOTREAD-2 output.
7. Do not edit a peer-owned baseline family without a fresh exact-path
   reservation and explicit handoff.

## Repository ecosystem scan

The static scan covers root and workspace Cargo manifests, `Cargo.lock`, live
source, benchmarks, artifacts, plans, and performance documentation. It found:

- the existing `AtomicU8`, `AtomicBool`, `parking_lot::RwLock`, and
  `ContendedMutex` implementations described above;
- no direct `seqlock`, `seqcount`, BRAVO, left-right, or `arc-swap` dependency;
- a transitive `crossbeam-epoch` lockfile entry and an internal epoch-tracking
  implementation, neither of which owns `TaskRecord` lifetime;
- one planning document that mentions left-right state replication but no live
  implementation; and
- the old task-state benchmark's aspirational seqlock/BRAVO wording.

The dispositions are:

- existing scalar atomics: `KEEP_INCUMBENT`; they already serve their exact
  payloads;
- rich task state and cancellation reason under their locks:
  `KEEP_PENDING_PROFILE`; ownership and coherence dominate the raw scalar read;
- BRAVO-style reader bias: `NOT_APPLICABLE_WITHOUT_PROFILED_READ_BIASED_LOCK`;
  it is not applicable to a single atomic flag;
- left-right, RCU, epoch reclamation, or copied snapshots:
  `REJECT_FOR_THIS_LANE`; they duplicate non-scalar state and do not remove the
  generation-valid record-retention requirement; and
- a torn non-atomic seqlock: `REJECT_UNCONDITIONALLY`. Version counters around
  concurrent plain reads and writes do not make those accesses valid Rust, and
  `TaskState` contains non-copy payloads. No unsafe read, bespoke seqlock, or
  lock-free record-lifetime scheme is authorized.

## Validation and no-claim boundary

This lane used static source anchors, Git history, source hashes, baseline JSON
inspection, and the authored contract. The contract is intentionally recorded
as not executed in this lane. No compiler, test, benchmark, profiler, or remote worker was invoked.

This inventory does not prove compilation, runtime correctness, wake
correctness, cancellation correctness, deterministic replay, performance,
regression freedom, final scheduler shape, live host availability, or broad
workspace health. It authorizes no production conversion, dependency change,
unsafe code, baseline rewrite, default flip, or performance claim.

<!-- END SCHEDULER HOT READ INVENTORY -->
