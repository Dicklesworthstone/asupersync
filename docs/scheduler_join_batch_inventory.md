# Scheduler join-completion and structured batch inventory

<!-- BEGIN SCHEDULER JOIN BATCH INVENTORY -->

Bead: `asupersync-sched-hot-path-perf-bt4y5f.3.1`

Machine artifact: `artifacts/scheduler_join_batch_inventory_v1.json`

Static contract: `tests/scheduler_join_batch_inventory_contract.rs`

## Disposition

The current source map is frozen, but the measurement gate is not satisfied.
The baseline registry contains zero rows for isolated legacy completion,
isolated structured completion, or the public `Cx` N=1000 spawn loop. This
packet therefore records
`STATIC_SURFACE_COMPLETE_MEASUREMENT_BLOCKED`; it does not close the bead or
authorize a production change.

### Post-capture provenance refresh (2026-08-06)

`SCHED-JOIN-BATCH-PROVENANCE-REFRESH-2026-08-06` joins the historical capture
at `e9a2d6229fd42d982f9bc296129852b7821c0905` to a static refresh at
`fbbd4d065ae4768b84e4161a00d10e5acba04b39`. Exactly two of the 15 source
pins had changed, while all 76 exact anchors still matched:

- `src/runtime/scheduler/three_lane.rs` changed at
  `b213fc7ba7966e3a8522d9d23fc0e57037613e2a` to promote timed tasks during a
  real ready injection. Its four JOIN-BATCH anchors still pin the global
  batch-one and owner-local batch-sixteen spawn-admission policies.
- `src/runtime/state.rs` changed at
  `6688f15be0acb724b264dd6ca6051201fe0e7f06` to drain deferred regions before
  an obligation-leak panic. That cleanup is after all three pinned admission
  anchors and changes none of their identity, quota, rollback, or successor
  publication contracts.

The refresh updates those two hashes and the `state.rs` line count. It changes
no source-pin path, semantic row, production or benchmark source, baseline
registry row, measurement state, candidate, threshold, or disposition. The
Rust contract was not executed, and the missing p50, p95, allocation,
repetition, and admitted two-host observations still keep the bead open.

The two completion families are intentionally separate:

- `RuntimeHandle::spawn` returns the legacy
  `runtime::builder::JoinHandle<T>`. It stores completion in
  `Arc<parking_lot::Mutex<JoinState<T>>>` and exposes `Future<Output = T>`.
- `Cx::spawn`, `Cx::spawn_in`, and `Scope::spawn_registered` return the
  canonical `runtime::TaskHandle<T>`. Its result travels through the project
  oneshot channel and is collected as `Result<T, JoinError>`.

The oneshot channel is itself backed by
`Arc<parking_lot::Mutex<OneShotInner<T>>>`. Gateway-based structured spawn also
uses an `Arc<std::sync::Mutex<Option<Sender>>>` to let completion and denial
paths claim the sender exactly once. Reusing oneshot for the legacy handle is a
safe semantic experiment, not a lock-free or performance claim.

## Current completion semantics

### Legacy RuntimeHandle JoinHandle

| Event | Incumbent observable behavior |
|---|---|
| synchronous spawn failure | `try_spawn` returns `SpawnError`; `spawn` panics through `expect` |
| success | `complete_task` stores one value, takes the registered waker, unlocks, and wakes; polling takes the value once |
| pending poll | one equivalent waker is retained or replaced under the completion mutex |
| task panic | the task panic payload is caught for worker isolation, stored, and resumed in the awaiter |
| cancellation or denial after mailbox publication | the unadmitted callback resolves the handle with a payload that becomes an awaiter panic, not a typed cancellation |
| shutdown or executor-side disappearance | pending mailbox work is resolved during drain; a result-less handle whose executor-side `Arc` disappeared reports finished and panics when polled |
| handle drop | no `Drop` implementation requests cancellation; dropping the observer leaves the runtime-owned task running |
| `is_finished` | true after local terminal consumption, while a result is stored, or after executor-side state disappears |
| terminal repoll | assertion panic |

Any safe transport experiment in `.3.2` targets this family first and must
preserve its public panic-versus-error boundary. Converting it to canonical
`JoinError` semantics would be an API change, not an isomorphic transport
replacement.

### Canonical Cx TaskHandle

| Event | Incumbent observable behavior |
|---|---|
| synchronous gateway/setup failure | `Cx::spawn` and `Cx::spawn_in` return `SpawnError::RuntimeUnavailable`; no handle is returned |
| success | the sender commits `Ok(value)`; `join`, `try_join`, or `poll_join` consumes one result |
| pending `join` | the temporary uninterruptible receive future owns its waiter and retires it on drop |
| pending `poll_join` | the receiver owns a persistent waiter so a JoinSet scan remains wakeable across polls |
| task panic | `JoinError::Panicked(PanicPayload)` |
| cancellation, later admission denial, or closed result channel | `JoinError::Cancelled` with the strongest available reason |
| explicit abort | requests and strengthens cancellation; it does not promise immediate task termination |
| `JoinFuture` drop | requests abort unless the result is already terminal or internal control flow defused the drop action |
| `TaskHandle` drop | no handle-level `Drop` implementation; the region still owns the task |
| terminal repoll | `JoinError::PolledAfterCompletion` |

`Scope::join_all` and `JoinSet::join_all` preserve input or spawn order.
`JoinSet::join_next` preserves completion order and uses the earliest-spawned
ready member as the deterministic tie-break. `JoinSet::drop` requests
cancellation for every member it still owns; `cancel_all` requests
cancellation and then drains every outcome.

## Current spawn producer and consumer boundary

There is no `Cx::spawn_batch`, `Cx::spawn_batch_in`, `Scope::spawn_batch`, or
`JoinSet::spawn_all` implementation in the captured tree. `JoinSet::spawn`
calls `Cx::spawn_in` once and pushes one `TaskHandle`.

The production ambient-free entry to this structured family is
`Runtime::request_cx_with_budget`. The public-loop baseline must construct its
`Runtime` and obtain one request-scoped `Cx` before the timed interval. This
changes setup reachability, not completion semantics, and records no timing
result.

Each current Send spawn performs all of the following independently:

1. allocate one provisional mailbox `TaskId`;
2. reserve one region pending-spawn credit before publication;
3. create one `SpawnRequest` with its own completion and admission slots;
4. record one enqueue trace event before queue visibility;
5. enqueue one request; and
6. notify the scheduler once.

Admission maps each provisional identity to a canonical arena identity. It
checks region liveness, creates one task record, applies one quota decision,
links one child `Cx`, stores one future, publishes one runnable task, and
releases that request's pending credit only after successor visibility. A
denied request retains its completion slots and credit until it is explicitly
resolved outside the runtime lock.

The global scheduler consumer deliberately dequeues at most one Send request
per `ThreeLaneWorker::next_task` selection. The owner-local lane has a separate
bound of sixteen. Those constants are fairness boundaries. A later producer
optimization may enqueue N independent requests and issue one final
notification, but it may not describe that as one queue operation or silently
change either consumer bound.

## Structured batch contract handed to BATCH-1

Bead `.3.4` owns the exact API design. This inventory freezes these minimum
requirements:

1. Prefer `Cx::spawn_batch` and `Cx::spawn_batch_in`, with
   `JoinSet::spawn_all`, over a new unstructured `RuntimeHandle` batch API.
2. Preserve deterministic input order and one task identity, pending credit,
   enqueue trace, handle, and admission outcome per member.
3. Distinguish a batch-wide failure before any publication from later
   per-member admission denial. Every accepted member must be admitted or
   explicitly resolved.
4. Define empty input as a successful no-op with no enqueue and no
   notification.
5. Specify a bounded maximum, boundary behavior, ownership on partial
   construction, cancellation, and local-versus-Send variants before
   implementation.
6. Retain the single-spawn loop as the normative fallback and rollback path.
7. Do not change scheduler consumer batching, add unsafe code, add a
   compatibility shim, or make a performance claim in the API-contract bead.

## Existing evidence is non-equivalent

`benches/spawn_throughput.rs` is the required harness to extend. Its current
groups are useful historical surfaces but do not satisfy this bead:

| Current group | What it actually measures | Why it is not the required baseline |
|---|---|---|
| `join_handle_completion/spawn_then_await_all/{direct,mailbox}` | 1,000 legacy `RuntimeHandle::spawn` calls, task execution, and ordered await | completion transport is not isolated |
| `join_set_fanout/join_all/1000` | 1,000 structured member spawns, execution, handle storage, and collection | canonical TaskHandle transport is not isolated |
| `join_set_fanout/join_next/1000` | the same fan-out plus completion-order scans | includes JoinSet scanning policy |
| `spawn_throughput/*` | task submission, latches, scheduler progress, task bodies, and completion observation | not the future public `Cx` batch-versus-loop shape |

The module comment currently calls the first group's collected values
`TaskHandle`, but `join_handle_completion_batch` obtains
`Runtime::current_handle()` and calls `RuntimeHandle::spawn`; its values are
the legacy builder `JoinHandle`. This inventory follows the executed source
path. The wording is left unchanged in this static slice.

The baseline registry has 105 total rows and twelve
`methodology/task_spawn/` rows across `host:fixmydocuments` and
`host:hetzner2`. The two
`methodology/task_spawn/local_queue_spawn_batch/1000` rows report p50 values
of 50,072 ns and 53,604 ns respectively, but both have null p95, neither has
allocation evidence, and the source benchmark only pushes synthetic `TaskId`
values through `LocalQueue`. Those rows never call `RuntimeHandle`, `Cx`, the
spawn gateway, admission, pending-spawn accounting, or completion handling.
They remain historical, non-equivalent evidence and must not be relabeled.

There are zero baseline-registry rows whose operation names cover
`join_handle_completion`, `join_set_fanout`, `spawn_throughput`, or the new
`sched/join_batch/v1/` namespace.

## Required measurement matrix

The existing `spawn_throughput` binary must gain separate cells under
`sched/join_batch/v1/`. At minimum:

| Operation | Timed boundary |
|---|---|
| `sched/join_batch/v1/legacy_completion_handoff/ready` | publish and consume a pre-created successful legacy completion |
| `sched/join_batch/v1/legacy_completion_handoff/pending_wake` | registered pending poll through publication and wake observation |
| `sched/join_batch/v1/legacy_completion_handoff/drop_observer` | observer drop with executor ownership retained, both pending and ready |
| `sched/join_batch/v1/task_handle_completion/ready` | publish and consume a pre-created canonical result through `join`, `try_join`, and `poll_join` profiles |
| `sched/join_batch/v1/task_handle_completion/pending_wake` | temporary and persistent waiter profiles through send and wake |
| `sched/join_batch/v1/task_handle_completion/drop_join_future` | unfinished, already-ready, and defused drop profiles |
| `sched/join_batch/v1/public_cx_spawn_loop/1000` | pre-create one production request-scoped `Cx` through `Runtime::request_cx_with_budget` outside the timer, then make exactly 1,000 public `Cx::spawn` calls; submission and collection are separate profiles |
| `sched/join_batch/v1/public_join_set_spawn_loop/1000` | exactly 1,000 `JoinSet::spawn` calls and spawn-order collection |

The later candidate uses
`sched/join_batch/v1/public_cx_spawn_batch/1000`; it does not exist yet and is
not an incumbent baseline.

Every required incumbent operation needs at least three retained repetitions
on each of at least two admitted host families. Each observation records p50,
p95, allocation count, allocated bytes, allocation method, exact work count,
profile and comparator role, worker and producer counts, admission mode,
state shape, source revision, overlay digest, harness hash, toolchain, target,
build profile, feature set, host and worker identities, OS and kernel, CPU and
core topology, NUMA, memory, allocator, timer source, and run timestamp.

Completion cells pre-create their transport and payload so task creation,
scheduling, body execution, runtime construction, thread creation, and
teardown stay outside the timed interval. Public-loop submission and
submission-plus-collection are distinct profiles and are never averaged
together. Comparisons are same-host, same-source, same-harness, same-feature,
and same-profile only.

## Candidate, no-win, and rollback policy

The JOIN candidate is limited to the legacy completion transport. The first
experiment may reuse the existing oneshot behavior, while retaining the
legacy handle's public panic semantics. The canonical TaskHandle and gateway
sender slot are also mutex-backed and are measured as separate incumbent
comparators, not assumed speedups.

The BATCH candidate is limited to structured producer publication. Its first
shape is one validated request and one queue publication per member with only
the scheduler notification amortized where the `.3.4` failure contract makes
that atomic at the API level.

A candidate is eligible to ship only when all mapped semantics have focused
lifecycle evidence, paired same-host p50 improves by at least 5% on every
required target cell, p95 does not regress by more than 5%, allocation count
and bytes do not increase, and at least three repetitions on each of two host
families agree in direction.

Any missing field, semantic drift, sub-5% p50 result, over-5% p95 regression,
allocation increase, host disagreement, unstable repeated-run spread, need
for unsafe code, or need for a consumer fairness change yields `KEEP` or an
explicit no-win result. The production source returns to the exact incumbent
behavior, the comparator cells and receipt remain, and incumbent baseline
values are not rewritten. JOIN and BATCH receive independent decisions.

## Validation and no-claim boundary

This slice used source inspection, Git history, hashes, exact anchors, and
baseline JSON inspection. The Rust contract is authored but intentionally not
executed. No compiler, formatter, test, benchmark, runtime process, or remote
worker was invoked.

This packet does not prove compilation, runtime correctness, completion or
wake correctness, cancellation correctness, p50, p95, allocations,
throughput, performance improvement, regression freedom, scheduler consumer
fairness, release readiness, or broad workspace health. It changes no
production or benchmark behavior, authorizes no unsafe code, and leaves the
bead open until the missing measurements exist.

<!-- END SCHEDULER JOIN BATCH INVENTORY -->
