# Runtime dynamic supervision

`Cx::open_dynamic_supervisor` opens a bounded, region-owned collection of named
supervised workers or whole managed supervisor trees. Existing workers keep
running while the single owner admits or terminates another name. This is an
additive execution surface for the dynamic-supervision goal; it does not mutate
the existing fixed-topology APIs or declare full OTP dynamic-topology parity.

## Admit real worker factories

A worker factory receives its actual registered `Cx` and `ManagedGeneration`.
The existing managed controller invokes it again after a restartable termination,
using a new task and region, only after the old generation has drained.

```rust,ignore
use asupersync::cx::{DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::supervision::{
    BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig,
};
use asupersync::{Cx, Outcome};
use std::time::Duration;

// Inside a runtime-owned task supplied with its real `cx`:
let mut workers = cx
    .open_dynamic_supervisor::<String>(DynamicSupervisorConfig::new(32))
    .await?;
let policy = DynamicWorkerConfig::new(
    ManagedRestartMode::Transient,
    SupervisionConfig::new(3, Duration::from_secs(60))
        .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(100))),
);
let job = workers.start_worker("indexer", policy, |cx: Cx, generation: ManagedGeneration| {
    async move {
        // Perform real work with this generation's capability context.
        match cx.checkpoint() {
            Ok(()) => Outcome::Ok(()),
            Err(_) => Outcome::Cancelled(cx.cancel_reason().unwrap()),
        }
    }
}).await?;

let completion = workers.wait_child(&job).await?;
// Inspect completion.supervisor AND completion.close: task, domain and cleanup
// outcomes are separate, and a successful wait is not application success.
let shutdown = workers.shutdown().await;
// Inspect shutdown.close and each retained child's outcome before promotion.
```

For a multi-worker topology, compile/bind a normal `ManagedSupervisor` and pass
it to `start_child(name, managed)`. Each dynamic entry retains that topology's
restart strategy, intensity, backoff, budgets and escalation behavior. There is
no cross-entry one-for-all or rest-for-one restart policy. The direct worker
configuration can narrow its controller budget and set its generation shutdown
budget; neither setting relaxes the enclosing capability or scheduler budget.

A start receipt means boundary admission and controller submission, **not worker
readiness**. A factory might not have run yet, and asynchronous task-admission
failure is still possible. Use an application readiness channel or the
initialization-aware interface below, and inspect the actual terminal report.
There is no successful dummy task or global registration.

## Initialization-aware worker readiness

This new surface is temporarily gated by `test-internals` for explicit validation
and is not compiled in default builds, including default lib tests. It has not
been compiled or executed in the authoring environment. Enabling the existing
internal-testing feature is not production approval; promotion requires the
native validation below. Existing supervision APIs remain enabled as before.

`start_initialized_worker(name, policy, initialize, run)` uses the same admission
and managed generation controller as `start_worker`. It returns the exact child
ID plus a `WorkerReadiness` view from `asupersync::cx::worker_readiness`. Keep the
child ID for stop/reap and await the view separately for startup ordering:

```rust,ignore
let (child, readiness) = workers.start_initialized_worker(
    "indexer", policy,
    |cx, generation| async move {
        // Application-owned initialization: load the index, bind the listener,
        // complete the upstream handshake, etc. Return its owned state.
        initialize_indexer(cx, generation).await
    },
    |cx, generation, indexer| async move {
        // Receives the exact non-Clone state produced by this generation.
        run_indexer(cx, generation, indexer).await
    },
).await?;

let first = readiness.wait_ready(&cx).await?;
// Only now submit work that depends on completed indexer initialization.
// This observation is not a lease: calls still need normal failure handling.

// To observe a later replacement rather than rediscover generation one:
let replacement = readiness.wait_ready_after(&cx, &first).await?;
assert!(replacement.generation().number > first.generation().number);
let completion = workers.terminate_child(&child).await?;
// Inspect completion.supervisor AND completion.close as usual.
```

The example's initializer/run functions are application code. The generic
`initialized_worker(initialize, run)` factory adapter is also accepted by existing
managed bindings and supervisor-mailbox worker submissions. Use one adapter per
managed child: the same instance is not an initializer for unrelated children.
No second executor, controller task, hidden region or process-wide registry is
created by the adapter.

Initialization runs at most once per generation. Each initialized replacement
uses its own freshly returned state. Successful initialization
hands its state to the run factory before publishing Ready. State and application
errors need Send, not Clone or Sync. Initialization errors return unchanged to
the managed controller and never invoke run; the controller's restart mode,
intensity, backoff and escalation policy remain authoritative.

Readiness is withdrawn when cancellation is observed while polling, and when
the body retires, including unwinding. The adapter registers a cancellation
waker but does not acknowledge cancellation on behalf of a blind user future.
If a cooperative initializer returns state after cancellation, run still
receives it for cleanup, but that generation does not become Ready. Initialization
and run own their partial-resource and panic cleanup; use resource scopes where
asynchronous cleanup is required. This is not an asynchronous destructor.

`ReadyWorker` observations carry the complete ManagedGeneration (number, task
and region) and an opaque factory identity. `is_current` checks the latest
observation. A previous generation cannot satisfy `wait_ready_after`, and an
observation from a different adapter returns ForeignObservation rather than
following a reused name. An overlapping invocation, zero/non-increasing number,
or mismatched task/region identity invalidates the view instead of reporting
successful startup.

`try_ready()` performs a passive snapshot with no waiter or Cx registration.
`wait_ready` and `wait_ready_after` are cancel-aware borrowing waits. Dropping a
wait or cancelling its observer unregisters that observer, not the worker, its
initializer, or any other observer. A fresh task context can resume observation.
Factory retirement wakes remaining observers with Closed after no active body
remains. Actual application errors stay in the ordinary child completion report.

The view stores only latest metadata, not every restart transition or application
payload. Short-lived Ready phases may be missed. Retired means body retirement,
and Closed means factory/body ownership ended; neither proves descendant drain.
The existing managed controller, not readiness metadata, prevents restart before
old-generation descendants/finalizers finish. `wait_child`, `terminate_child`
and region close retain their normal quiescence responsibilities.

Readiness is not continuous health, a resource lease, a readiness deadline,
automatic dependent-worker restart, or an OTP dependency graph. An initializer
which never progresses can leave observers waiting; bound that wait using the
observer's own context/deadline, then explicitly stop and reap through the owner
when required. A deadline on an observer does not cancel the service implicitly.

### Focused readiness validation

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_worker_readiness \
  cargo test -p asupersync --features test-internals --lib cx::worker_readiness::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_worker_readiness \
  cargo test -p asupersync --features test-internals --test worker_readiness_native
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_native_parked_task_cancellation \
  cargo test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -- --nocapture
```

The readiness increment includes sixteen unit/lab tests and six native tests.
Native current-thread/two-worker journeys withhold a real TCP handshake response
until a socket read is witnessed Pending; cancel an independently parked observer
without stopping initialization; hold old-generation descendant cleanup before
allowing restart; and retain an acquired socket through acknowledged startup
cancellation until run receives and releases it. They end with actual controller
and enclosing-region closure, not a metadata-only completion assertion.

Bead N/A for this increment: the oversized tracker export returned empty content
through the available connector. No tracker closure is claimed. The focused RCH
commands could not execute because RCH, Rust/Cargo, rustfmt and UBS are unavailable
in this editing environment. These tests are authored, NOT compiled or run; source
review and matching Git blob hashes are not native correctness or release proof.

## Lifecycle and identity

Every admission has a `DynamicChildId` containing the owner region, enclosing
child region and a monotone admission sequence. All control operations require
that exact ID, not just a name. Reusing a name after a clean reap cannot let a
stale handle cancel its replacement. Region IDs retain their arena generations.

`children()` reports reserved names in deterministic lexical order without
polling or consuming results. `wait_child` joins one controller and closes its
boundary. `next_completed` finds a completed entry with lexical ready tie-breaks.
`request_stop` only publishes cancellation; `terminate_child` also waits for the
real controller and enclosing region to finish.

`terminate_children(&ids)` first validates **every** ID and rejects duplicates,
without stopping any child on an invalid request. It then stops every selected
controller before waiting and drives all selected closes together. Results follow
input order; each child has its own result. Successful reaps free capacity and
failed cleanup keeps its reservation. Nonselected workers continue running.

## Drain and cancellation boundaries

Capacity counts retained names, including finished-but-unreaped and quarantined
entries. It does not claim to bound the tasks, payloads or captured factory data
inside each supplied tree; their own region/admission policies still apply.
A zero ceiling denies all children. Names contain 1 through 255 UTF-8 bytes.
There is no unbounded completion history inside the collection.

A pending wait owns its controller result and boxed close future **in the
collection**, not in the disposable borrowing wait. Dropping a wait keeps the
name, result and cleanup progress. Repeating the wait resumes the same close;
it does not restart a finalizer or lose a previously joined outcome. Stopping a
child is not reversed by dropping the subsequent termination wait.

An explicit close failure, cleanup failure or unreported controller panic is
not a reusable slot. The child remains quarantined; `child_result` exposes the
retained report and owner shutdown returns all still-retained results. Do not
treat an error, missing close receipt or cancellation as a successful operation.

`begin_shutdown` seals admission and requests every controller's stop before any
await. `shutdown` drives **all child boundaries concurrently**, then closes the
root. In particular, a pending finalizer in boundary A must not prevent boundary
B's finalizers from starting. All observed typed errors remain in the report.
Task-only cancellation of the owner is registered as a wake source during waits;
on observation it seals admission and initiates the children's stop protocol.

Dropping the whole owner or consuming shutdown future requests cancellation and
close through the existing ownership backstops. Only the enclosing runtime's
region barrier can establish later quiescence. Arbitrary blocking polls, retained
obligations and noncooperative finalizers still need their documented progress
premises; no wall-clock termination guarantee is invented here.

## Validation

The source includes six initial lab tests plus six deeper lifecycle tests (the
interdependent-finalizer test exercises both group and whole-owner shutdown),
and two separate public native-runtime journeys:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib cx::dynamic_supervisor::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test dynamic_supervision_native
```

The tests use real managed controllers, lab/native schedulers, channels and
runtime-registered lab finalizers. Native cleanup callbacks are labeled as
application cleanup, not falsely described as registered region finalizers.
The authoring environment had no Rust toolchain, rustfmt or RCH, so these commands
have **not** been executed there. Source review and Git blob comparisons do not
establish successful compilation, native cancellation correctness, performance,
or a release-ready workspace. Run the authorized RCH lanes before deployment.
