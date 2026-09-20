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
failure is still possible. Use an application readiness channel and inspect the
actual terminal report. There is no successful dummy task or global registration.

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
