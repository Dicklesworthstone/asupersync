# Readiness-dependent execution

This surface is **opt-in under `test-internals` and has not yet been compiled
or executed by its author**. It extends `cx::worker_readiness`; it does not
promote readiness or these dependency APIs into the default production build.

`WorkerDependencies` adds two operations missing from individual readiness
observers: an all-ready barrier and execution that stops when any selected
prerequisite generation is lost. The existing managed supervisor still owns
worker restart policy and generation drain. No separate executor is introduced.

## An all-ready vector, not accumulated historical successes

Construct an immutable set with an explicit maximum dependency count:

```rust,ignore
use asupersync::cx::worker_readiness::dependencies::WorkerDependencies;

let dependencies = WorkerDependencies::new(vec![database_ready, index_ready], 8)?;
let snapshot = dependencies.wait_ready(&cx).await?;
let generations: Vec<_> = snapshot.generations().collect();
let changed = snapshot.wait_lost(&cx).await?;
```

Every entry is an existing `WorkerReadiness` observation capability, not a child
name. Clones of the same factory observation are rejected as duplicate entries.
Input order determines error indices and snapshot order. No wait, spawn or
initializer is run by the constructor. Count and metadata reservation failures
are explicit; the caller's already allocated input is outside that accounting.

The barrier does not remember that A was ready yesterday and combine that with
B becoming ready today. It first collects exact ready-generation observations,
then validates them all again. For a particular managed generation, Ready can
be entered only once. Therefore a successful vector was simultaneously ready
at a common point between those passes: every chosen generation stayed Ready
from its first observation through its second validation. No two readiness
state locks need to be held together, and no callbacks run under those locks.

Every prerequisite is armed before state sampling. A terminal failure in a later
entry is inspected even when an earlier entry is still unstarted; waiting for
that earlier entry first would conceal a permanently closed prerequisite.
Broadcast re-arming work is bounded per poll. Metadata and registrations are
O(number of dependencies) per live wait; there is no generation event history.
Continuous churn may prevent a stable all-ready observation indefinitely.

A snapshot is immediately stale-able, **not a lease on worker resources**.
`first_lost`, `is_current` and `wait_lost` retain the selected exact identities.
An upstream restart completed between polls still invalidates the old snapshot.
The replacement cannot turn it back into a current one. Obtain a new snapshot
explicitly. Empty sets are immediately ready; their loss wait ends only when
its observer is cancelled. Dropping or cancelling an observer never stops a
prerequisite, and unregisters only that observation's own waiters.

## Runtime-owned dependent work

```rust,ignore
use asupersync::cx::worker_readiness::dependencies::DependencyScopeConfig;
use asupersync::{Budget, Outcome};

let report = dependencies.run(
    &cx,
    DependencyScopeConfig::new(Budget::INFINITE),
    |work_cx, exact_generations| async move {
        // Start effects only here, with the actual admitted task's Cx.
        // Every descendant spawned through work_cx stays in this subtree.
        // Real application code decides what to do with these observations.
        let _ = exact_generations;
        work_cx.cancelled().await;
        let _ = work_cx.checkpoint(); // Acknowledge before asynchronous cleanup.
        // Await application-specific cleanup before returning its exact outcome.
        Outcome::<(), String>::Ok(())
    },
).await?;

// A task join alone is not the operation result or its quiescence proof.
assert!(report.close.is_ok());
// This intentionally-stopped example need not have report.is_success() == true.
```

`run` waits for all prerequisites before admitting its own child region. It
rechecks the selected identities after region admission and inside the real
work task before invoking the user factory. A dependency may still fail after
the final check; there is no atomic effect admission or distributed fencing
lease here. Once observed, loss cancels the **dependent** region, not upstream
workers or unrelated siblings. The driver joins the work task and closes its
region, including descendants and registered finalizers, before returning.
Monitoring prerequisite loss ends at work-task join; region closure already
cancels/drains any remaining descendants. Caller cancellation remains observed
and acknowledged through that close phase as well.

The caller's existing task drives `run`; it does not spawn a detached monitoring
loop. One ordinary work task and one child region are admitted per run, after
the barrier. Region/task budgets and capability constraints remain authoritative.
There is no automatic deadline, retry loop, or graph-wide reconfiguration.

A completed report retains the exact prerequisite vector, work-factory invocation
witness, task submission refusal, typed application outcome inside the actual
task terminal, first stop cause, independent caller cancellation, cancellation
command error and actual region-close result. Work values/errors require Send,
not Clone or Sync. A later parent abort cannot be mistaken for the upstream
loss that was observed first. `is_success` rejects stop requests, missing work,
application errors, task panics, cancellation and failed finalizer outcomes.
The report is returned to the driving caller; wrapping that caller in another
task retains that task's ordinary terminal-publication policy. This primitive
does not override cancellation racing after its final observation/return.

Dropping `run` requests work cancellation and region close via owned guards.
It does not synchronously drain or yield a report. The enclosing region barrier
is required before claiming later quiescence. A callback may acknowledge
cancellation and continue pending to complete protocol cleanup. No arbitrary
callback, destructor, foreign call or forgotten obligation is forcibly made
cooperative. Hard runtime abort/process exit can prevent completion. Resources
captured before work admission retain their caller-side cleanup responsibility.

## Composing real supervisor restarts

Use `run` inside an existing `ManagedChildFactory` / `start_worker` body. Map a
returned dependency-loss report to the application's error type to request a
restart under the chosen existing policy. The native regression retains the
entire `DependencyScopeReport` in a boxed typed error; a transient supervisor
restarts it only after the old dependent operation and its region have drained.
Each new call selects a fresh all-ready vector. Upstream readiness returning
early does not skip the previous dependent cleanup barrier.

This intentionally does not alter the existing `depends_on` topology compiler,
one-for-all/rest-for-one semantics, or independent dynamic entries. The caller
must choose an acyclic startup topology and an appropriate restart/intensity
policy. Waiting cyclically on initialization is not detected by this immutable
set. Repeated permanent dependency failure can exhaust an explicitly selected
restart budget; it is not silently ignored or turned into success.

## Validation and boundaries

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_worker_dependencies \
  cargo test -p asupersync --features test-internals --lib cx::worker_readiness::dependencies::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_worker_dependencies \
  cargo test -p asupersync --features test-internals --test worker_dependencies_native
```

The two implementation units add 18 unit/lab tests and eight native tests. The
native current-thread/two-worker journeys use real managed prerequisites and
witness a blocked all-ready barrier, work cancellation observers, descendant
cleanup, and a real TCP read before permitting the peer's exact acknowledgement.
They test upstream loss, caller abort, dropping the operation, and a real
transient dependent restart with an already-ready replacement prerequisite.
The old dependent's cleanup gate must finish before its replacement runs.
A separate lab regression aborts the caller only after the work returned and
its descendant cleanup is pending, then checks the retained original value.

The authoring environment has no Rust, Cargo, rustfmt, RCH or UBS. Both focused
RCH invocations fail before execution with command-not-found; no local Cargo
fallback or Actions run is authorized. These tests are authored, **not executed**.
A separate finite-state readiness model checks double-collect interleavings and
rejects a deliberately broken non-revalidating variant. That and lexical/hash
checks are supplemental, not proof of Rust typing, native wakeup correctness,
performance, complete supervision semantics or release readiness.
