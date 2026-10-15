# Owned initialized-supervisor startup

`CompiledSupervisor::bind_initialized_owned` keeps the existing initialized
managed topology and its matching readiness views in one owner. Its `start`
operation returns a running-service handle only after the whole topology has
been observed ready together. The existing `bind_initialized`, managed
supervisor, readiness and dependency APIs remain unchanged.

This module currently inherits the `test-internals` feature gate. It is an
experimental validation surface, not a default production API. No Rust build
or native test was executed in the authoring environment; do not mistake the
committed tests or this example for release qualification.

## Why startup is an owned operation

Waiting on readiness alone does not decide what to do with the rest of a
partially started application. In particular, a retained Transient factory
whose restart budget stopped can leave an all-ready waiter pending while an
unrelated sibling keeps running. A user-level timeout that only drops the
observation leaves that work alive.

The owned start path retains one additional child-region boundary around the
incumbent managed controller. It observes readiness, actual controller
termination, caller cancellation and one absolute deadline. Refusal stops the
complete owned topology and then joins/closes it before returning an error.
The typed controller and application results remain separate from the first
startup cause and from enclosing-region cleanup.

There is no second executor, detached monitor, speculative restart tracker or
new dependency. The caller's task drives startup; the existing managed
controller drives the workers. Prepared state is consumed, so a supervisor
cannot accidentally be started against another topology's readiness views.

## Use

```rust,ignore
use asupersync::cx::worker_readiness::dependencies::supervisor::{
    InitializedChildBinding, InitializedRunResult, InitializedStartConfig,
    InitializedTopologyLimits,
};
use asupersync::supervision::{
    BackoffStrategy, ManagedRestartMode, SupervisionConfig, SupervisorBuilder,
};
use asupersync::{Budget, Cx, Outcome};
use std::time::Duration;

type Failure = Box<InitializedRunResult<&'static str>>;

fn classify(result: InitializedRunResult<&'static str>) -> Outcome<(), Failure> {
    if result.as_ref().is_ok_and(|report| report.is_success()) {
        Outcome::Ok(())
    } else {
        Outcome::Err(Box::new(result)) // Retain the complete original result.
    }
}

async fn application(cx: &Cx) {
    let worker = InitializedChildBinding::new(
        "index",
        ManagedRestartMode::Temporary,
        |_cx, _generation| async { Outcome::<_, &'static str>::Ok(vec![1_u64, 2]) },
        |worker_cx, _generation, _index| async move {
            // Replace this wait with real application work using worker_cx.
            worker_cx.cancelled().await;
            worker_cx.checkpoint().expect_err("acknowledge shutdown");
            Outcome::<(), &'static str>::Cancelled(worker_cx.cancel_reason().unwrap())
        },
        classify,
    );
    let prepared = SupervisorBuilder::new("service")
        .child(worker.spec())
        .compile().unwrap()
        .bind_initialized_owned(
            vec![worker],
            SupervisionConfig::new(0, Duration::from_secs(60))
                .with_backoff(BackoffStrategy::None),
            InitializedTopologyLimits { max_children: 1, max_edges: 0 },
        ).unwrap();

    let mut running = match prepared.start(cx, InitializedStartConfig::new(
        Duration::from_secs(5), Budget::INFINITE,
    )).await {
        Ok(running) => running,
        Err(error) => {
            // Inspect error.cause, error.cancellation and error.cleanup.
            // A cleanup close error does not prove quiescence.
            panic!("startup failed: {error:?}");
        }
    };
    assert_eq!(running.initial_readiness().len(), 1);
    // Readiness is a snapshot, not a lease. The worker may fail after observation.
    let exit = running.shutdown().await.unwrap();
    assert!(exit.close.is_ok());
    // Also inspect exit.controller, including each child's typed outcome and
    // cleanup, and exit.stop_error. Successful close is not successful work.
}
```

The example is retained source, not an executed compile claim. Resource-bearing
initializers still own partial-acquisition cleanup. The existing initialized
worker adapter hands late successful acquisition to run for cleanup without
publishing Ready after cancellation.

## Deadline and cancellation policy

The finite timeout is measured from the first poll. A checked absolute deadline
covers enclosing-region admission and all initialization/restarts. Overflow
refuses instead of saturating or restarting the allowance. A parent deadline can
shorten startup. Missing explicit timer authority refuses before region admission;
the bound Sleep never uses the ambient/global fallback timer.

The startup deadline is **not** installed as a lifetime deadline on the new
region. Once startup is accepted, its timer is retired and the existing worker
and parent budgets govern normal execution. An empty topology is refused as a
running service; existing empty-graph APIs remain available.

Control checks bracket controller/readiness polling. Cancellation or expiry
that arrives during that poll wins before its result is accepted, including a
readiness future that itself acknowledged caller cancellation. This avoids
reporting caller cancellation as an unrelated dependency failure or accepting a
late ready value. Controller exit also refuses even when retained readiness
views would otherwise wait indefinitely.

Once a region-opening command is submitted, a timeout does not discard its
outcome. A late admitted region is observed and closed without starting workers.
Failure teardown can exceed the startup allowance: it must wait for cooperative
workers, their descendants and finalizers. This is an acceptance deadline, not
a hard-kill or universal wall-clock termination guarantee.

The first cause stays fixed during teardown. Caller cancellation first observed
while teardown is pending is recorded separately, acknowledged through the
caller's real Cx, and does not overwrite an earlier deadline/readiness cause or
a worker's typed result. No cancellation-aware result send erases that report.

## Ownership after success or abandonment

`RunningInitializedSupervisor` owns the controller and enclosing region. `join`
waits for natural controller termination and then closes the boundary.
`request_stop` initiates whole-topology cancellation; `shutdown` requests it and
then joins. Startup does not automatically cancel unrelated sibling regions.

Borrowing join/shutdown futures can be dropped and resumed. The controller
result and in-progress close remain in the handle, not in the disposable wait.
The exit report can be consumed once; a later join returns
`JoinError::PolledAfterCompletion`. These observation waits are uninterruptible:
callers that catch their own cancellation must acknowledge it under the normal
Cx contract; a cancellation-blind enclosing task can still have its return
classified as task cancellation.

Dropping the running owner or a pending start future requests cancellation/close
through existing task and region guards. Drop does not perform asynchronous
cleanup synchronously. The enclosing runtime region is the final quiescence
barrier after abandonment. Runtime destruction/process exit, blocking callbacks,
forgotten obligations and non-progressing cleanup remain outside a completion
promise. Readiness is not a health check, resource lease, durable receipt or
authoritative per-child permanent-retirement event.

## Validation

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_initialized_startup \
  cargo test -p asupersync --features test-internals \
  --lib cx::worker_readiness::dependencies::supervisor::launch::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_initialized_startup \
  cargo test -p asupersync --features test-internals --test initialized_startup_native
```

There are ten source-local tests and six native tests. The native journeys use
current-thread/two-worker schedulers and real loopback TCP, with a supplied
VirtualClock only to choose the deadline boundary after I/O has actually parked.
No wall-clock sleep guesses when to abort. Tests cover startup success outliving
the allowance, timeout followed by caller abort during pending TCP cleanup, and
dropping startup followed by an enclosing-region drain. Exact INIT/STOP/ACK bytes,
late resource handoff, typed outcomes and timer retirement are asserted.
The test application's acknowledged TCP cleanup uses an explicit 128-poll mask,
because TCP performs its own cancellation checkpoint on each poll. The startup
owner does not grant that mask or promise that arbitrary cleanup will finish.
The initializer also handles cancellation arriving between its observer poll
and the socket's checkpoint, retaining the acquired stream for cleanup.

The authoring session's RCH attempts failed before compilation with command not
found (exit 127). Rust/Cargo/rustfmt/UBS were unavailable. Source/API review,
lexical delimiter checks and blob hashes do not prove Rust typing, native
wakeups, cleanup liveness, performance or release readiness. Run the authorized
RCH feature/profile and native-cancellation lanes before promotion.
